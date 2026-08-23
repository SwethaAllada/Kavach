"""Bridges backend/ to the top-level locales/ package, and extends coverage
to languages with no authored locales/<code>/ YAML via runtime translation.

locales/ lives one directory above backend/ (repo_root/locales/), but
uvicorn runs with backend/ as the import root (see render.yaml's
`uvicorn main:app` and README's local dev instructions), so `import locales`
fails from inside backend/ unless the repo root is added to sys.path. This
mirrors how services/rag.py reaches data/scam_kb.json via an explicit
filesystem path rather than a package import — same cross-boundary problem,
same fix, applied once here instead of in every consumer module.

Two tiers of language support:
  - YAML-backed (en, hi, te): read directly from locales/<code>/responses.yaml,
    exactly as before. This path is unchanged by the translation feature.
  - Translate-on-demand (everything else in SUPPORTED_LANGUAGES — 17 more
    languages as of this writing, see _TRANSLATE_ON_DEMAND_LANGUAGES): the
    English string is fetched from locales/en/responses.yaml and translated
    via deep_translator.GoogleTranslator, cached per (lang, path) for the
    process lifetime so a given string is only translated once. Adding a
    further language later is a one-line change to
    _TRANSLATE_ON_DEMAND_LANGUAGES — no new YAML required.

    Several of these (sa, mai, ks, ne, kok, sd) are written in Devanagari,
    same as Hindi — classifier._detect_language cannot tell them apart from
    Hindi by script alone (Marathi is the only Devanagari-sharing language
    with a word-marker disambiguator; extending that to 5 more languages
    would be guesswork without real message samples to validate against).
    These languages are reachable via the `hint` parameter (e.g. a UI
    language selector) but will auto-detect as "hi" from raw text.

Public API:
  - SUPPORTED_LANGUAGES: tuple[str, ...] — the ONLY place the supported
    language set is defined. YAML-backed codes come from
    locales.registry.available_locales(); translate-on-demand codes are
    listed in _TRANSLATE_ON_DEMAND_LANGUAGES below. Every consumer
    (llm.py's prompt, classifier._detect_language, report.py,
    whatsapp_format.py) reads this instead of hardcoding a language list.
  - get_string(language, *path, default="") -> str
        Look up a nested key in locales/<language>/responses.yaml (e.g.
        get_string("hi", "fallback_templates", "kyc_bank", "explanation")),
        or, for a translate-on-demand language, translate the English value
        at that path. Falls back to English on a missing language, missing
        key, or translation failure, then to `default` if English is also
        missing it. Never raises.
  - get_locale(code) -> LocaleBundle | None — re-exported from the registry.

Fallback contract (hard requirement — see backend/tests/test_locales.py and
test_locales_fallback.py): requested language -> English -> caller-supplied
default. A missing locale, a missing key, a malformed YAML file, or a failed
translation must never raise and must never return None/empty when a
default is given. Wiring this registry into the request path must not be
able to break /analyze or /webhook.
"""

from __future__ import annotations

import logging
import re
import sys
from pathlib import Path
from typing import Any

from core.config import settings

log = logging.getLogger(__name__)

_REPO_ROOT = Path(__file__).resolve().parents[2]


def _ensure_locales_importable() -> None:
    root_str = str(_REPO_ROOT)
    if root_str not in sys.path:
        sys.path.insert(0, root_str)


_ensure_locales_importable()

try:
    from locales.registry import REGISTRY, get_locale  # noqa: E402
except Exception as e:  # pragma: no cover - defensive: locales/ must always exist
    log.exception("failed to import locales.registry: %s", e)
    REGISTRY = {}

    def get_locale(code: str):  # type: ignore[no-redef]
        return None


_FALLBACK_LANGUAGE = "en"

# Languages with NO locales/<code>/ YAML directory — served by translating
# the English string on demand instead of an authored file. Adding one more
# is a one-line change here; it does not touch get_string()'s logic.
_TRANSLATE_ON_DEMAND_LANGUAGES: tuple[str, ...] = (
    "ta",   # Tamil
    "kn",   # Kannada
    "ml",   # Malayalam
    "bn",   # Bengali
    "mr",   # Marathi
    "gu",   # Gujarati
    "pa",   # Punjabi (Gurmukhi)
    "or",   # Odia
    "ur",   # Urdu
    "as",   # Assamese
    "sa",   # Sanskrit
    "mai",  # Maithili
    "sat",  # Santali
    "ks",   # Kashmiri
    "ne",   # Nepali
    "kok",  # Konkani
    "sd",   # Sindhi
)

# The single source of truth for the supported-language set: YAML-backed
# codes (from what's actually on disk under locales/) plus the
# translate-on-demand codes above. Every consumer reads this instead of
# hardcoding a language list.
SUPPORTED_LANGUAGES: tuple[str, ...] = tuple(
    sorted(set(REGISTRY.keys()) | set(_TRANSLATE_ON_DEMAND_LANGUAGES))
) or (_FALLBACK_LANGUAGE,)


def _get_yaml_string(language: str, path: tuple[str, ...]) -> str | None:
    """Look up responses.yaml[path[0]]...[path[-1]] for a YAML-backed
    `language`. Returns None if missing/malformed rather than raising."""
    try:
        bundle = get_locale(language)
        if bundle is None:
            return None
        node: Any = bundle.responses
        for key in path:
            if not isinstance(node, dict) or key not in node:
                return None
            node = node[key]
        return node if isinstance(node, str) and node else None
    except Exception as e:  # pragma: no cover - defensive
        log.warning("_get_yaml_string(%s, %r) failed: %s", language, path, e)
        return None


# Cache of already-translated strings for the process lifetime, keyed by
# (lang, path-tuple) -> translated string. A given string is only sent to
# Google Translate once per (language, key) per process.
_translation_cache: dict[tuple[str, tuple[str, ...]], str] = {}

# Placeholders used in report summary templates. Must survive translation
# byte-for-byte — see _translate_safely().
#   [DATE], [AMOUNT], [YOUR NAME]  -- user-fill-in placeholders (all-caps,
#     bracket-delimited).
#   {entity}, {ask}, {scam_type_human}, {headline}, {label}, {risk}
#     -- str.format() placeholders. These are NOT just cosmetic: Google
#     Translate has been observed translating the identifier INSIDE the
#     braces (e.g. "{ask}" -> "{கேளும்படி}"), which makes the later
#     .format(ask=...) call raise KeyError. A dropped or mangled {..}
#     placeholder is a crash risk, not just a quality issue, so it gets the
#     same "reject and fall back to English" treatment as a missing [..].
_BRACKET_PLACEHOLDER_RE = re.compile(r"\[[A-Z0-9 /_-]+\]")
_FORMAT_PLACEHOLDER_RE = re.compile(r"\{[a-zA-Z_][a-zA-Z0-9_]*\}")

# Our language codes vs. the code deep_translator's GoogleTranslator expects
# — these differ for a few languages (verified against
# GoogleTranslator().get_supported_languages(as_dict=True)). Konkani is the
# one confirmed mismatch: we use "kok" (ISO 639-2, matches SUPPORTED_LANGUAGES
# and the UI/detection code elsewhere) but GoogleTranslator expects "gom".
# Santali ("sat") and Kashmiri ("ks") are not in GoogleTranslator's supported
# list at all as of this writing — _translate_safely's own exception handling
# already covers that (falls back to English), no mapping can fix it.
_TRANSLATOR_CODE_OVERRIDES: dict[str, str] = {
    "kok": "gom",
}


def _find_placeholders(text: str) -> set[str]:
    return set(_BRACKET_PLACEHOLDER_RE.findall(text)) | set(_FORMAT_PLACEHOLDER_RE.findall(text))


def _translate_safely(english_text: str, target_lang: str) -> str | None:
    """Translate `english_text` to `target_lang` via GoogleTranslator.

    Returns None (never raises) on any failure: network error, unsupported
    language, rate limit, or a translation that dropped or mangled a
    placeholder present in the source — either a [BRACKET] fill-in marker or
    a {format} placeholder (logged as a warning so silent placeholder loss
    is visible in logs, not just guessed at). A mangled {format} placeholder
    is a crash risk (str.format() raises KeyError on an unexpected field
    name), not just a quality issue, so it gets the same treatment.
    """
    try:
        from deep_translator import GoogleTranslator

        translator_lang = _TRANSLATOR_CODE_OVERRIDES.get(target_lang, target_lang)
        translated = GoogleTranslator(source="en", target=translator_lang).translate(english_text)
        if not isinstance(translated, str) or not translated.strip():
            return None

        source_placeholders = _find_placeholders(english_text)
        if source_placeholders:
            missing = source_placeholders - _find_placeholders(translated)
            if missing:
                log.warning(
                    "translation to %s dropped/mangled placeholder(s) %s; using English original",
                    target_lang, sorted(missing),
                )
                return None

        return translated
    except Exception as e:
        log.warning("translation to %s failed (falling back to English): %s", target_lang, e)
        return None


def _get_translated_string(language: str, path: tuple[str, ...], english_value: str) -> str:
    """Return a cached or freshly-translated version of `english_value` for
    a translate-on-demand `language`. Falls back to `english_value` if
    translation is disabled or fails."""
    if not settings.translation_enabled:
        return english_value

    cache_key = (language, path)
    cached = _translation_cache.get(cache_key)
    if cached is not None:
        return cached

    translated = _translate_safely(english_value, language)
    result = translated if translated is not None else english_value
    _translation_cache[cache_key] = result
    return result


def get_string(language: str, *path: str, default: str = "") -> str:
    """Look up responses.yaml[path[0]][path[1]]...[path[-1]] for `language`.

    YAML-backed languages (en, hi, te) read the file directly, exactly as
    before. Translate-on-demand languages (see _TRANSLATE_ON_DEMAND_LANGUAGES)
    fetch the English value and translate it, caching the result.

    Falls back to English if `language` isn't registered/translatable or the
    key is missing there, then to `default` if English is missing it too.
    Never raises — a malformed/missing locale, a typo'd key, or a translation
    failure returns `default` (or the English string) instead of crashing
    the request path.
    """
    if language in REGISTRY:
        value = _get_yaml_string(language, path)
        if value is not None:
            return value
        # Fall through to English below if this YAML locale is missing the key.
    elif language in _TRANSLATE_ON_DEMAND_LANGUAGES:
        english_value = _get_yaml_string(_FALLBACK_LANGUAGE, path)
        if english_value is not None:
            return _get_translated_string(language, path, english_value)
        # English itself doesn't have this key either — fall through.

    english_value = _get_yaml_string(_FALLBACK_LANGUAGE, path)
    if english_value is not None:
        return english_value

    return default
