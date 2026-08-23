import { useState } from 'react'
import AnalyzePanel from '../components/AnalyzePanel'
import VerdictCard from '../components/VerdictCard'
import { LANG_STORAGE_KEY } from '../lib/labels'

// Kept in sync with backend core.locales_loader.SUPPORTED_LANGUAGES (20
// languages: en/hi/te are locale-file-backed, the rest translate on demand
// — see backend/core/locales_loader.py). Selecting one of the newer 10
// (or/ur/as/sa/mai/sat/ks/ne/kok/sd) translates the verdict's own
// explanation/action text correctly; the fixed section headers ("WHY THIS
// VERDICT" etc.) stay in English for those until real translations are
// authored in src/lib/labels.js — same honest fallback used everywhere
// else in this codebase rather than invented copy.
const LANG_CHIPS = [
  { code: 'en', label: 'English' },
  { code: 'hi', label: 'हिन्दी' },
  { code: 'te', label: 'తెలుగు' },
  { code: 'ta', label: 'தமிழ்' },
  { code: 'bn', label: 'বাংলা' },
  { code: 'mr', label: 'मराठी' },
  { code: 'gu', label: 'ગુજરાતી' },
  { code: 'pa', label: 'ਪੰਜਾਬੀ' },
  { code: 'kn', label: 'ಕನ್ನಡ' },
  { code: 'ml', label: 'മലയാളം' },
  { code: 'or', label: 'ଓଡ଼ିଆ' },
  { code: 'ur', label: 'اردو' },
  { code: 'as', label: 'অসমীয়া' },
  { code: 'sa', label: 'संस्कृतम्' },
  { code: 'mai', label: 'मैथिली' },
  { code: 'sat', label: 'ᱥᱟᱱᱛᱟᱲᱤ' },
  { code: 'ks', label: 'کٲشُر' },
  { code: 'ne', label: 'नेपाली' },
  { code: 'kok', label: 'कोंकणी' },
  { code: 'sd', label: 'سنڌي' },
]

const HOW_IT_WORKS = [
  { icon: '🔍', title: 'Paste a message', desc: 'Drop in any suspicious SMS or WhatsApp text.' },
  { icon: '💡', title: 'AI analyzes it', desc: 'Rules and a language model check it in seconds.' },
  { icon: '📑', title: 'Cites known patterns', desc: 'Matched against real, documented scam advisories.' },
  { icon: '🛡️', title: 'Guides you to report', desc: 'Get a clear next step, in your language.' },
]

function readUiLang() {
  try {
    return localStorage.getItem(LANG_STORAGE_KEY) || 'auto'
  } catch {
    return 'auto'
  }
}

export default function HomePage() {
  const [verdict, setVerdict] = useState(null)
  const [uiLang, setUiLang] = useState(readUiLang)

  function selectLang(code) {
    const next = uiLang === code ? 'auto' : code // tap again to deselect back to auto
    try {
      localStorage.setItem(LANG_STORAGE_KEY, next)
    } catch {
      // localStorage unavailable (private mode, etc.) — still works for this
      // page load via the event below, just won't persist across reloads.
    }
    setUiLang(next)
    // localStorage writes don't fire a 'storage' event in the SAME tab that
    // wrote them, so VerdictCard listens for this custom event to re-render
    // its section labels immediately, without needing a fresh analysis.
    window.dispatchEvent(new CustomEvent('kavach:ui-lang-change', { detail: next }))
  }

  return (
    <div className="content">
      <section className="hero">
        <h1>Is this message a scam?</h1>
        <p>
          Paste any suspicious SMS or WhatsApp message. Get an instant answer in your
          language — free, private, no sign-up.
        </p>
        <div className="lang-chip-row" role="group" aria-label="Choose verdict language">
          {LANG_CHIPS.map((l) => (
            <button
              type="button"
              key={l.code}
              className={`lang-pill${uiLang === l.code ? ' is-selected' : ''}`}
              onClick={() => selectLang(l.code)}
              aria-pressed={uiLang === l.code}
            >
              {l.label}
            </button>
          ))}
        </div>
      </section>

      <AnalyzePanel onResult={setVerdict} />

      {verdict ? (
        <VerdictCard verdict={verdict} />
      ) : (
        <section className="how-it-works" aria-label="How Kavach works">
          {HOW_IT_WORKS.map((step) => (
            <div className="how-card" key={step.title}>
              <div className="how-icon" aria-hidden="true">{step.icon}</div>
              <div className="how-title">{step.title}</div>
              <p className="how-desc">{step.desc}</p>
            </div>
          ))}
        </section>
      )}
    </div>
  )
}
