// Single source of truth for the supported UI/interface languages.
// Every place that renders a language chip/list (HomePage's selector,
// AboutPage's "Languages supported" list, LangContext's SUPPORTED codes,
// translations.js's T object keys) must import this — no duplicate lists.
//
// Scoped down to 4 languages for the demo (English, Hindi, Telugu, Tamil).
// No RTL language in this set today; the `rtl` field and the RTL plumbing
// elsewhere (LangContext's dir handling) are left in place as harmless,
// forward-compatible groundwork in case more languages (e.g. Urdu) are
// added later.
export const LANGUAGES = [
  { code: 'en', label: 'English', rtl: false },
  { code: 'hi', label: 'हिन्दी', rtl: false },
  { code: 'te', label: 'తెలుగు', rtl: false },
  { code: 'ta', label: 'தமிழ்', rtl: false },
]

export const LANGUAGE_CODES = LANGUAGES.map((l) => l.code)
