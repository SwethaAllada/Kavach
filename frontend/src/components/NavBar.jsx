import { NavLink } from 'react-router-dom'

const UI_LANGUAGES = [
  { code: 'auto', label: 'Auto' },
  { code: 'en', label: 'English' },
  { code: 'hi', label: 'हिन्दी' },
  { code: 'te', label: 'తెలుగు' },
  { code: 'ta', label: 'தமிழ்' },
  { code: 'bn', label: 'বাংলা' },
  { code: 'mr', label: 'मराठी' },
  { code: 'gu', label: 'ગુજરાતી' },
  { code: 'kn', label: 'ಕನ್ನಡ' },
  { code: 'ml', label: 'മലയാളം' },
  { code: 'pa', label: 'ਪੰਜਾਬੀ' },
]

const LANG_STORAGE_KEY = 'kavach_ui_lang'

function navLinkClass({ isActive }) {
  return `navbar-link${isActive ? ' is-active' : ''}`
}

export default function NavBar() {
  function onLangChange(e) {
    try {
      localStorage.setItem(LANG_STORAGE_KEY, e.target.value)
    } catch {
      // localStorage unavailable (private mode, etc.) — the selector still
      // works for the current page load, it just won't persist.
    }
    // localStorage writes don't trigger a 'storage' event in the SAME tab
    // that wrote them (only other tabs get notified) — dispatch our own
    // event so an already-visible VerdictCard re-renders with the new
    // language immediately, without needing a fresh analysis.
    window.dispatchEvent(new CustomEvent('kavach:ui-lang-change', { detail: e.target.value }))
  }

  let initialLang = 'auto'
  try {
    initialLang = localStorage.getItem(LANG_STORAGE_KEY) || 'auto'
  } catch {
    // ignore
  }

  return (
    <header className="navbar" role="banner">
      <div className="navbar-inner">
        <NavLink to="/" className="navbar-brand" aria-label="Kavach home">
          <span className="navbar-mark" aria-hidden="true">क</span>
          <span className="navbar-word">Kavach</span>
        </NavLink>

        <nav className="navbar-links" aria-label="Main navigation">
          <NavLink to="/" className={navLinkClass} end>Analyze</NavLink>
          <NavLink to="/trends" className={navLinkClass}>Trends</NavLink>
          <NavLink to="/about" className={navLinkClass}>About</NavLink>
          <NavLink to="/faq" className={navLinkClass}>FAQ</NavLink>
        </nav>

        <div className="navbar-right">
          <label className="visually-hidden" htmlFor="kavach-ui-lang">Interface language</label>
          <select
            id="kavach-ui-lang"
            className="lang-select"
            defaultValue={initialLang}
            onChange={onLangChange}
          >
            {UI_LANGUAGES.map((l) => (
              <option key={l.code} value={l.code}>{l.label}</option>
            ))}
          </select>
          <a className="emergency-badge" href="tel:1930" aria-label="Call the cyber crime helpline, 1930">
            📞 1930
          </a>
        </div>
      </div>
    </header>
  )
}

export { LANG_STORAGE_KEY }
