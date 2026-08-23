import { NavLink } from 'react-router-dom'

function navLinkClass({ isActive }) {
  return `navbar-link${isActive ? ' is-active' : ''}`
}

export default function NavBar() {
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
          <a className="emergency-badge" href="tel:1930" aria-label="Call the cyber crime helpline, 1930">
            📞 1930
          </a>
        </div>
      </div>
    </header>
  )
}
