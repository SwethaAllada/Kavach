import { NavLink } from 'react-router-dom'
import { useTranslation } from '../lib/useTranslation'

function navLinkClass({ isActive }) {
  return `navbar-link${isActive ? ' is-active' : ''}`
}

export default function NavBar() {
  const { t } = useTranslation()

  return (
    <header className="navbar" role="banner">
      <div className="navbar-inner">
        <NavLink to="/" className="navbar-brand" aria-label="Kavach home">
          <span className="navbar-mark" aria-hidden="true">क</span>
          <span className="navbar-word">Kavach</span>
        </NavLink>

        <nav className="navbar-links" aria-label="Main navigation">
          <NavLink to="/" className={navLinkClass} end>{t('nav_analyze')}</NavLink>
          <NavLink to="/trends" className={navLinkClass}>{t('nav_trends')}</NavLink>
          <NavLink to="/about" className={navLinkClass}>{t('nav_about')}</NavLink>
          <NavLink to="/faq" className={navLinkClass}>{t('nav_faq')}</NavLink>
        </nav>

        <div className="navbar-right">
          <a className="emergency-badge" href="tel:1930" aria-label="Call the cyber crime helpline, 1930">
            {t('nav_emergency')}
          </a>
        </div>
      </div>
    </header>
  )
}
