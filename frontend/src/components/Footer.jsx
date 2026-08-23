import { Link } from 'react-router-dom'

export default function Footer() {
  return (
    <footer className="site-footer">
      <div className="site-footer-inner">
        <div className="footer-row">
          <span>Kavach — catch the scam before it catches you.</span>
          <div className="footer-links">
            <Link to="/about">About</Link>
            <span aria-hidden="true">·</span>
            <Link to="/faq">FAQ</Link>
            <span aria-hidden="true">·</span>
            <Link to="/trends">Trends</Link>
            <span aria-hidden="true">·</span>
            <a href="https://github.com/SwethaAllada/Kavach" target="_blank" rel="noreferrer">GitHub</a>
          </div>
        </div>
        <div className="footer-row">
          <span className="footer-muted">🔒 No messages stored. Privacy first.</span>
          <span className="footer-muted">
            Emergency: <a href="tel:1930">📞 1930</a> ·{' '}
            <a href="https://cybercrime.gov.in" target="_blank" rel="noreferrer">cybercrime.gov.in</a>
          </span>
        </div>
      </div>
    </footer>
  )
}
