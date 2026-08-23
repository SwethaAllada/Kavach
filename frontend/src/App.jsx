import { useState } from 'react'
import AnalyzePanel from './components/AnalyzePanel'
import VerdictCard from './components/VerdictCard'
import TrendsDashboard from './components/TrendsDashboard'

export default function App() {
  const [verdict, setVerdict] = useState(null)
  const [tab, setTab] = useState('analyze')

  return (
    <div className="page">
      <header className="site-header" role="banner">
        <div className="brand">
          <div className="brand-mark" aria-hidden="true">क</div>
          <div className="brand-text">
            <h1>Kavach</h1>
            <div className="tagline">Check any suspicious message before you act.</div>
          </div>
        </div>
        <nav className="nav" aria-label="Views">
          <button
            className={`nav-tab${tab === 'analyze' ? ' is-active' : ''}`}
            onClick={() => setTab('analyze')}
            aria-current={tab === 'analyze' ? 'page' : undefined}
          >
            Analyze
          </button>
          <button
            className={`nav-tab${tab === 'trends' ? ' is-active' : ''}`}
            onClick={() => setTab('trends')}
            aria-current={tab === 'trends' ? 'page' : undefined}
          >
            Trends
          </button>
          <a className="nav-tab" href="/about">About</a>
          <a className="nav-tab" href="/faq">FAQ</a>
        </nav>
        <a className="emergency-badge" href="tel:1930" aria-label="Call the cyber crime helpline, 1930">
          📞 1930
        </a>
      </header>

      <main>
        {tab === 'analyze' && (
          <>
            <AnalyzePanel onResult={setVerdict} />
            {verdict && <VerdictCard verdict={verdict} />}
          </>
        )}
        {tab === 'trends' && <TrendsDashboard />}
      </main>

      <footer className="site-footer">
        <div className="site-footer-row">
          <div className="site-footer-left">Kavach © 2026 — catch the scam before it catches you.</div>
          <div className="site-footer-center">
            <a href="/about">About</a>
            <span aria-hidden="true">·</span>
            <a href="/faq">FAQ</a>
            <span aria-hidden="true">·</span>
            <button type="button" className="footer-link-btn" onClick={() => setTab('trends')}>Trends</button>
            <span aria-hidden="true">·</span>
            <a href="https://github.com/SwethaAllada/Kavach" target="_blank" rel="noreferrer">GitHub</a>
          </div>
          <div className="site-footer-right">🔒 No messages are stored. Privacy first.</div>
        </div>
        <div className="site-footer-emergency">
          Emergency: Call <a href="tel:1930">1930</a> ·{' '}
          <a href="https://cybercrime.gov.in" target="_blank" rel="noreferrer">cybercrime.gov.in</a>
        </div>
      </footer>
    </div>
  )
}
