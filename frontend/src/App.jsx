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
        </nav>
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

      <footer className="foot-note">
        Kavach is guidance only — it does not file reports on your behalf. When in doubt, call{' '}
        <a href="tel:1930">1930</a> or visit{' '}
        <a href="https://cybercrime.gov.in" target="_blank" rel="noreferrer">
          cybercrime.gov.in
        </a>.
      </footer>
    </div>
  )
}
