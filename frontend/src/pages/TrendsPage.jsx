import TrendsDashboard from '../components/TrendsDashboard'

export default function TrendsPage() {
  return (
    <div className="content">
      <h1 style={{ fontSize: 'var(--text-3xl)', fontWeight: 700, margin: '0 0 8px' }}>
        Live Scam Trends
      </h1>
      <p className="muted" style={{ marginBottom: 24 }}>
        Anonymized data from messages analyzed by Kavach users. No message content is
        stored — only the scam type and language.
      </p>
      <TrendsDashboard />
    </div>
  )
}
