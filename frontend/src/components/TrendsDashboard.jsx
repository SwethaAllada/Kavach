export default function TrendsDashboard() {
  return (
    <section className="card">
      <h2 className="card-title">Local scam trends</h2>
      <p className="card-subtitle">
        Anonymized aggregate view of the scam patterns Kavach is seeing across users
        in your city. Powered by verdicts submitted through this app.
      </p>

      <div className="trends-placeholder">
        <div className="big" aria-hidden="true">📊</div>
        <div style={{ fontSize: 'var(--step-1)', color: 'var(--ink-2)', fontWeight: 600 }}>
          Coming soon
        </div>
        <p style={{ marginTop: 'var(--space-3)', maxWidth: 480, marginInline: 'auto' }}>
          Once enough submissions arrive, this dashboard will show which scam
          categories are trending in your area (last 7 days), the most-flagged
          suspicious numbers, and language mix. All data anonymized before display.
        </p>
      </div>
    </section>
  )
}
