import { useEffect, useState } from 'react'
import { getTrends } from '../lib/api'
import { useTranslation } from '../lib/useTranslation'

// Human-readable labels for scam-type keys returned by the backend.
const SCAM_LABEL = {
  digital_arrest: 'Digital Arrest',
  investment_stock: 'Investment / Trading',
  kyc_bank: 'Bank / KYC',
  courier_parcel: 'Courier / Customs',
  job_task: 'Task Job',
  loan_app: 'Loan App',
  lottery_prize: 'Lottery / Prize',
  tech_support: 'Tech Support',
  upi_collect_request: 'UPI Collect',
  romance: 'Romance',
  deepfake_voice: 'Deepfake Voice',
  other: 'Suspicious (other)',
  likely_safe: 'Likely Safe',
  unknown: 'Unknown',
}

const LANG_LABEL = { en: 'English', hi: 'हिन्दी', te: 'తెలుగు', ta: 'தமிழ்' }

const RISK_LABEL = { low: 'Low', medium: 'Medium', high: 'High' }
const RISK_TONE = { low: 'safe', medium: 'caution', high: 'danger' }

// Pick a bar tone based on whether the row represents a scam class.
function scamTone(key) {
  if (key === 'likely_safe') return 'safe'
  if (key === 'other' || key === 'unknown') return 'caution'
  return 'danger'
}

function StatTile({ title, rows, order, labels, tones }) {
  return (
    <div className="stat-tile">
      <div className="stat-tile-title">{title}</div>
      <div className="stat-tile-rows">
        {order.map((k) => {
          const v = rows[k] || 0
          const lbl = (labels && labels[k]) || k
          const tone = tones && tones[k]
          return (
            <div className="stat-row" key={k}>
              <span className="k" style={tone ? { color: `var(--${tone === 'safe' ? 'safe' : tone === 'danger' ? 'danger' : 'caution'})` } : undefined}>
                {lbl}
              </span>
              <span className="v">{v}</span>
            </div>
          )
        })}
      </div>
    </div>
  )
}

function HBarList({ data, labelMap, toneFn, max }) {
  const entries = Object.entries(data || {})
  if (entries.length === 0) return <p className="section-body" style={{ color: 'var(--ink-muted)' }}>No data yet.</p>
  const localMax = max || Math.max(...entries.map(([, v]) => v), 1)
  return (
    <div className="hbar-list">
      {entries.map(([key, count]) => {
        const width = Math.max(4, Math.round((count / localMax) * 100))
        const tone = toneFn ? toneFn(key) : ''
        return (
          <div className="hbar" key={key}>
            <div className="hbar-label">{(labelMap && labelMap[key]) || key}</div>
            <div className="hbar-track">
              <div
                className={`hbar-fill${tone ? ' tone-' + tone : ''}`}
                style={{ width: `${width}%` }}
                role="presentation"
              />
            </div>
            <div className="hbar-count">{count}</div>
          </div>
        )
      })}
    </div>
  )
}

function Sparkline({ series }) {
  if (!series || series.length === 0) return null
  const max = Math.max(...series.map((d) => d.count), 1)
  return (
    <div>
      <div className="sparkline" role="img" aria-label={`7-day activity: ${series.map(d => d.count).join(', ')}`}>
        {series.map((d) => {
          const heightPct = Math.max(4, Math.round((d.count / max) * 100))
          return (
            <div
              key={d.date}
              className="spark-bar"
              style={{ height: `${heightPct}%` }}
              title={`${d.date}: ${d.count}`}
            />
          )
        })}
      </div>
      <div className="spark-labels">
        {series.map((d) => {
          // Format "YYYY-MM-DD" -> "Mon" (English weekday) for the projector.
          let dow = ''
          try {
            const dt = new Date(d.date + 'T00:00:00Z')
            dow = dt.toLocaleDateString('en-US', { weekday: 'short', timeZone: 'UTC' })
          } catch { dow = d.date.slice(5) }
          return <span key={d.date}>{dow}</span>
        })}
      </div>
    </div>
  )
}

// Pattern Intelligence: approved/pending/auto-approved counts from the
// backend's crowd-verification pipeline. Not fetched separately — comes
// back as part of the /trends response's pattern_intelligence field, which
// may be absent on an older cached response or if the backend hasn't
// populated it yet, so this renders nothing rather than crashing.
function PatternIntelligence({ patternIntelligence, t }) {
  if (!patternIntelligence) return null
  const { approved_count, pending_count, auto_approved_count } = patternIntelligence

  return (
    <div className="trend-block">
      <h3>{t('trends_patterns')}</h3>
      <div className="stat-tiles">
        <StatTile
          title={t('trends_approved')}
          rows={{ approved: approved_count || 0 }}
          order={['approved']}
          labels={{ approved: t('trends_approved') }}
        />
        <StatTile
          title={t('trends_pending')}
          rows={{ pending: pending_count || 0 }}
          order={['pending']}
          labels={{ pending: t('trends_pending') }}
        />
        <StatTile
          title={t('trends_auto')}
          rows={{ auto: auto_approved_count || 0 }}
          order={['auto']}
          labels={{ auto: t('trends_auto') }}
        />
      </div>
    </div>
  )
}

export default function TrendsDashboard() {
  const { t } = useTranslation()
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const ac = new AbortController()
    setLoading(true)
    getTrends({ signal: ac.signal })
      .then((d) => setData(d))
      .finally(() => setLoading(false))
    return () => ac.abort()
  }, [])

  if (loading) {
    return (
      <section className="card">
        <h2 className="card-title">Local scam trends</h2>
        <div className="trends-loading">Loading anonymized trends…</div>
      </section>
    )
  }

  const status = data?.status || 'unavailable'
  const total = data?.total_count || 0

  // Empty / unavailable states — never render broken bars.
  if (total === 0 || status === 'unavailable') {
    const isUnavailable = status === 'unavailable'
    return (
      <section className="card">
        <h2 className="card-title">Local scam trends</h2>
        <p className="card-subtitle">
          Anonymized aggregate view of scam patterns Kavach is seeing. We never store the message
          text — only the scam category, risk bucket, language, and timestamp.
        </p>
        <div className="trends-empty">
          <div className="big" aria-hidden="true">📊</div>
          <div style={{ fontSize: 'var(--step-1)', color: 'var(--ink-2)', fontWeight: 600 }}>
            {isUnavailable ? 'Trends store is currently unavailable' : 'No data yet'}
          </div>
          <p style={{ marginTop: 'var(--space-3)', maxWidth: 520, marginInline: 'auto' }}>
            {isUnavailable
              ? "We couldn't reach the anonymized trends database right now. Your analysis still works — this dashboard will populate once the store is reachable again."
              : 'Analyze a few messages from the Analyze tab and refresh — as verdicts come in, this dashboard will fill with the anonymized breakdown.'}
          </p>
        </div>
      </section>
    )
  }

  return (
    <section className="card" aria-label="Local scam trends">
      <div className="trends-headline">
        <div>
          <div className="trends-total">
            <span className="label">{t('trends_total')}</span>
            {total.toLocaleString('en-IN')}
          </div>
        </div>
        <div className={`trends-status status-${status}`}>
          {status === 'ok' && 'Live · anonymized'}
          {status === 'empty' && 'No data yet'}
          {status === 'unavailable' && 'Store unavailable — showing empty state'}
        </div>
      </div>

      <div className="stat-tiles">
        <StatTile
          title="Risk breakdown"
          rows={data.by_risk_bucket}
          order={['high', 'medium', 'low']}
          labels={RISK_LABEL}
          tones={RISK_TONE}
        />
        <StatTile
          title={t('trends_languages')}
          rows={data.by_language}
          order={Object.keys(data.by_language || {})}
          labels={LANG_LABEL}
        />
        <StatTile
          title="Decision path"
          rows={{
            ...(data.by_decision_source || {}),
            'fallback used': data.fallback_used_count || 0,
          }}
          order={[
            ...Object.keys(data.by_decision_source || {}),
            'fallback used',
          ]}
        />
      </div>

      <div className="trend-block">
        <h3>{t('trends_scam_types')}</h3>
        <HBarList
          data={data.by_scam_type}
          labelMap={SCAM_LABEL}
          toneFn={scamTone}
        />
      </div>

      <div className="trend-block">
        <h3>Last 7 days</h3>
        <Sparkline series={data.last_7_days} />
      </div>

      <PatternIntelligence patternIntelligence={data.pattern_intelligence} t={t} />

      <p className="card-subtitle" style={{ marginTop: 'var(--space-4)', marginBottom: 0 }}>
        Only the fields shown above are stored. Message text, phone numbers, UPI IDs, links, and
        every phrase from your message stay on your device.
      </p>
    </section>
  )
}
