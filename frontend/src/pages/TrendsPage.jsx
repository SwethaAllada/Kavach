import TrendsDashboard from '../components/TrendsDashboard'
import { useTranslation } from '../lib/useTranslation'

export default function TrendsPage() {
  const { t } = useTranslation()

  return (
    <div className="content">
      <h1 style={{ fontSize: 'var(--text-3xl)', fontWeight: 700, margin: '0 0 8px' }}>
        {t('trends_headline')}
      </h1>
      <p className="muted" style={{ marginBottom: 24 }}>
        {t('trends_desc')}
      </p>
      <TrendsDashboard />
    </div>
  )
}
