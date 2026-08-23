/**
 * Small risk donut (72x72). For scam_type === 'likely_safe', callers should
 * render the ✓ check instead (see VerdictCard) — this component always
 * draws the numeric donut, used for every non-safe verdict.
 */
export default function RiskMeter({ risk = 0, tone = 'safe' }) {
  const clamped = Math.max(0, Math.min(100, Math.round(risk)))
  const radius = 30
  const circumference = 2 * Math.PI * radius
  const offset = circumference * (1 - clamped / 100)
  const word = tone === 'danger' ? 'HIGH' : tone === 'warn' ? 'MED' : 'LOW'

  return (
    <div
      className="risk-donut"
      role="meter"
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={clamped}
      aria-label={`Risk score ${clamped} out of 100`}
    >
      <svg viewBox="0 0 72 72" aria-hidden="true">
        <circle className="track" cx="36" cy="36" r={radius} />
        <circle
          className={`fill tone-${tone}`}
          cx="36"
          cy="36"
          r={radius}
          strokeDasharray={circumference}
          strokeDashoffset={offset}
        />
      </svg>
      <div className="center">
        <div>
          <div className="num">{clamped}</div>
          <div className={`word tone-${tone}`}>{word}</div>
        </div>
      </div>
    </div>
  )
}
