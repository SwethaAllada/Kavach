import RiskMeter from './RiskMeter'
import SignalChips from './SignalChips'
import ReportLinks from './ReportLinks'

// Human-readable labels for scam types from the backend taxonomy.
const SCAM_LABEL = {
  digital_arrest: 'Digital Arrest Scam',
  investment_stock: 'Investment / Trading Scam',
  kyc_bank: 'Bank / KYC Scam',
  courier_parcel: 'Fake Courier / Customs Scam',
  job_task: 'Task-based Job Scam',
  loan_app: 'Loan App Scam',
  lottery_prize: 'Lottery / Prize Scam',
  tech_support: 'Fake Tech Support Scam',
  upi_collect_request: 'UPI Collect-Request Scam',
  romance: 'Romance Scam',
  deepfake_voice: 'Deepfake Voice Scam',
  other: 'Suspicious Message',
  likely_safe: 'Likely Safe',
}

const LANG_LABEL = { en: 'English', hi: 'हिन्दी (Hindi)', te: 'తెలుగు (Telugu)' }

function riskState(risk, scamType) {
  if (scamType === 'likely_safe' || risk < 40) return 'safe'
  if (risk < 70) return 'caution'
  return 'danger'
}

export default function VerdictCard({ verdict }) {
  if (!verdict) return null

  const {
    scam_type,
    risk,
    signals = [],
    matched_patterns = [],
    explanation,
    recommended_action,
    detected_language = 'en',
    report,
    extracted_text,
    extracted_sender,
  } = verdict

  // ImageVerdict includes extracted_text; a text-path Verdict never does.
  const fromImage = typeof extracted_text === 'string'

  const state = riskState(risk, scam_type)
  const scamLabel = SCAM_LABEL[scam_type] || scam_type
  const langLabel = LANG_LABEL[detected_language] || detected_language

  return (
    <article className="verdict" aria-live="polite">
      {/* Hero */}
      <div className="verdict-hero">
        <div>
          <div className="hero-label">Verdict</div>
          <div className={`hero-title state-${state}`}>{scamLabel}</div>
          <div className="lang-chip" title="Language auto-detected by the analyzer">
            <span aria-hidden="true">🌐</span>
            <span>Detected: {langLabel}</span>
          </div>
        </div>
        <RiskMeter risk={risk} state={state} />
      </div>

      {/* Body */}
      <div className="verdict-body">
        {fromImage && (
          <div className="section">
            <h3 className="section-title">Extracted message text</h3>
            <p className="section-body extracted-text-readback" lang={detected_language}>
              {extracted_text || '(no text found)'}
            </p>
            {extracted_sender && (
              <div className="extracted-sender">
                <span className="label">Sender detected:</span> <code>{extracted_sender}</code>
              </div>
            )}
          </div>
        )}

        {explanation && (
          <div className="section">
            <h3 className="section-title">Why this verdict</h3>
            <p className="section-body" lang={detected_language}>{explanation}</p>
          </div>
        )}

        {recommended_action && (
          <div className="section">
            <h3 className="section-title">What to do</h3>
            <div className={`action-callout state-${state}`} lang={detected_language}>
              {recommended_action}
            </div>
          </div>
        )}

        {signals && signals.length > 0 && (
          <div className="section">
            <h3 className="section-title">Warning signals detected</h3>
            <SignalChips signals={signals} />
          </div>
        )}

        {matched_patterns && matched_patterns.length > 0 && (
          <div className="section">
            <h3 className="section-title">
              Grounded in known scam patterns ({matched_patterns.length})
            </h3>
            <div className="citations-grid">
              {matched_patterns.map((m, i) => (
                <div className="citation" key={m.id || i}>
                  <div className="citation-header">
                    <div className="citation-title">{m.title}</div>
                    <div className="citation-sim" title="Match strength">
                      {Math.round((m.similarity || 0) * 100)}%
                    </div>
                  </div>
                  {m.source && <div className="citation-source">Source: {m.source}</div>}
                  {m.matched_indicators && m.matched_indicators.length > 0 && (
                    <div className="citation-indicators">
                      {m.matched_indicators.map((phrase, j) => (
                        <span className="ind" key={j} lang={detected_language}>{phrase}</span>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {report && <ReportLinks report={report} fromImage={fromImage} />}
      </div>
    </article>
  )
}
