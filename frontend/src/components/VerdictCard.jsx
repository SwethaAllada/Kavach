import { useEffect, useState } from 'react'
import RiskMeter from './RiskMeter'
import SignalChips from './SignalChips'
import ReportSection from './ReportSection'
import { getLabels, LANG_STORAGE_KEY } from '../lib/labels'

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

const LANG_LABEL = {
  en: 'English', hi: 'हिन्दी (Hindi)', te: 'తెలుగు (Telugu)', ta: 'தமிழ் (Tamil)',
  bn: 'বাংলা (Bengali)', mr: 'मराठी (Marathi)', gu: 'ગુજરાતી (Gujarati)',
  kn: 'ಕನ್ನಡ (Kannada)', ml: 'മലയാളം (Malayalam)', pa: 'ਪੰਜਾਬੀ (Punjabi)',
  or: 'ଓଡ଼ିଆ (Odia)', ur: 'اردو (Urdu)', as: 'অসমীয়া (Assamese)',
  sa: 'संस्कृतम् (Sanskrit)', mai: 'मैथिली (Maithili)', sat: 'ᱥᱟᱱᱛᱟᱲᱤ (Santali)',
  ks: 'کٲشُر (Kashmiri)', ne: 'नेपाली (Nepali)', kok: 'कोंकणी (Konkani)',
  sd: 'سنڌي (Sindhi)',
}

function riskTone(risk, scamType) {
  if (scamType === 'likely_safe' || risk < 40) return 'safe'
  if (risk < 70) return 'warn'
  return 'danger'
}

function useUiLang(detectedLanguage) {
  const [uiLang, setUiLang] = useState(() => {
    try {
      return localStorage.getItem(LANG_STORAGE_KEY) || 'auto'
    } catch {
      return 'auto'
    }
  })

  useEffect(() => {
    function onChange(e) {
      setUiLang(e.detail)
    }
    window.addEventListener('kavach:ui-lang-change', onChange)
    return () => window.removeEventListener('kavach:ui-lang-change', onChange)
  }, [])

  return uiLang === 'auto' ? (detectedLanguage || 'en') : uiLang
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

  const displayLang = useUiLang(detected_language)
  const L = getLabels(displayLang)

  const tone = riskTone(risk, scam_type)
  const isSafe = scam_type === 'likely_safe'
  const scamLabel = SCAM_LABEL[scam_type] || scam_type
  const langLabel = LANG_LABEL[detected_language] || detected_language

  return (
    <article className="verdict" aria-live="polite">
      <div className={`verdict-header tone-${tone}`}>
        <div>
          <div className={`verdict-scam-label tone-${tone}`}>{scamLabel}</div>
          <div className="verdict-lang-chip" title="Language auto-detected by the analyzer">
            <span aria-hidden="true">🌐</span>
            <span>Detected: {langLabel}</span>
          </div>
        </div>
        {isSafe ? (
          <span className="safe-check" aria-hidden="true">✓</span>
        ) : (
          <RiskMeter risk={risk} tone={tone} />
        )}
      </div>

      <div className="verdict-body">
        {fromImage && (
          <div className="verdict-section">
            <h3 className="section-label">Extracted message text</h3>
            <p className="extracted-text-readback" lang={detected_language}>
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
          <div className="verdict-section">
            <h3 className="section-label">{L.why}</h3>
            <p className="verdict-explanation" lang={detected_language}>{explanation}</p>
          </div>
        )}

        {recommended_action && (
          <div className="verdict-section">
            <h3 className="section-label">{L.whatToDo}</h3>
            <div className="action-box" lang={detected_language}>{recommended_action}</div>
          </div>
        )}

        {isSafe && (
          <div className="verdict-section">
            <div className="safe-reassurance">
              This message looks safe. If you are still unsure, do not share any OTP, PIN, or
              money — trust your instincts.
            </div>
          </div>
        )}

        {!isSafe && signals && signals.length > 0 && (
          <div className="verdict-section">
            <h3 className="section-label">{L.signals}</h3>
            <SignalChips signals={signals} />
          </div>
        )}

        {!isSafe && matched_patterns && matched_patterns.length > 0 && (
          <div className="verdict-section">
            <details className="patterns-details">
              <summary>{L.patterns} ({matched_patterns.length})</summary>
              {matched_patterns.map((m, i) => (
                <div className="pattern-card" key={m.id || i}>
                  <div className="pattern-header">
                    <div className="pattern-title">{m.title}</div>
                    <div className="pattern-sim" title="Match strength">
                      {Math.round((m.similarity || 0) * 100)}%
                    </div>
                  </div>
                  {m.source && <div className="pattern-source">Source: {m.source}</div>}
                  {m.matched_indicators && m.matched_indicators.length > 0 && (
                    <div className="pattern-indicators">
                      {m.matched_indicators.slice(0, 3).map((phrase, j) => (
                        <span className="ind" key={j} lang={detected_language}>{phrase}</span>
                      ))}
                      {m.matched_indicators.length > 3 && (
                        <span className="ind ind-more">
                          +{m.matched_indicators.length - 3} more
                        </span>
                      )}
                    </div>
                  )}
                </div>
              ))}
            </details>
          </div>
        )}

        {!isSafe && report && (
          <div className="verdict-section">
            <ReportSection report={report} fromImage={fromImage} signals={signals} risk={risk} labels={L} />
          </div>
        )}
      </div>
    </article>
  )
}
