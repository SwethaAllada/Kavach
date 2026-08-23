import { useState } from 'react'

const CHAKSHU_FORM_URL = 'https://sancharsaathi.gov.in/sfc/Home/sfc-complaint.jsp'

export default function ReportSection({ report, fromImage = false, signals = [], risk = 0, labels }) {
  const [categoryCopied, setCategoryCopied] = useState(false)
  const [toastVisible, setToastVisible] = useState(false)

  if (!report) return null

  // "Do not push to file a complaint over a safe message" — quiet secondary link only.
  if (report.should_report === false) {
    if (!report.channels || report.channels.length === 0) return null
    const primary = report.channels[0]
    return (
      <aside className="quiet-report" role="note">
        Was this number suspicious anyway? You can report it to{' '}
        <a href={primary.value} target="_blank" rel="noreferrer">{primary.name}</a>.
      </aside>
    )
  }

  const summary = report.prefilled_summary || ''
  const category = report.chakshu_category || ''
  const isSevere = risk >= 85 || (signals || []).includes('payment')

  async function copyCategory() {
    try {
      await navigator.clipboard.writeText(category)
      setCategoryCopied(true)
      setTimeout(() => setCategoryCopied(false), 2000)
    } catch {
      // Best-effort — the value is also visible in the box itself.
    }
  }

  async function copyComplaintAndOpenForm() {
    try {
      await navigator.clipboard.writeText(summary)
    } catch {
      // Best-effort copy; still open the form either way.
    }
    window.open(CHAKSHU_FORM_URL, '_blank', 'noopener,noreferrer')
    setToastVisible(true)
    setTimeout(() => setToastVisible(false), 3000)
  }

  return (
    <div className="report-section">
      <div className={`report-urgency-banner ${isSevere ? 'severe' : 'standard'}`}>
        {isSevere
          ? `⚠ ${labels?.reportNow || 'ACT NOW — REPORT THIS FRAUD'}`
          : `⚠ ${labels?.reportSuggested || 'YOU SHOULD REPORT THIS'}`}
      </div>

      <div className="report-call-wrap">
        <a className="report-call-btn" href="tel:1930">
          📞 Call 1930 — Cyber Crime Helpline
        </a>
        <p className="report-call-sub">Free · 24/7 · Call if you have lost money</p>
      </div>

      <div className="report-divider">or report online</div>

      <div className="chakshu-card">
        <div className="chakshu-card-header">
          <span className="name">चक्षु — Sanchar Saathi</span>
          <span className="sub">Official DoT fraud portal</span>
        </div>

        {category && (
          <div className="chakshu-field">
            <p className="chakshu-field-label">Select this category in the Chakshu form</p>
            <div className="chakshu-value-box">
              <span>{category}</span>
              <button type="button" className="btn btn-secondary btn-small" onClick={copyCategory}>
                {categoryCopied ? 'Copied ✓' : 'Copy'}
              </button>
            </div>
          </div>
        )}

        {summary && (
          <div className="chakshu-field">
            <p className="chakshu-field-label">Paste this into &quot;Enter complaint details&quot;</p>
            <textarea
              className="chakshu-summary-textarea"
              readOnly
              value={summary}
              lang={report.language || 'en'}
              rows={4}
            />
            <button type="button" className="btn btn-secondary" style={{ marginTop: 10 }} onClick={copyComplaintAndOpenForm}>
              Copy complaint text
            </button>
            <p className="chakshu-hint">
              Fill in the [ ] fields with your own details before submitting.
            </p>
            {toastVisible && (
              <div className="chakshu-toast" role="status">
                Copied! Paste it in the Chakshu form.
              </div>
            )}
          </div>
        )}

        <a className="chakshu-open-link" href={CHAKSHU_FORM_URL} target="_blank" rel="noreferrer">
          Open Chakshu form →
        </a>
      </div>

      {report.evidence_checklist && report.evidence_checklist.length > 0 && (
        <details className="evidence-details" style={{ marginTop: 16 }}>
          <summary>What to save as evidence ({report.evidence_checklist.length} items)</summary>
          <ul>
            {report.evidence_checklist.map((item, i) => (
              <li key={i}>{item}</li>
            ))}
          </ul>
        </details>
      )}

      {fromImage && (
        <p className="chakshu-hint" style={{ textAlign: 'center' }}>
          Remember to attach the screenshot you uploaded when you file the report.
        </p>
      )}

      <p className="report-disclaimer">
        Kavach helps you prepare your report. You submit it directly on Chakshu.
      </p>
    </div>
  )
}
