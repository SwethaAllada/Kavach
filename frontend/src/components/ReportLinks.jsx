import { useState } from 'react'

const URGENCY_HEADLINE = {
  immediate: 'Act now — report this fraud',
  standard: 'Report this fraud',
}
const URGENCY_ICON = {
  immediate: '⚠',
  standard: '📢',
}

const CHAKSHU_FORM_URL = 'https://sancharsaathi.gov.in/sfc/Home/sfc-complaint.jsp'

function ChannelIcon({ type }) {
  return <span className="channel-icon" aria-hidden="true">{type === 'phone' ? '📞' : '🔗'}</span>
}

function ChannelRow({ ch }) {
  const isPhone = ch.type === 'phone'
  const href = isPhone ? `tel:${ch.value}` : ch.value
  return (
    <li className="channel">
      <ChannelIcon type={ch.type} />
      <div>
        <div className="channel-name">
          <a href={href} target={isPhone ? undefined : '_blank'} rel={isPhone ? undefined : 'noreferrer'}>
            {ch.name}
          </a>
        </div>
        <div className="channel-value">{ch.value}</div>
        <div className="channel-when">{ch.when}</div>
      </div>
    </li>
  )
}

export default function ReportLinks({ report, fromImage = false }) {
  const [copied, setCopied] = useState(false)
  const [chakshuCopied, setChakshuCopied] = useState(false)

  if (!report) return null

  // "Do not push to file a complaint over a safe message" — quiet secondary link only.
  if (report.should_report === false) {
    if (!report.channels || report.channels.length === 0) return null
    const primary = report.channels[0]
    return (
      <aside className="quiet-report" role="note">
        <span>Was this number suspicious anyway? You can report it to&nbsp;
          <a href={primary.value} target="_blank" rel="noreferrer">{primary.name}</a>.
        </span>
      </aside>
    )
  }

  const summary = report.prefilled_summary || ''

  async function copySummary() {
    try {
      await navigator.clipboard.writeText(summary)
      setCopied(true)
      setTimeout(() => setCopied(false), 2500)
    } catch {
      // Older browsers / permission denied — fallback: select the text.
      const ta = document.getElementById('kavach-summary-textarea')
      if (ta) {
        ta.focus(); ta.select()
      }
    }
  }

  async function copyChakshuSummary() {
    try {
      await navigator.clipboard.writeText(summary)
      setChakshuCopied(true)
      setTimeout(() => setChakshuCopied(false), 2500)
    } catch {
      // Best-effort — the same summary is also copyable from the block above.
    }
  }

  const headline = URGENCY_HEADLINE[report.urgency] || URGENCY_HEADLINE.standard
  const icon = URGENCY_ICON[report.urgency] || URGENCY_ICON.standard
  const bannerClass = `report-banner urgency-${report.urgency || 'standard'}`

  return (
    <section className="report-panel" aria-label="Report this fraud" lang={report.language || 'en'}>
      <header className={bannerClass}>
        <span className="icon" aria-hidden="true">{icon}</span>
        <span>{headline}</span>
      </header>

      <div className="report-body">
        <div>
          <h3 className="section-title" style={{ marginBottom: '0.75rem' }}>Report to</h3>
          <ul className="channel-list">
            {report.channels?.map((ch) => (
              <ChannelRow key={ch.name} ch={ch} />
            ))}
          </ul>
        </div>

        {summary && (
          <div className="summary-block">
            <label htmlFor="kavach-summary-textarea">Ready-to-paste complaint description</label>
            <textarea
              id="kavach-summary-textarea"
              readOnly
              value={summary}
              lang={report.language || 'en'}
              rows={6}
            />
            <div className="copy-row">
              <button type="button" className="btn btn-secondary" onClick={copySummary}>
                {copied ? '✓ Copied' : 'Copy summary'}
              </button>
              {copied && <span className="copy-status" role="status">Copied to clipboard</span>}
              <span style={{ fontSize: 'var(--step--1)', color: 'var(--ink-muted)' }}>
                Fill the [bracketed] fields with your own details before submitting.
              </span>
            </div>
          </div>
        )}

        {report.evidence_checklist && report.evidence_checklist.length > 0 && (
          <div className="evidence">
            <details open={report.urgency === 'immediate' ? false : true}>
              <summary>Evidence to gather before you file ({report.evidence_checklist.length})</summary>
              <ul>
                {report.evidence_checklist.map((item, i) => (
                  <li key={i}>{item}</li>
                ))}
              </ul>
            </details>
          </div>
        )}

        {report.chakshu_category && (
          <div className="chakshu-block">
            <h3 className="section-title">Report to Chakshu</h3>
            <a
              className="btn btn-chakshu"
              href={CHAKSHU_FORM_URL}
              target="_blank"
              rel="noreferrer"
            >
              Open Chakshu complaint form ↗
            </a>

            <p className="chakshu-lead">Use these details to fill in the Chakshu form:</p>
            <ul className="chakshu-checklist">
              <li>
                <span className="chakshu-field">Medium:</span> SMS / WhatsApp — select whichever
                matches how you received this message.
              </li>
              <li>
                <span className="chakshu-field">Category:</span> {report.chakshu_category}
              </li>
              {summary && (
                <li>
                  <span className="chakshu-field">Complaint details:</span>
                  <div className="chakshu-summary-copy">
                    <span className="chakshu-summary-preview">{summary}</span>
                    <button type="button" className="btn btn-secondary btn-small" onClick={copyChakshuSummary}>
                      {chakshuCopied ? '✓ Copied' : 'Copy'}
                    </button>
                  </div>
                </li>
              )}
              <li>
                <span className="chakshu-field">Screenshot:</span>{' '}
                {fromImage
                  ? 'Attach the screenshot you uploaded to Kavach.'
                  : 'Take a screenshot of the suspicious message and attach it.'}
              </li>
              <li>
                <span className="chakshu-field">Date/Time:</span> Note when you received this message.
              </li>
            </ul>
          </div>
        )}
      </div>
    </section>
  )
}
