import { useState, useRef, useCallback } from 'react'
import { analyze, ApiError } from '../lib/api'

// Realistic one-tap examples across scam_type and language. Kept close to the
// eval dataset so judges get recognizable, well-tested demo inputs.
const EXAMPLES = [
  {
    id: 'en_digital_arrest',
    label: 'English • Digital Arrest',
    text:
      "This is CBI. A parcel with your Aadhaar has illegal items. Stay on this " +
      "video call, do not tell anyone, and transfer Rs 2,00,000 to this " +
      "verification account. Contact +919812345678.",
  },
  {
    id: 'hi_scam',
    label: 'हिन्दी • Scam',
    text:
      "मैं CBI से बोल रहा हूं। आपके नाम पर मुकदमा दर्ज है। तुरंत इस Skype कॉल पर आएं, " +
      "किसी को मत बताना, अन्यथा गिरफ्तार वारंट जारी होगा।",
  },
  {
    id: 'te_scam',
    label: 'తెలుగు • Scam',
    text:
      "మీ SBI ఖాతా బ్లాక్ అవుతుంది. KYC అప్‌డేట్ కోసం OTP వెంటనే షేర్ చేయండి. " +
      "లేకపోతే ఖాతా మూసివేయబడుతుంది. https://sbi-kyc-verify.co.in",
  },
  {
    id: 'legit_otp',
    label: 'English • Legit OTP',
    text:
      "Your OTP for HDFC Bank is 483920. Do not share it with anyone. Valid for 10 minutes.",
  },
]

export default function AnalyzePanel({ onResult, onLoadingChange }) {
  const [text, setText] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const abortRef = useRef(null)

  const runAnalyze = useCallback(async (input) => {
    setError(null)
    onResult && onResult(null)                 // clear prior verdict
    setLoading(true)
    onLoadingChange && onLoadingChange(true)

    // Cancel any in-flight call if the user re-submits fast.
    if (abortRef.current) abortRef.current.abort()
    const controller = new AbortController()
    abortRef.current = controller

    try {
      const verdict = await analyze(input, { signal: controller.signal })
      onResult && onResult(verdict)
    } catch (err) {
      if (err instanceof ApiError && err.kind === 'abort') return
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setLoading(false)
      onLoadingChange && onLoadingChange(false)
    }
  }, [onResult, onLoadingChange])

  function onSubmit(e) {
    e.preventDefault()
    runAnalyze(text)
  }

  function useExample(ex) {
    setText(ex.text)
    // Run immediately so a single tap gives judges the full flow.
    runAnalyze(ex.text)
  }

  return (
    <section className="card analyze" aria-label="Analyze a message">
      <h2 className="card-title">Analyze a message</h2>
      <p className="card-subtitle">
        Paste a suspicious call, SMS, or WhatsApp message. We'll check it in seconds —
        works in English, हिन्दी, and తెలుగు.
      </p>

      <form onSubmit={onSubmit}>
        <label className="visually-hidden" htmlFor="kavach-analyze-input">Suspicious message</label>
        <textarea
          id="kavach-analyze-input"
          value={text}
          onChange={(e) => setText(e.target.value)}
          rows={6}
          disabled={loading}
          placeholder="Paste a suspicious call, SMS, or WhatsApp message here…"
          aria-label="Suspicious message"
        />

        <div className="analyze-actions">
          <button type="submit" className="btn" disabled={loading || !text.trim()}>
            {loading ? (
              <>
                <span className="spinner" aria-hidden="true" />
                <span>Analyzing…</span>
              </>
            ) : (
              <>Analyze</>
            )}
          </button>

          {text && !loading && (
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => { setText(''); setError(null); onResult && onResult(null) }}
              aria-label="Clear input"
            >
              Clear
            </button>
          )}
        </div>

        <div className="example-strip" aria-label="Try an example">
          <span className="label">Try an example:</span>
          {EXAMPLES.map((ex) => (
            <button
              type="button"
              key={ex.id}
              className="example-chip"
              onClick={() => useExample(ex)}
              disabled={loading}
            >
              {ex.label}
            </button>
          ))}
        </div>

        {error && (
          <div className="error-box" role="alert">
            <strong>Something went wrong.</strong> {error}
          </div>
        )}
      </form>
    </section>
  )
}
