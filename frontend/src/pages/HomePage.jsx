import { useState } from 'react'
import AnalyzePanel from '../components/AnalyzePanel'
import VerdictCard from '../components/VerdictCard'

const LANG_CHIPS = ['English', 'हिन्दी', 'తెలుగు', 'தமிழ்', 'বাংলা', 'मराठी', 'ਪੰਜਾਬੀ']

export default function HomePage() {
  const [verdict, setVerdict] = useState(null)

  return (
    <div className="content">
      <section className="hero">
        <h1>Is this message a scam?</h1>
        <p>
          Paste any suspicious SMS or WhatsApp message. Get an instant answer in your
          language — free, private, no sign-up.
        </p>
        <div className="lang-chip-row" aria-hidden="true">
          {LANG_CHIPS.map((l) => (
            <span className="lang-pill" key={l}>{l}</span>
          ))}
        </div>
      </section>

      <AnalyzePanel onResult={setVerdict} />

      {verdict && <VerdictCard verdict={verdict} />}
    </div>
  )
}
