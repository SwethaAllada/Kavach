const STEPS = [
  { icon: '🔍', name: 'Detect', desc: 'Rules, a language model, and a scam knowledge base scan the message.' },
  { icon: '💡', name: 'Explain', desc: 'You get a clear reason why it is or isn’t a scam, in your language.' },
  { icon: '📑', name: 'Cite', desc: 'Matched patterns are shown as citations, grounded in real advisories.' },
  { icon: '🛡️', name: 'Guide', desc: 'A concrete next step, plus a ready-to-file report if needed.' },
]

const LANGUAGES = ['English', 'हिन्दी', 'తెలుగు', 'தமிழ்', 'বাংলা', 'मराठी', 'ગુજરાતી', 'ಕನ್ನಡ', 'മലയാളം', 'ਪੰਜਾਬੀ']

export default function AboutPage() {
  return (
    <div className="content content-narrow">
      <h1>About Kavach</h1>
      <p>
        Kavach is a free AI-powered fraud shield built for every Indian citizen.
        Forward any suspicious SMS or WhatsApp message and get an instant, clear
        verdict — what kind of scam it is, why it's suspicious, and exactly what
        to do next. It works in 10 Indian languages and stores nothing about you.
      </p>

      <h2>How it works</h2>
      <div className="about-steps">
        {STEPS.map((s) => (
          <div className="about-step" key={s.name}>
            <div className="icon" aria-hidden="true">{s.icon}</div>
            <div className="name">{s.name}</div>
            <p className="desc">{s.desc}</p>
          </div>
        ))}
      </div>

      <h2>Languages supported</h2>
      <div className="lang-chip-row">
        {LANGUAGES.map((l) => (
          <span className="lang-pill" key={l}>{l}</span>
        ))}
      </div>

      <h2>Privacy promise</h2>
      <div className="privacy-box">
        Your message is never stored. Kavach processes it in memory to detect
        the scam pattern, then immediately discards it. Only an anonymized count
        (scam type and language detected — nothing else) is kept for our trends
        map. Your identity, your message text, and any personal details are
        never recorded, never sold, and never shared.
      </div>

      <h2>Powered by</h2>
      <p>
        Kavach uses a hybrid AI engine combining deterministic rules, a large
        language model, and a knowledge base of documented Indian scam patterns
        to classify messages. It is grounded in real government advisories from
        MHA, I4C, RBI, and TRAI.
      </p>

      <h2>Limitations</h2>
      <p>
        Kavach is a guidance tool, not a guarantee. It is accurate in the vast
        majority of cases but not perfect. When in doubt, call 1930 or trust
        your instincts — never share an OTP, PIN, or transfer money under pressure.
      </p>
    </div>
  )
}
