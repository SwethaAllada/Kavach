const FAQS = [
  {
    q: 'Is my message stored anywhere?',
    a: 'No. Your message is processed in memory and immediately discarded after ' +
      'analysis. We never store your message text, your phone number, or your ' +
      'identity. Only an anonymous count of the scam type detected is kept for ' +
      'our trends map.',
  },
  {
    q: 'What languages does Kavach support?',
    a: 'Kavach understands and responds in 20 Indian languages: English, Hindi, ' +
      'Telugu, Tamil, Bengali, Marathi, Gujarati, Kannada, Malayalam, Punjabi, ' +
      'Odia, Urdu, Assamese, Sanskrit, Maithili, Santali, Kashmiri, Nepali, ' +
      'Konkani, and Sindhi. It also handles mixed-language messages like ' +
      'Hinglish and Tenglish — the way Indians actually write.',
  },
  {
    q: 'How accurate is Kavach?',
    a: 'On a benchmark of 377 messages spanning all scam types across three languages, ' +
      'Kavach correctly identified scams with over 98% accuracy and a near-zero ' +
      'false-positive rate on legitimate messages like real bank OTPs and delivery ' +
      'notifications. It is not perfect — when in doubt, call 1930.',
  },
  {
    q: 'What if I have already lost money?',
    a: 'Call 1930 immediately — this is India’s 24/7 Cyber Crime Helpline. Do not ' +
      'wait. Also file a complaint at cybercrime.gov.in. Time matters when money ' +
      'has been transferred.',
  },
  {
    q: 'How is Kavach different from Truecaller?',
    a: 'Truecaller identifies who is calling based on a phone number database. ' +
      'Kavach reads the content of the message to understand the scam’s intent. ' +
      'These solve different problems: Truecaller cannot help when a scammer uses ' +
      'a new or spoofed number, and cannot analyze a WhatsApp message at all. ' +
      'Kavach can. Truecaller also requires access to your contacts and call logs. ' +
      'Kavach stores nothing about you.',
  },
  {
    q: 'Can I use Kavach on WhatsApp?',
    a: 'Yes. Save the Kavach WhatsApp number as a contact and forward any suspicious ' +
      'message to it. You will receive a verdict reply in seconds, in your language.',
  },
  {
    q: 'What is Chakshu / Sanchar Saathi?',
    a: 'Chakshu is India’s official fraud reporting portal, run by the Department ' +
      'of Telecommunications. Reporting a scam there helps authorities trace and ' +
      'block fraud numbers nationwide. Kavach helps you prepare your Chakshu report ' +
      'by identifying the scam type and drafting complaint text for you.',
  },
  {
    q: 'What if Kavach says it is safe but I am still worried?',
    a: 'Trust your instincts — Kavach is a guide, not a guarantee. If something ' +
      'feels wrong, do not share any OTP, PIN, or money regardless of what Kavach ' +
      'says. Call 1930 if you are unsure. Your caution is always right.',
  },
]

export default function FAQPage() {
  return (
    <div className="content content-narrow">
      <h1>Frequently Asked Questions</h1>
      <div>
        {FAQS.map((item, i) => (
          <details className="faq-item" key={i}>
            <summary>
              <span>{item.q}</span>
              <span className="faq-indicator" aria-hidden="true" />
            </summary>
            <p className="faq-answer">{item.a}</p>
          </details>
        ))}
      </div>
    </div>
  )
}
