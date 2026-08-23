// Human-readable labels for signals from the backend.
const SIGNAL_LABEL = {
  authority: 'Authority impersonation',
  fear: 'Fear / threats',
  isolation: 'Isolation from family',
  urgency: 'Extreme urgency',
  payment: 'Payment demand',
  secrecy: 'Secrecy pressure',
  too_good_to_be_true: 'Too good to be true',
  credential_request: 'Asks for OTP / password',
  phishing_url: 'Known phishing link (PhishTank)',
}

// authority/fear/payment/credential_request = danger tint;
// isolation/secrecy/urgency/too_good_to_be_true = warn tint.
const SIGNAL_TONE = {
  authority: 'danger',
  fear: 'danger',
  payment: 'danger',
  credential_request: 'danger',
  isolation: 'warn',
  secrecy: 'warn',
  urgency: 'warn',
  too_good_to_be_true: 'warn',
  phishing_url: 'danger',
}

export default function SignalChips({ signals = [] }) {
  if (!signals || signals.length === 0) return null
  return (
    <ul className="signal-chips">
      {signals.map((s) => {
        const tone = SIGNAL_TONE[s] || 'warn'
        const label = SIGNAL_LABEL[s] || s.replace(/_/g, ' ')
        return (
          <li key={s} className={`signal-chip tone-${tone}`}>
            <span className="dot" aria-hidden="true" />
            <span>{label}</span>
          </li>
        )
      })}
    </ul>
  )
}
