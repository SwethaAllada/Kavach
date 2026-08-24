import { useTranslation } from '../lib/useTranslation'

const FAQS = [
  { qKey: 'faq_q1', aKey: 'faq_a1' },
  { qKey: 'faq_q2', aKey: 'faq_a2' },
  { qKey: 'faq_q3', aKey: 'faq_a3' },
  { qKey: 'faq_q4', aKey: 'faq_a4' },
  { qKey: 'faq_q5', aKey: 'faq_a5' },
  { qKey: 'faq_q6', aKey: 'faq_a6' },
  { qKey: 'faq_q7', aKey: 'faq_a7' },
  { qKey: 'faq_q8', aKey: 'faq_a8' },
]

export default function FAQPage() {
  const { t } = useTranslation()

  return (
    <div className="content content-narrow">
      <h1>{t('faq_headline')}</h1>
      <div>
        {FAQS.map((item) => (
          <details className="faq-item" key={item.qKey}>
            <summary>
              <span>{t(item.qKey)}</span>
              <span className="faq-indicator" aria-hidden="true" />
            </summary>
            <p className="faq-answer">{t(item.aKey)}</p>
          </details>
        ))}
      </div>
    </div>
  )
}
