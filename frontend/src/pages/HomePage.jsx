import { useState } from 'react'
import AnalyzePanel from '../components/AnalyzePanel'
import VerdictCard from '../components/VerdictCard'
import { LANGUAGES } from '../lib/languages'
import { useLang } from '../lib/LangContext'
import { useTranslation } from '../lib/useTranslation'

export default function HomePage() {
  const [verdict, setVerdict] = useState(null)
  const { lang, switchLang } = useLang()
  const { t } = useTranslation()

  const HOW_IT_WORKS = [
    { icon: '🔍', titleKey: 'how_paste', descKey: 'how_paste_desc' },
    { icon: '💡', titleKey: 'how_ai', descKey: 'how_ai_desc' },
    { icon: '📑', titleKey: 'how_cite', descKey: 'how_cite_desc' },
    { icon: '🛡️', titleKey: 'how_guide', descKey: 'how_guide_desc' },
  ]

  return (
    <div className="content">
      <section className="hero">
        <h1>{t('hero_headline')}</h1>
        <p>{t('hero_subtext')}</p>
        <div className="lang-chip-row" role="group" aria-label="Choose verdict language">
          {LANGUAGES.map((l) => (
            <button
              type="button"
              key={l.code}
              className={`lang-pill${lang === l.code ? ' is-selected' : ''}`}
              onClick={() => switchLang(l.code)}
              aria-pressed={lang === l.code}
            >
              {l.label}
            </button>
          ))}
        </div>
      </section>

      <AnalyzePanel onResult={setVerdict} />

      {verdict ? (
        <VerdictCard verdict={verdict} />
      ) : (
        <section className="how-it-works" aria-label="How Kavach works">
          {HOW_IT_WORKS.map((step) => (
            <div className="how-card" key={step.titleKey}>
              <div className="how-icon" aria-hidden="true">{step.icon}</div>
              <div className="how-title">{t(step.titleKey)}</div>
              <p className="how-desc">{t(step.descKey)}</p>
            </div>
          ))}
        </section>
      )}
    </div>
  )
}
