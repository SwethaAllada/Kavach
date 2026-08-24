import { LANGUAGES } from '../lib/languages'
import { useTranslation } from '../lib/useTranslation'

export default function AboutPage() {
  const { t } = useTranslation()

  return (
    <div className="content content-narrow">
      <h1>{t('about_headline')}</h1>
      <p>{t('about_p1')}</p>

      <h2>{t('about_how_headline')}</h2>

      <h2>{t('about_languages_headline')}</h2>
      <p className="muted">{t('about_languages_desc')}</p>
      <div className="lang-chip-row">
        {LANGUAGES.map((l) => (
          <span className="lang-pill" key={l.code}>{l.label}</span>
        ))}
      </div>

      <h2>{t('about_privacy_headline')}</h2>
      <div className="privacy-box">
        {t('about_privacy_text')}
      </div>

      <h2>{t('about_limits_headline')}</h2>
      <p>{t('about_limits_text')}</p>
    </div>
  )
}
