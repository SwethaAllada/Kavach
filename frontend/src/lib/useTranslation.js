import { T, t as translate } from './translations'
import { useLang } from './LangContext'

// Reactive wrapper around the LangContext: derives t/rtl/dir from the
// current context `lang` value so every consumer re-renders automatically
// when the language changes, without a page reload and without reading
// localStorage directly on every render.
export function useTranslation() {
  const { lang } = useLang()
  return {
    t: (key) => translate(lang, key),
    lang,
    rtl: lang === 'ur',
    dir: lang === 'ur' ? 'rtl' : 'ltr',
  }
}

export { T }
