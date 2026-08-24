import { createContext, useContext, useState, useEffect, createElement } from 'react'
import { LANGUAGE_CODES } from './languages'

const SUPPORTED = LANGUAGE_CODES
const STORAGE_KEY = 'kavach_ui_lang' // MUST match the existing key already used elsewhere in this codebase

function detectDefaultLang() {
  try {
    const stored = localStorage.getItem(STORAGE_KEY)
    if (stored && SUPPORTED.includes(stored)) return stored
  } catch {
    // localStorage unavailable (private mode, etc.) — fall through to browser detection.
  }
  try {
    const browserLang = navigator.language?.split('-')[0]
    if (browserLang && SUPPORTED.includes(browserLang)) return browserLang
  } catch {
    // navigator unavailable in some non-browser test/SSR context — fall through.
  }
  return 'en'
}

export const LangContext = createContext({ lang: 'en', switchLang: () => {} })

export function LangProvider({ children }) {
  const [lang, setLang] = useState(detectDefaultLang)

  const switchLang = (code) => {
    if (!SUPPORTED.includes(code)) return // defensive: never set an unsupported code
    try {
      localStorage.setItem(STORAGE_KEY, code)
    } catch {
      // best-effort persistence only
    }
    setLang(code)
  }

  useEffect(() => {
    document.documentElement.dir = lang === 'ur' ? 'rtl' : 'ltr'
    document.documentElement.lang = lang
  }, [lang])

  return createElement(LangContext.Provider, { value: { lang, switchLang } }, children)
}

export const useLang = () => useContext(LangContext)
