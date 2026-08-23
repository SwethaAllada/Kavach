// UI section labels for VerdictCard, per interface language. This is
// display-copy translation for the FIXED section headers ("WHY THIS
// VERDICT", etc.) — separate from the backend's own detected_language,
// which drives the actual explanation/action text content.

// localStorage key the language chips (HomePage) write to and VerdictCard
// reads from. Shared here (not a component) so both can import it without
// depending on each other.
export const LANG_STORAGE_KEY = 'kavach_ui_lang'

export const SECTION_LABELS = {
  en: {
    verdict: 'VERDICT', why: 'WHY THIS VERDICT', whatToDo: 'WHAT TO DO',
    signals: 'WARNING SIGNALS DETECTED', patterns: 'MATCHED SCAM PATTERNS',
    safe: 'THIS LOOKS SAFE', reportNow: 'ACT NOW — REPORT THIS FRAUD',
    reportSuggested: 'YOU SHOULD REPORT THIS',
  },
  hi: {
    verdict: 'निर्णय', why: 'यह निर्णय क्यों', whatToDo: 'क्या करें',
    signals: 'चेतावनी संकेत', patterns: 'जाने-माने घोटाले के नमूने',
    safe: 'यह सुरक्षित लगता है', reportNow: 'अभी रिपोर्ट करें',
    reportSuggested: 'इसकी रिपोर्ट करें',
  },
  te: {
    verdict: 'నిర్ణయం', why: 'ఈ నిర్ణయం ఎందుకు', whatToDo: 'ఏమి చేయాలి',
    signals: 'హెచ్చరిక సంకేతాలు', patterns: 'తెలిసిన మోసం నమూనాలు',
    safe: 'ఇది సురక్షితంగా కనిపిస్తోంది', reportNow: 'ఇప్పుడే నివేదించండి',
    reportSuggested: 'నివేదించడం మంచిది',
  },
  ta: {
    verdict: 'தீர்ப்பு', why: 'இந்த தீர்ப்பு ஏன்', whatToDo: 'என்ன செய்வது',
    signals: 'எச்சரிக்கை சமிக்ஞைகள்', patterns: 'அறியப்பட்ட மோசடி முறைகள்',
    safe: 'இது பாதுகாப்பாக தெரிகிறது', reportNow: 'இப்போது புகாரளிக்கவும்',
    reportSuggested: 'புகாரளிக்கவும்',
  },
  bn: {
    verdict: 'রায়', why: 'এই রায় কেন', whatToDo: 'কী করবেন',
    signals: 'সতর্কতা সংকেত', patterns: 'পরিচিত প্রতারণার ধরন',
    safe: 'এটি নিরাপদ মনে হচ্ছে', reportNow: 'এখনই রিপোর্ট করুন',
    reportSuggested: 'রিপোর্ট করুন',
  },
  mr: {
    verdict: 'निर्णय', why: 'हा निर्णय का', whatToDo: 'काय करावे',
    signals: 'इशारा संकेत', patterns: 'ओळखीचे फसवणूक नमुने',
    safe: 'हे सुरक्षित वाटते', reportNow: 'आत्ता तक्रार करा',
    reportSuggested: 'तक्रार करा',
  },
  gu: {
    verdict: 'ચુકાદો', why: 'આ ચુકાદો શા માટે', whatToDo: 'શું કરવું',
    signals: 'ચેતવણી સંકેતો', patterns: 'જાણીતા છેતરપિંડી નમૂના',
    safe: 'આ સુરક્ષિત લાગે છે', reportNow: 'હવે ફરિયાદ કરો',
    reportSuggested: 'ફરિયાદ કરો',
  },
  kn: {
    verdict: 'ತೀರ್ಪು', why: 'ಈ ತೀರ್ಪು ಏಕೆ', whatToDo: 'ಏನು ಮಾಡಬೇಕು',
    signals: 'ಎಚ್ಚರಿಕೆ ಸಂಕೇತಗಳು', patterns: 'ತಿಳಿದ ವಂಚನೆ ಮಾದರಿಗಳು',
    safe: 'ಇದು ಸುರಕ್ಷಿತವಾಗಿ ಕಾಣುತ್ತದೆ', reportNow: 'ಈಗ ವರದಿ ಮಾಡಿ',
    reportSuggested: 'ವರದಿ ಮಾಡಿ',
  },
  ml: {
    verdict: 'വിധി', why: 'ഈ വിധി എന്തുകൊണ്ട്', whatToDo: 'എന്ത് ചെയ്യണം',
    signals: 'മുന്നറിയിപ്പ് സൂചനകൾ', patterns: 'അറിയപ്പെടുന്ന തട്ടിപ്പ് രീതികൾ',
    safe: 'ഇത് സുരക്ഷിതമായി തോന്നുന്നു', reportNow: 'ഇപ്പോൾ റിപ്പോർട്ട് ചെയ്യുക',
    reportSuggested: 'റിപ്പോർട്ട് ചെയ്യുക',
  },
  pa: {
    verdict: 'ਫੈਸਲਾ', why: 'ਇਹ ਫੈਸਲਾ ਕਿਉਂ', whatToDo: 'ਕੀ ਕਰਨਾ ਹੈ',
    signals: 'ਚੇਤਾਵਨੀ ਸੰਕੇਤ', patterns: 'ਜਾਣੇ-ਪਛਾਣੇ ਧੋਖੇ ਦੇ ਨਮੂਨੇ',
    safe: 'ਇਹ ਸੁਰੱਖਿਅਤ ਲੱਗਦਾ ਹੈ', reportNow: 'ਹੁਣੇ ਰਿਪੋਰਟ ਕਰੋ',
    reportSuggested: 'ਰਿਪੋਰਟ ਕਰੋ',
  },
}

export const getLabels = (lang) => SECTION_LABELS[lang] || SECTION_LABELS.en
