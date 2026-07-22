import { useState } from 'react'
import { analyze } from './lib/api'

export default function App() {
  const [text, setText] = useState('')
  const [result, setResult] = useState(null)

  async function handleAnalyze() {
    const data = await analyze(text)
    setResult(data)
  }

  return (
    <div>
      <h1>Kavach</h1>
      <textarea
        value={text}
        onChange={(e) => setText(e.target.value)}
        rows={6}
        placeholder="Paste a suspicious message here..."
      />
      <br />
      <button onClick={handleAnalyze}>Analyze</button>
      {result && <pre>{JSON.stringify(result, null, 2)}</pre>}
    </div>
  )
}
