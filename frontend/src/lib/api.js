const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:8000'

export async function analyze(text) {
  const response = await fetch(`${API_BASE}/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text }),
  })
  return response.json()
}
