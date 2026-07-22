// Kavach API client.
// - Reads base URL from VITE_API_BASE (default http://localhost:8000)
// - Robust error handling: distinguishes network failures from HTTP errors
//   from malformed JSON, so the UI can show a clear message either way.
// - No timeout by default because the backend can legitimately take 8-15s on
//   an LLM call; callers can pass an AbortSignal to bound it.

const API_BASE = (import.meta.env.VITE_API_BASE || 'http://localhost:8000').replace(/\/+$/, '')

export class ApiError extends Error {
  constructor(message, { kind, status, detail } = {}) {
    super(message)
    this.name = 'ApiError'
    this.kind = kind // 'network' | 'http' | 'parse' | 'abort'
    this.status = status
    this.detail = detail
  }
}

/**
 * Send text to the backend for analysis. Returns the Verdict object.
 * Throws ApiError with `kind` set for the caller to render a specific message.
 */
export async function analyze(text, { signal } = {}) {
  const trimmed = (text || '').trim()
  if (!trimmed) {
    throw new ApiError('Please enter a message to analyze.', { kind: 'input' })
  }

  let response
  try {
    response = await fetch(`${API_BASE}/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text: trimmed }),
      signal,
    })
  } catch (err) {
    if (err && err.name === 'AbortError') {
      throw new ApiError('Analysis was cancelled.', { kind: 'abort' })
    }
    throw new ApiError(
      "Couldn't reach the Kavach backend. Is the server running on " + API_BASE + '?',
      { kind: 'network', detail: err && err.message },
    )
  }

  const contentType = response.headers.get('content-type') || ''
  let body = null
  if (contentType.includes('application/json')) {
    try {
      body = await response.json()
    } catch (err) {
      throw new ApiError('The backend returned a malformed response.', {
        kind: 'parse',
        status: response.status,
        detail: err && err.message,
      })
    }
  }

  if (!response.ok) {
    const detail = (body && (body.detail || body.error || body.message)) || response.statusText
    throw new ApiError(`Analysis failed (HTTP ${response.status}). ${detail}`, {
      kind: 'http',
      status: response.status,
      detail,
    })
  }

  if (!body || typeof body !== 'object' || !body.scam_type) {
    throw new ApiError('The backend returned an unexpected response.', {
      kind: 'parse',
      status: response.status,
    })
  }

  return body
}

/**
 * Fetch the anonymized trends aggregate. Never throws — on any failure
 * returns an empty shape with status="unavailable" so the caller can render
 * a graceful message without a crash.
 */
export async function getTrends({ signal } = {}) {
  const empty = {
    status: 'unavailable',
    total_count: 0,
    by_scam_type: {},
    by_risk_bucket: { low: 0, medium: 0, high: 0 },
    by_language: {},
    by_decision_source: {},
    fallback_used_count: 0,
    last_7_days: [],
  }
  try {
    const response = await fetch(`${API_BASE}/trends`, { signal })
    if (!response.ok) return empty
    const body = await response.json()
    if (!body || typeof body !== 'object') return empty
    return { ...empty, ...body }
  } catch {
    return empty
  }
}

/** Base URL, exposed for status displays and debugging. */
export function getApiBase() {
  return API_BASE
}
