import React from 'react'

/**
 * Circular risk meter. Reads risk 0-100 and a state ('safe' | 'caution' | 'danger')
 * and renders an SVG arc. Colors + animation come from CSS (see index.css).
 * `prefers-reduced-motion` is respected by the global CSS override.
 */
export default function RiskMeter({ risk = 0, state = 'safe' }) {
  const clamped = Math.max(0, Math.min(100, Math.round(risk)))
  const radius = 70
  const circumference = 2 * Math.PI * radius
  const offset = circumference * (1 - clamped / 100)

  return (
    <div
      className="risk-meter"
      role="meter"
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={clamped}
      aria-label={`Risk score ${clamped} out of 100`}
    >
      <svg viewBox="0 0 168 168" aria-hidden="true">
        <circle className="track" cx="84" cy="84" r={radius} />
        <circle
          className={`fill state-${state}`}
          cx="84"
          cy="84"
          r={radius}
          strokeDasharray={circumference}
          strokeDashoffset={offset}
        />
      </svg>
      <div className="center">
        <div>
          <div className="risk-num">{clamped}</div>
          <div className="risk-lbl">Risk</div>
        </div>
      </div>
    </div>
  )
}
