import React from 'react';

const SEVERITY_PRESETS = {
  CRITICAL: { bg: '#dc2626', color: '#fff' },
  HIGH: { bg: '#ea580c', color: '#fff' },
  MEDIUM: { bg: '#d97706', color: '#fff' },
  LOW: { bg: '#65a30d', color: '#fff' },
  INFO: { bg: '#6b7280', color: '#fff' },
  PASS: { bg: '#14532d', color: '#4ade80' },
  FAIL: { bg: '#450a0a', color: '#f87171' },
  NA: { bg: '#1f2937', color: '#9ca3af' },
  ALLOW: { bg: '#14532d', color: '#4ade80' },
  REVIEW: { bg: '#451a03', color: '#fbbf24' },
  BLOCK: { bg: '#450a0a', color: '#f87171' },
};

/**
 * Generic badge component.
 * Props:
 *   label: string — text to display
 *   variant: string — one of the SEVERITY_PRESETS keys (optional)
 *   bg: string — custom background color (optional)
 *   color: string — custom text color (optional)
 *   size: 'sm' | 'md' — badge size (default: 'sm')
 */
export default function Badge({ label, variant, bg, color, size = 'sm' }) {
  const preset = SEVERITY_PRESETS[(variant || label || '').toUpperCase()] || {};
  const finalBg = bg || preset.bg || '#374151';
  const finalColor = color || preset.color || '#fff';
  const padding = size === 'md' ? '4px 12px' : '2px 8px';
  const fontSize = size === 'md' ? 13 : 11;

  return (
    <span style={{
      background: finalBg,
      color: finalColor,
      padding,
      borderRadius: 4,
      fontSize,
      fontWeight: 700,
      letterSpacing: 0.3,
      display: 'inline-block',
    }}>
      {label}
    </span>
  );
}
