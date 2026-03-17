import React from 'react';

/**
 * Stat card with label, value, and optional sub-label.
 * Props:
 *   label: string — card label
 *   value: string | number — main displayed value
 *   color: string — accent color
 *   sub: string — optional sub-label below value
 *   icon: string — optional emoji/icon prefix
 */
export default function StatCard({ label, value, color = '#60a5fa', sub, icon }) {
  return (
    <div style={{
      background: '#1f2937',
      border: `1px solid ${color}30`,
      borderLeft: `4px solid ${color}`,
      borderRadius: 8,
      padding: '14px 18px',
      flex: 1,
      minWidth: 120,
    }}>
      <div style={{ color: '#9ca3af', fontSize: 11, fontWeight: 600, marginBottom: 6, letterSpacing: 0.3 }}>
        {icon && <span style={{ marginRight: 4 }}>{icon}</span>}
        {label}
      </div>
      <div style={{ color, fontSize: 30, fontWeight: 800, lineHeight: 1 }}>
        {value}
      </div>
      {sub && (
        <div style={{ color: '#4b5563', fontSize: 11, marginTop: 4 }}>{sub}</div>
      )}
    </div>
  );
}
