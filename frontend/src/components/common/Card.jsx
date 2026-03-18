import React from 'react';

/**
 * Generic dark-themed card container.
 * Props:
 *   title: string — card heading
 *   children: React node
 *   style: object — extra styles for the outer container
 *   accentColor: string — left border accent color (optional)
 *   noPadding: bool — skip inner padding (default false)
 */
export default function Card({ title, children, style = {}, accentColor, noPadding = false }) {
  return (
    <div style={{
      background: '#1f2937',
      border: '1px solid #374151',
      borderLeft: accentColor ? `4px solid ${accentColor}` : '1px solid #374151',
      borderRadius: 10,
      overflow: 'hidden',
      ...style,
    }}>
      {title && (
        <div style={{
          padding: '12px 20px',
          borderBottom: '1px solid #374151',
          color: '#e5e7eb',
          fontWeight: 700,
          fontSize: 14,
          background: '#161e2e',
        }}>
          {title}
        </div>
      )}
      <div style={noPadding ? {} : { padding: 20 }}>
        {children}
      </div>
    </div>
  );
}
