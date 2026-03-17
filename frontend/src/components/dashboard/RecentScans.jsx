import React from 'react';

const CATEGORY_COLORS = {
  SAST: '#3b82f6',
  SCA: '#8b5cf6',
  IaC: '#06b6d4',
  DAST: '#f59e0b',
};

export default function RecentScans({ scans = [] }) {
  if (!scans || scans.length === 0) {
    return (
      <div style={{ color: '#9ca3af', textAlign: 'center', padding: 20, fontSize: 13 }}>
        스캔 이력이 없습니다.
      </div>
    );
  }

  return (
    <div style={{ overflowX: 'auto' }}>
      <table style={{ width: '100%', borderCollapse: 'collapse' }}>
        <thead>
          <tr>
            {['스캔 ID', '도구', '카테고리', '발견 수', '상태', '실행 시각'].map(h => (
              <th key={h} style={{
                padding: '8px 12px',
                textAlign: 'left',
                color: '#9ca3af',
                fontSize: 11,
                fontWeight: 600,
                borderBottom: '1px solid #374151',
              }}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {scans.map((scan, idx) => {
            const catColor = CATEGORY_COLORS[scan.category] || '#6b7280';
            return (
              <tr key={scan.id || idx} style={{ background: idx % 2 === 0 ? '#1f2937' : '#111827' }}>
                <td style={{ padding: '8px 12px', color: '#60a5fa', fontFamily: 'monospace', fontSize: 12 }}>
                  {scan.id}
                </td>
                <td style={{ padding: '8px 12px', color: '#fff', fontSize: 13 }}>{scan.tool}</td>
                <td style={{ padding: '8px 12px' }}>
                  <span style={{
                    background: catColor + '30',
                    color: catColor,
                    padding: '2px 8px',
                    borderRadius: 4,
                    fontSize: 11,
                    fontWeight: 600,
                  }}>{scan.category}</span>
                </td>
                <td style={{ padding: '8px 12px', color: scan.findings > 0 ? '#f87171' : '#4ade80', fontWeight: 700 }}>
                  {scan.findings}
                </td>
                <td style={{ padding: '8px 12px' }}>
                  <span style={{
                    background: '#14532d',
                    color: '#4ade80',
                    padding: '2px 8px',
                    borderRadius: 4,
                    fontSize: 11,
                  }}>{scan.status}</span>
                </td>
                <td style={{ padding: '8px 12px', color: '#6b7280', fontSize: 12 }}>{scan.time}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
