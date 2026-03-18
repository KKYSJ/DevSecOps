import React from 'react';

const SEVERITY_COLORS = {
  CRITICAL: { bg: '#dc2626', color: '#fff' },
  HIGH: { bg: '#ea580c', color: '#fff' },
  MEDIUM: { bg: '#d97706', color: '#fff' },
  LOW: { bg: '#65a30d', color: '#fff' },
  INFO: { bg: '#6b7280', color: '#fff' },
};

function SeverityBadge({ severity }) {
  const s = (severity || 'INFO').toUpperCase();
  const style = SEVERITY_COLORS[s] || SEVERITY_COLORS.INFO;
  return (
    <span style={{
      background: style.bg,
      color: style.color,
      padding: '2px 8px',
      borderRadius: 4,
      fontSize: 11,
      fontWeight: 700,
      letterSpacing: 0.5,
    }}>
      {s}
    </span>
  );
}

function ConfidenceBadge({ level }) {
  const l = (level || '').toUpperCase();
  const colorMap = { HIGH: '#16a34a', MED: '#d97706', MEDIUM: '#d97706', LOW: '#6b7280' };
  const bg = colorMap[l] || '#374151';
  return (
    <span style={{
      background: bg,
      color: '#fff',
      padding: '2px 6px',
      borderRadius: 4,
      fontSize: 11,
      fontWeight: 600,
    }}>
      {l || '-'}
    </span>
  );
}

function CategoryBadge({ category }) {
  const colorMap = {
    SAST: '#3b82f6',
    SCA: '#8b5cf6',
    IAC: '#06b6d4',
    DAST: '#f59e0b',
  };
  const bg = colorMap[(category || '').toUpperCase()] || '#6b7280';
  return (
    <span style={{
      background: bg,
      color: '#fff',
      padding: '2px 8px',
      borderRadius: 4,
      fontSize: 11,
      fontWeight: 600,
    }}>
      {(category || '').toUpperCase()}
    </span>
  );
}

export default function VulnTable({ vulns = [], showTool = true }) {
  const thStyle = {
    padding: '10px 12px',
    textAlign: 'left',
    color: '#9ca3af',
    fontSize: 12,
    fontWeight: 600,
    borderBottom: '1px solid #374151',
    whiteSpace: 'nowrap',
  };

  const tdStyle = {
    padding: '10px 12px',
    fontSize: 13,
    color: '#e5e7eb',
    borderBottom: '1px solid #1f2937',
    verticalAlign: 'top',
  };

  if (!vulns || vulns.length === 0) {
    return (
      <div style={{ color: '#9ca3af', textAlign: 'center', padding: 40, fontSize: 14 }}>
        취약점이 없습니다.
      </div>
    );
  }

  return (
    <div style={{ overflowX: 'auto' }}>
      <table style={{ width: '100%', borderCollapse: 'collapse' }}>
        <thead>
          <tr>
            <th style={thStyle}>심각도</th>
            <th style={thStyle}>제목</th>
            {showTool && <th style={thStyle}>도구</th>}
            <th style={thStyle}>카테고리</th>
            <th style={thStyle}>파일/패키지</th>
            <th style={thStyle}>CWE/CVE</th>
            <th style={thStyle}>신뢰도</th>
            <th style={thStyle}>조치</th>
          </tr>
        </thead>
        <tbody>
          {vulns.map((v, idx) => {
            const fileOrPkg = v.file_path
              ? `${v.file_path}${v.line_number ? `:${v.line_number}` : ''}`
              : v.package_name
              ? `${v.package_name}${v.package_version ? `@${v.package_version}` : ''}`
              : v.url
              ? v.url
              : '-';

            const cweOrCve = v.cve_id || v.cwe_id || '-';

            const actionHint = v.fixed_version
              ? `${v.package_name || ''}을(를) ${v.fixed_version}으로 업그레이드`
              : v.category === 'SAST'
              ? '코드 검토 및 수정 필요'
              : v.category === 'IaC'
              ? 'IaC 설정 검토 필요'
              : v.category === 'DAST'
              ? '입력값 검증 및 인코딩 적용'
              : '수동 검토 필요';

            const rowBg = idx % 2 === 0 ? '#1f2937' : '#111827';

            return (
              <tr key={v.id || idx} style={{ background: rowBg }}>
                <td style={tdStyle}>
                  <SeverityBadge severity={v.severity} />
                </td>
                <td style={{ ...tdStyle, maxWidth: 280 }}>
                  <div style={{ fontWeight: 600, color: '#fff', fontSize: 13, wordBreak: 'break-word' }}>
                    {v.title || '-'}
                  </div>
                  {v.description && (
                    <div style={{ color: '#6b7280', fontSize: 11, marginTop: 2 }}>{v.description}</div>
                  )}
                </td>
                {showTool && (
                  <td style={tdStyle}>
                    <span style={{ color: '#60a5fa', fontFamily: 'monospace', fontSize: 12 }}>
                      {v.tool || '-'}
                    </span>
                  </td>
                )}
                <td style={tdStyle}>
                  <CategoryBadge category={v.category} />
                </td>
                <td style={{ ...tdStyle, fontFamily: 'monospace', fontSize: 11, color: '#9ca3af', maxWidth: 200, wordBreak: 'break-all' }}>
                  {fileOrPkg}
                </td>
                <td style={{ ...tdStyle, fontFamily: 'monospace', fontSize: 11 }}>
                  {cweOrCve !== '-' ? (
                    <span style={{ color: '#f87171' }}>{cweOrCve}</span>
                  ) : '-'}
                </td>
                <td style={tdStyle}>
                  <ConfidenceBadge level={v.confidence} />
                </td>
                <td style={{ ...tdStyle, fontSize: 12, color: '#9ca3af', maxWidth: 180 }}>
                  {actionHint}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
