import React, { useState, useEffect } from 'react';
import axios from 'axios';

const API_BASE = process.env.REACT_APP_API_BASE_URL || 'http://localhost:8000/api/v1';


const SEVERITY_COLORS = {
  CRITICAL: { bg: '#dc2626', color: '#fff' },
  HIGH: { bg: '#ea580c', color: '#fff' },
  MEDIUM: { bg: '#d97706', color: '#fff' },
  LOW: { bg: '#65a30d', color: '#fff' },
  INFO: { bg: '#6b7280', color: '#fff' },
};

const GATE_STYLES = {
  ALLOW: { bg: '#14532d', border: '#16a34a', text: '#4ade80', icon: '✅', label: '배포 허용' },
  REVIEW: { bg: '#451a03', border: '#d97706', text: '#fbbf24', icon: '⚠️', label: '검토 필요' },
  BLOCK: { bg: '#450a0a', border: '#dc2626', text: '#f87171', icon: '🚫', label: '배포 차단' },
};

const JUDGEMENT_STYLES = {
  TRUE_POSITIVE: { bg: '#450a0a', color: '#f87171', border: '#dc2626', label: '취약' },
  REVIEW_NEEDED: { bg: '#451a03', color: '#fbbf24', border: '#d97706', label: '확인필요' },
  FALSE_POSITIVE: { bg: '#1f2937', color: '#9ca3af', border: '#374151', label: '오탐' },
};

const CONFIDENCE_STYLES = {
  HIGH: { bg: '#14532d', color: '#4ade80' },
  MED: { bg: '#1e3a5f', color: '#60a5fa' },
  MEDIUM: { bg: '#1e3a5f', color: '#60a5fa' },
  LOW: { bg: '#374151', color: '#9ca3af' },
};

const CAT_COLORS = {
  SAST: '#3b82f6',
  SCA: '#8b5cf6',
  IAC: '#06b6d4',
  DAST: '#f59e0b',
};

function SeverityBadge({ severity }) {
  const s = (severity || 'INFO').toUpperCase();
  const style = SEVERITY_COLORS[s] || SEVERITY_COLORS.INFO;
  return (
    <span style={{
      background: style.bg,
      color: style.color,
      padding: '3px 8px',
      borderRadius: 4,
      fontSize: 11,
      fontWeight: 700,
      letterSpacing: 0.5,
    }}>
      {s}
    </span>
  );
}

function JudgementBadge({ code, label }) {
  const style = JUDGEMENT_STYLES[code] || JUDGEMENT_STYLES.REVIEW_NEEDED;
  return (
    <span style={{
      background: style.bg,
      color: style.color,
      border: `1px solid ${style.border}`,
      padding: '3px 8px',
      borderRadius: 4,
      fontSize: 11,
      fontWeight: 700,
    }}>
      {label || style.label}
    </span>
  );
}

function ConfidenceBadge({ level }) {
  const l = (level || 'LOW').toUpperCase();
  const style = CONFIDENCE_STYLES[l] || CONFIDENCE_STYLES.LOW;
  return (
    <span style={{
      background: style.bg,
      color: style.color,
      padding: '3px 8px',
      borderRadius: 4,
      fontSize: 11,
      fontWeight: 600,
    }}>
      {l}
    </span>
  );
}

function ToolResult({ result }) {
  if (!result) {
    return <span style={{ color: '#6b7280', fontSize: 12, fontStyle: 'italic' }}>해당 없음</span>;
  }
  const detected = result.status === 'detected';
  return (
    <div style={{ display: 'flex', alignItems: 'flex-start', gap: 6 }}>
      <span style={{ fontSize: 13, flexShrink: 0 }}>{detected ? '🔍' : '—'}</span>
      <span style={{
        fontSize: 12,
        color: detected ? '#e5e7eb' : '#6b7280',
        fontStyle: detected ? 'normal' : 'italic',
        fontFamily: detected ? 'monospace' : 'inherit',
        wordBreak: 'break-word',
      }}>
        {result.display_result || '탐지 안됨'}
      </span>
    </div>
  );
}

function ExpandableCell({ reason, action_text }) {
  const [open, setOpen] = useState(false);
  return (
    <div>
      <button
        onClick={() => setOpen(v => !v)}
        style={{
          background: 'none',
          border: '1px solid #374151',
          color: '#9ca3af',
          padding: '3px 8px',
          borderRadius: 4,
          fontSize: 11,
          cursor: 'pointer',
          display: 'flex',
          alignItems: 'center',
          gap: 4,
        }}
      >
        <span>{open ? '▲' : '▼'}</span>
        <span>{open ? '접기' : '근거/조치'}</span>
      </button>
      {open && (
        <div style={{
          marginTop: 8,
          background: '#111827',
          border: '1px solid #374151',
          borderRadius: 6,
          padding: 10,
          minWidth: 240,
        }}>
          {reason && (
            <div style={{ marginBottom: 8 }}>
              <div style={{ color: '#60a5fa', fontSize: 11, fontWeight: 700, marginBottom: 4 }}>📋 근거</div>
              <div style={{ color: '#d1d5db', fontSize: 12, lineHeight: 1.6 }}>{reason}</div>
            </div>
          )}
          {action_text && (
            <div>
              <div style={{ color: '#4ade80', fontSize: 11, fontWeight: 700, marginBottom: 4 }}>🔧 조치</div>
              <div style={{ color: '#d1d5db', fontSize: 12, lineHeight: 1.6 }}>{action_text}</div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function SectionTable({ section }) {
  const catColor = CAT_COLORS[section.category?.toUpperCase()] || '#6b7280';
  const hasTwoTools = !!section.tool_b_name;

  const thStyle = {
    padding: '10px 12px',
    textAlign: 'left',
    color: '#9ca3af',
    fontSize: 11,
    fontWeight: 700,
    borderBottom: '1px solid #374151',
    whiteSpace: 'nowrap',
    letterSpacing: 0.3,
  };

  const tdStyle = {
    padding: '10px 12px',
    fontSize: 13,
    borderBottom: '1px solid #1f2937',
    verticalAlign: 'top',
  };

  return (
    <div style={{
      background: '#1f2937',
      border: '1px solid #374151',
      borderRadius: 10,
      marginBottom: 24,
      overflow: 'hidden',
    }}>
      {/* Section Header */}
      <div style={{
        padding: '14px 20px',
        borderBottom: '1px solid #374151',
        display: 'flex',
        alignItems: 'center',
        gap: 12,
        background: '#161e2e',
      }}>
        <span style={{
          background: catColor,
          color: '#fff',
          padding: '3px 10px',
          borderRadius: 4,
          fontSize: 12,
          fontWeight: 800,
          letterSpacing: 1,
        }}>
          {section.category?.toUpperCase()}
        </span>
        <span style={{ color: '#fff', fontWeight: 700, fontSize: 15 }}>{section.title}</span>
        <span style={{
          marginLeft: 'auto',
          background: '#374151',
          color: '#9ca3af',
          padding: '2px 10px',
          borderRadius: 10,
          fontSize: 12,
        }}>
          {section.rows?.length || 0}건
        </span>
      </div>

      {/* Tool names header bar */}
      <div style={{
        padding: '8px 20px',
        background: '#1a2332',
        borderBottom: '1px solid #374151',
        display: 'flex',
        gap: 16,
        fontSize: 12,
        color: '#6b7280',
      }}>
        <span>
          <span style={{ color: '#9ca3af', fontWeight: 600 }}>Tool A: </span>
          <span style={{ color: '#60a5fa', fontFamily: 'monospace' }}>
            {section.tool_a_name}
          </span>
        </span>
        {hasTwoTools && (
          <span>
            <span style={{ color: '#9ca3af', fontWeight: 600 }}>Tool B: </span>
            <span style={{ color: '#a78bfa', fontFamily: 'monospace' }}>
              {section.tool_b_name}
            </span>
          </span>
        )}
      </div>

      {/* Table */}
      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ background: '#111827' }}>
              <th style={thStyle}>{section.target_label_name || '대상'}</th>
              <th style={thStyle}>심각도</th>
              <th style={thStyle}>판정</th>
              <th style={thStyle}>신뢰도</th>
              <th style={{ ...thStyle, textAlign: 'right' }}>점수</th>
              <th style={thStyle}>Tool A 결과</th>
              {hasTwoTools && <th style={thStyle}>Tool B 결과</th>}
              <th style={thStyle}>근거/조치</th>
            </tr>
          </thead>
          <tbody>
            {(section.rows || []).map((row, idx) => {
              const rowBg = idx % 2 === 0 ? '#1f2937' : '#1a2332';
              const isHighRisk = row.judgement_code === 'TRUE_POSITIVE' &&
                (row.severity === 'CRITICAL' || row.severity === 'HIGH');

              return (
                <tr key={row.row_id || idx} style={{
                  background: rowBg,
                  borderLeft: isHighRisk
                    ? `3px solid ${SEVERITY_COLORS[row.severity]?.bg || '#ea580c'}`
                    : '3px solid transparent',
                }}>
                  {/* Target */}
                  <td style={{ ...tdStyle, maxWidth: 220 }}>
                    <div style={{
                      color: '#e5e7eb',
                      fontFamily: 'monospace',
                      fontSize: 12,
                      wordBreak: 'break-all',
                      lineHeight: 1.4,
                    }}>
                      {row.target_label}
                    </div>
                  </td>

                  {/* Severity */}
                  <td style={tdStyle}>
                    <SeverityBadge severity={row.severity} />
                  </td>

                  {/* Judgement */}
                  <td style={tdStyle}>
                    <JudgementBadge code={row.judgement_code} label={row.display_label} />
                  </td>

                  {/* Confidence */}
                  <td style={tdStyle}>
                    <ConfidenceBadge level={row.confidence_level} />
                  </td>

                  {/* Score */}
                  <td style={{ ...tdStyle, textAlign: 'right' }}>
                    <span style={{
                      color: row.row_score >= 50 ? '#f87171' : row.row_score >= 20 ? '#fbbf24' : '#9ca3af',
                      fontWeight: 700,
                      fontSize: 13,
                      fontFamily: 'monospace',
                    }}>
                      {typeof row.row_score === 'number' ? row.row_score.toFixed(1) : '—'}
                    </span>
                  </td>

                  {/* Tool A */}
                  <td style={{ ...tdStyle, maxWidth: 200 }}>
                    <ToolResult result={row.tool_a} />
                  </td>

                  {/* Tool B */}
                  {hasTwoTools && (
                    <td style={{ ...tdStyle, maxWidth: 200 }}>
                      <ToolResult result={row.tool_b} />
                    </td>
                  )}

                  {/* Reason / Action */}
                  <td style={tdStyle}>
                    <ExpandableCell reason={row.reason} action_text={row.action_text} />
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default function CrossValidationPage() {
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    axios.get(`${API_BASE}/cross`)
      .then(res => {
        if (res.data) {
          setReport(res.data);
        }
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div style={{ color: 'white', padding: 60, textAlign: 'center', fontSize: 16, fontFamily: 'monospace' }}>
        <div style={{ fontSize: 24, marginBottom: 12 }}>🔍</div>
        교차 검증 결과 로딩 중...
      </div>
    );
  }

  const dr = report?.dashboard_report || report || {};
  const cards = dr.summary_cards || {};
  const sections = dr.sections || [];
  const gate = (cards.gate_decision || 'REVIEW').toUpperCase();
  const gateStyle = GATE_STYLES[gate] || GATE_STYLES.REVIEW;

  const containerStyle = {
    background: '#111827',
    minHeight: '100vh',
    color: '#fff',
    fontFamily: "'Segoe UI', system-ui, sans-serif",
    paddingBottom: 40,
  };

  return (
    <div style={containerStyle}>
      {/* Page Header */}
      <div style={{ marginBottom: 20 }}>
        <h1 style={{ fontSize: 24, fontWeight: 800, color: '#fff', margin: 0, marginBottom: 6 }}>
          교차 검증 결과
        </h1>
        <div style={{ color: '#6b7280', fontSize: 13 }}>
          다중 보안 도구 교차 검증 리포트 — 오탐 감소 및 탐지 정확도 향상
        </div>
      </div>

      {/* Gate Decision Banner */}
      <div style={{
        background: gateStyle.bg,
        border: `2px solid ${gateStyle.border}`,
        borderRadius: 10,
        padding: '18px 24px',
        marginBottom: 24,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: 12,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          <span style={{ fontSize: 28 }}>{gateStyle.icon}</span>
          <div>
            <div style={{ color: gateStyle.text, fontWeight: 800, fontSize: 18 }}>
              배포 판정: {gate} — {gateStyle.label}
            </div>
            <div style={{ color: '#9ca3af', fontSize: 13, marginTop: 2 }}>
              총점: {typeof cards.total_score === 'number' ? cards.total_score.toFixed(1) : '—'} / 100
            </div>
          </div>
        </div>
        {/* Summary mini-cards */}
        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
          {[
            { label: 'CRITICAL', count: cards.critical_count || 0, color: '#dc2626' },
            { label: 'HIGH', count: cards.high_count || 0, color: '#ea580c' },
            { label: 'MEDIUM', count: cards.medium_count || 0, color: '#d97706' },
            { label: 'LOW', count: cards.low_count || 0, color: '#65a30d' },
          ].map(c => (
            <div key={c.label} style={{
              background: '#1f2937',
              border: `1px solid ${c.color}50`,
              borderRadius: 6,
              padding: '6px 12px',
              textAlign: 'center',
              minWidth: 60,
            }}>
              <div style={{ color: c.color, fontWeight: 800, fontSize: 18 }}>{c.count}</div>
              <div style={{ color: '#6b7280', fontSize: 10, fontWeight: 600 }}>{c.label}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Score display */}
      <div style={{
        background: '#1f2937',
        border: '1px solid #374151',
        borderRadius: 8,
        padding: '12px 20px',
        marginBottom: 24,
        display: 'flex',
        alignItems: 'center',
        gap: 20,
        flexWrap: 'wrap',
      }}>
        <span style={{ color: '#9ca3af', fontSize: 14 }}>
          총점:&nbsp;
          <span style={{ color: '#fff', fontWeight: 800, fontSize: 18, fontFamily: 'monospace' }}>
            {typeof cards.total_score === 'number' ? cards.total_score.toFixed(1) : '0.0'}
          </span>
          <span style={{ color: '#6b7280', fontSize: 13 }}> / 100</span>
        </span>
        <span style={{ color: '#374151' }}>|</span>
        <span style={{ color: '#9ca3af', fontSize: 14 }}>
          배포 판정:&nbsp;
          <span style={{
            color: gateStyle.text,
            fontWeight: 800,
            fontSize: 16,
          }}>
            {gate}
          </span>
        </span>
        <span style={{ color: '#374151' }}>|</span>
        <span style={{ color: '#9ca3af', fontSize: 14 }}>
          검증 섹션:&nbsp;
          <span style={{ color: '#60a5fa', fontWeight: 700 }}>{sections.length}</span>
          <span style={{ color: '#6b7280' }}>개 카테고리</span>
        </span>
        <span style={{ color: '#374151' }}>|</span>
        <span style={{ color: '#9ca3af', fontSize: 14 }}>
          전체 항목:&nbsp;
          <span style={{ color: '#60a5fa', fontWeight: 700 }}>
            {sections.reduce((acc, s) => acc + (s.rows?.length || 0), 0)}
          </span>
          <span style={{ color: '#6b7280' }}>건</span>
        </span>
      </div>

      {/* Category navigation */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 24, flexWrap: 'wrap' }}>
        {sections.map(section => {
          const catKey = section.category?.toUpperCase();
          const catColor = CAT_COLORS[catKey] || '#6b7280';
          return (
            <a
              key={section.section_id}
              href={`#${section.section_id}`}
              style={{
                background: catColor + '20',
                color: catColor,
                border: `1px solid ${catColor}50`,
                padding: '6px 14px',
                borderRadius: 20,
                fontSize: 13,
                fontWeight: 600,
                textDecoration: 'none',
                cursor: 'pointer',
              }}
            >
              {catKey} ({section.rows?.length || 0})
            </a>
          );
        })}
      </div>

      {/* Sections */}
      {sections.map(section => (
        <div key={section.section_id} id={section.section_id}>
          <SectionTable section={section} />
        </div>
      ))}

      {sections.length === 0 && (
        <div style={{
          background: '#1f2937',
          border: '1px solid #374151',
          borderRadius: 10,
          padding: 40,
          textAlign: 'center',
          color: '#6b7280',
        }}>
          교차 검증 섹션이 없습니다.
        </div>
      )}
    </div>
  );
}
