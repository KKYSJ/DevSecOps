import React, { useState, useEffect } from 'react';
import axios from 'axios';

const API_BASE = process.env.REACT_APP_API_BASE_URL || 'http://localhost:8000/api/v1';


const GATE_STYLES = {
  ALLOW: { bg: '#14532d', color: '#4ade80', border: '#16a34a' },
  REVIEW: { bg: '#451a03', color: '#fbbf24', border: '#d97706' },
  BLOCK: { bg: '#450a0a', color: '#f87171', border: '#dc2626' },
};

const PHASE_STATUS_STYLES = {
  PASS: { bg: '#14532d', color: '#4ade80' },
  FAIL: { bg: '#450a0a', color: '#f87171' },
  REVIEW: { bg: '#451a03', color: '#fbbf24' },
  BLOCK: { bg: '#450a0a', color: '#f87171' },
  RUNNING: { bg: '#1e3a5f', color: '#60a5fa' },
  SKIPPED: { bg: '#1f2937', color: '#6b7280' },
};

const TOOL_CATEGORY_COLORS = {
  SAST: '#3b82f6',
  SCA: '#8b5cf6',
  IaC: '#06b6d4',
  DAST: '#f59e0b',
  CROSS: '#ec4899',
};

function PhaseBadge({ phase }) {
  const s = PHASE_STATUS_STYLES[phase?.status] || PHASE_STATUS_STYLES.SKIPPED;
  return (
    <div style={{ minWidth: 80 }}>
      <div style={{
        background: s.bg,
        color: s.color,
        padding: '3px 8px',
        borderRadius: 4,
        fontSize: 11,
        fontWeight: 700,
        textAlign: 'center',
        marginBottom: 4,
      }}>
        {phase?.status || '-'}
      </div>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 2 }}>
        {(phase?.tools || []).map((tool, i) => {
          const catColor = TOOL_CATEGORY_COLORS[tool.category] || '#6b7280';
          const isOk = tool.status === 'PASS' || tool.status === 'ALLOW';
          return (
            <span key={i} title={`${tool.name}: ${tool.status} (${tool.findings}건)`} style={{
              background: isOk ? '#14532d' : '#450a0a',
              color: isOk ? '#4ade80' : '#f87171',
              border: `1px solid ${catColor}30`,
              padding: '1px 5px',
              borderRadius: 3,
              fontSize: 9,
              fontWeight: 600,
              whiteSpace: 'nowrap',
            }}>
              {tool.name.replace('OWASP ', '')} {tool.findings > 0 ? `(${tool.findings})` : '✓'}
            </span>
          );
        })}
      </div>
    </div>
  );
}

function GateBadge({ gate, score }) {
  const s = GATE_STYLES[gate] || GATE_STYLES.REVIEW;
  return (
    <div style={{ textAlign: 'center' }}>
      <span style={{
        background: s.bg,
        color: s.color,
        border: `1px solid ${s.border}`,
        padding: '4px 12px',
        borderRadius: 4,
        fontSize: 12,
        fontWeight: 800,
        display: 'block',
        marginBottom: 2,
      }}>
        {gate}
      </span>
      <span style={{
        color: parseFloat(score) >= 80 ? '#4ade80' : parseFloat(score) >= 60 ? '#fbbf24' : '#f87171',
        fontSize: 11,
        fontFamily: 'monospace',
        fontWeight: 700,
      }}>
        {score?.toFixed(1)}
      </span>
    </div>
  );
}

export default function PipelinePage() {
  const [pipelines, setPipelines] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedRun, setSelectedRun] = useState(null);

  useEffect(() => {
    axios.get(`${API_BASE}/pipelines`)
      .then(res => {
        const data = Array.isArray(res.data) ? res.data : (res.data.pipelines || res.data.items || []);
        setPipelines(data);
      })
      .catch(() => setPipelines([]))
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div style={{ color: 'white', padding: 60, textAlign: 'center', fontSize: 16, fontFamily: 'monospace' }}>
        <div style={{ fontSize: 24, marginBottom: 12 }}>⚙️</div>
        파이프라인 이력 로딩 중...
      </div>
    );
  }

  const containerStyle = {
    background: '#111827',
    minHeight: '100vh',
    color: '#fff',
    fontFamily: "'Segoe UI', system-ui, sans-serif",
    paddingBottom: 40,
  };

  const sectionStyle = {
    background: '#1f2937',
    border: '1px solid #374151',
    borderRadius: 10,
    overflow: 'hidden',
    marginBottom: 20,
  };

  const thStyle = {
    padding: '10px 12px',
    textAlign: 'left',
    color: '#9ca3af',
    fontSize: 11,
    fontWeight: 700,
    borderBottom: '1px solid #374151',
    whiteSpace: 'nowrap',
    background: '#111827',
  };

  const tdStyle = {
    padding: '12px',
    borderBottom: '1px solid #1f2937',
    verticalAlign: 'top',
  };

  // Stats
  const gateStats = pipelines.reduce((acc, p) => {
    acc[p.gate] = (acc[p.gate] || 0) + 1;
    return acc;
  }, {});

  return (
    <div style={containerStyle}>
      {/* Header */}
      <div style={{ marginBottom: 20 }}>
        <h1 style={{ fontSize: 24, fontWeight: 800, color: '#fff', margin: 0, marginBottom: 6 }}>
          파이프라인 실행 이력
        </h1>
        <div style={{ color: '#6b7280', fontSize: 13 }}>
          CI/CD 보안 게이트 파이프라인 실행 기록
        </div>
      </div>

      {/* Stats */}
      <div style={{ display: 'flex', gap: 14, marginBottom: 20, flexWrap: 'wrap' }}>
        {[
          { label: '전체 실행', value: pipelines.length, color: '#60a5fa' },
          { label: 'ALLOW', value: gateStats.ALLOW || 0, color: '#4ade80' },
          { label: 'REVIEW', value: gateStats.REVIEW || 0, color: '#fbbf24' },
          { label: 'BLOCK', value: gateStats.BLOCK || 0, color: '#f87171' },
        ].map(stat => (
          <div key={stat.label} style={{
            background: '#1f2937',
            border: '1px solid #374151',
            borderRadius: 8,
            padding: '12px 20px',
            flex: 1,
            minWidth: 120,
          }}>
            <div style={{ color: '#9ca3af', fontSize: 12, marginBottom: 6 }}>{stat.label}</div>
            <div style={{ color: stat.color, fontSize: 28, fontWeight: 800 }}>{stat.value}</div>
          </div>
        ))}
        <div style={{
          background: '#1f2937',
          border: '1px solid #374151',
          borderRadius: 8,
          padding: '12px 20px',
          flex: 2,
          minWidth: 200,
        }}>
          <div style={{ color: '#9ca3af', fontSize: 12, marginBottom: 6 }}>ALLOW 비율</div>
          <div style={{ color: '#fff', fontSize: 14 }}>
            <span style={{ color: '#4ade80', fontWeight: 800, fontSize: 24 }}>
              {pipelines.length > 0 ? ((gateStats.ALLOW || 0) / pipelines.length * 100).toFixed(0) : 0}%
            </span>
            <span style={{ color: '#6b7280', fontSize: 12, marginLeft: 4 }}>({gateStats.ALLOW || 0}/{pipelines.length})</span>
          </div>
          <div style={{ background: '#374151', borderRadius: 10, height: 6, marginTop: 8, overflow: 'hidden' }}>
            <div style={{
              width: `${pipelines.length > 0 ? (gateStats.ALLOW || 0) / pipelines.length * 100 : 0}%`,
              height: '100%',
              background: '#16a34a',
              borderRadius: 10,
            }} />
          </div>
        </div>
      </div>

      {/* Pipeline Table */}
      <div style={sectionStyle}>
        <div style={{
          padding: '12px 20px',
          borderBottom: '1px solid #374151',
          background: '#161e2e',
          display: 'flex',
          alignItems: 'center',
          gap: 8,
        }}>
          <span style={{ color: '#e5e7eb', fontWeight: 700, fontSize: 14 }}>파이프라인 실행 목록</span>
          <span style={{
            background: '#374151',
            color: '#9ca3af',
            padding: '2px 8px',
            borderRadius: 10,
            fontSize: 12,
            marginLeft: 'auto',
          }}>
            총 {pipelines.length}회
          </span>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr>
                <th style={thStyle}>Run #</th>
                <th style={thStyle}>브랜치 / 커밋</th>
                <th style={thStyle}>Phase 1 (SAST/SCA)</th>
                <th style={thStyle}>Phase 2 (IaC/DAST)</th>
                <th style={thStyle}>Phase 3 (교차검증)</th>
                <th style={{ ...thStyle, textAlign: 'center' }}>게이트 / 점수</th>
                <th style={thStyle}>실행 시각</th>
                <th style={thStyle}>소요 시간</th>
              </tr>
            </thead>
            <tbody>
              {pipelines.map((run, idx) => {
                const rowBg = idx % 2 === 0 ? '#1f2937' : '#1a2332';
                const isSelected = selectedRun === run.id;
                const gateS = GATE_STYLES[run.gate] || GATE_STYLES.REVIEW;
                return (
                  <React.Fragment key={run.id}>
                    <tr
                      onClick={() => setSelectedRun(isSelected ? null : run.id)}
                      style={{
                        background: isSelected ? '#1e3a5f' : rowBg,
                        cursor: 'pointer',
                        borderLeft: `3px solid ${gateS.border}`,
                      }}
                    >
                      {/* Run # */}
                      <td style={{ ...tdStyle, whiteSpace: 'nowrap' }}>
                        <div style={{ color: '#60a5fa', fontFamily: 'monospace', fontSize: 14, fontWeight: 700 }}>
                          #{run.run_number}
                        </div>
                        <div style={{ color: '#6b7280', fontSize: 10, fontFamily: 'monospace' }}>{run.id}</div>
                      </td>

                      {/* Branch / Commit */}
                      <td style={{ ...tdStyle, maxWidth: 200 }}>
                        <div style={{ color: '#a78bfa', fontFamily: 'monospace', fontSize: 12, marginBottom: 2 }}>
                          🌿 {run.branch}
                        </div>
                        <div style={{ color: '#9ca3af', fontFamily: 'monospace', fontSize: 11 }}>
                          {run.commit} · {run.author}
                        </div>
                        <div style={{ color: '#6b7280', fontSize: 11, marginTop: 2, maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {run.commit_msg}
                        </div>
                      </td>

                      {/* Phase 1 */}
                      <td style={tdStyle}>
                        <PhaseBadge phase={run.phase1} />
                      </td>

                      {/* Phase 2 */}
                      <td style={tdStyle}>
                        <PhaseBadge phase={run.phase2} />
                      </td>

                      {/* Phase 3 */}
                      <td style={tdStyle}>
                        <PhaseBadge phase={run.phase3} />
                      </td>

                      {/* Gate */}
                      <td style={{ ...tdStyle, textAlign: 'center' }}>
                        <GateBadge gate={run.gate} score={run.score} />
                      </td>

                      {/* Time */}
                      <td style={{ ...tdStyle, whiteSpace: 'nowrap' }}>
                        <div style={{ color: '#9ca3af', fontSize: 12 }}>{run.triggered_at}</div>
                      </td>

                      {/* Duration */}
                      <td style={{ ...tdStyle, whiteSpace: 'nowrap' }}>
                        <span style={{ color: '#60a5fa', fontFamily: 'monospace', fontSize: 12 }}>
                          ⏱ {run.duration}
                        </span>
                      </td>
                    </tr>

                    {/* Expanded Detail Row */}
                    {isSelected && (
                      <tr>
                        <td colSpan={8} style={{ background: '#1e3a5f', padding: 0, borderBottom: '1px solid #374151' }}>
                          <div style={{ padding: '16px 24px' }}>
                            <div style={{ color: '#93c5fd', fontWeight: 700, fontSize: 13, marginBottom: 12 }}>
                              실행 상세 정보: Run #{run.run_number}
                            </div>
                            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
                              {[run.phase1, run.phase2, run.phase3].map((phase, pi) => (
                                <div key={pi} style={{
                                  background: '#111827',
                                  border: '1px solid #374151',
                                  borderRadius: 6,
                                  padding: 12,
                                }}>
                                  <div style={{ color: '#9ca3af', fontSize: 11, fontWeight: 700, marginBottom: 8 }}>
                                    Phase {pi + 1}
                                  </div>
                                  {(phase?.tools || []).map((tool, ti) => {
                                    const catColor = TOOL_CATEGORY_COLORS[tool.category] || '#6b7280';
                                    const isOk = tool.status === 'PASS' || tool.status === 'ALLOW';
                                    return (
                                      <div key={ti} style={{
                                        display: 'flex',
                                        alignItems: 'center',
                                        justifyContent: 'space-between',
                                        padding: '4px 0',
                                        borderBottom: ti < phase.tools.length - 1 ? '1px solid #1f2937' : 'none',
                                      }}>
                                        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                                          <span style={{
                                            background: catColor + '20',
                                            color: catColor,
                                            padding: '1px 5px',
                                            borderRadius: 3,
                                            fontSize: 9,
                                            fontWeight: 700,
                                          }}>
                                            {tool.category}
                                          </span>
                                          <span style={{ color: '#e5e7eb', fontSize: 12 }}>{tool.name}</span>
                                        </div>
                                        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                                          <span style={{ color: '#6b7280', fontSize: 11 }}>{tool.findings}건</span>
                                          <span style={{
                                            color: isOk ? '#4ade80' : '#f87171',
                                            fontSize: 12,
                                            fontWeight: 700,
                                          }}>
                                            {isOk ? '✓' : '✗'}
                                          </span>
                                        </div>
                                      </div>
                                    );
                                  })}
                                </div>
                              ))}
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Legend */}
      <div style={{
        background: '#1f2937',
        border: '1px solid #374151',
        borderRadius: 8,
        padding: '12px 20px',
        display: 'flex',
        gap: 20,
        flexWrap: 'wrap',
        alignItems: 'center',
      }}>
        <span style={{ color: '#6b7280', fontSize: 12, fontWeight: 600 }}>게이트 판정:</span>
        {[
          { gate: 'ALLOW', desc: '배포 허용' },
          { gate: 'REVIEW', desc: '검토 필요' },
          { gate: 'BLOCK', desc: '배포 차단' },
        ].map(({ gate, desc }) => {
          const s = GATE_STYLES[gate];
          return (
            <div key={gate} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <span style={{
                background: s.bg,
                color: s.color,
                border: `1px solid ${s.border}`,
                padding: '2px 8px',
                borderRadius: 4,
                fontSize: 11,
                fontWeight: 700,
              }}>
                {gate}
              </span>
              <span style={{ color: '#9ca3af', fontSize: 12 }}>{desc}</span>
            </div>
          );
        })}
        <span style={{ color: '#6b7280', fontSize: 11, marginLeft: 'auto' }}>
          행을 클릭하면 상세 정보를 볼 수 있습니다.
        </span>
      </div>
    </div>
  );
}
