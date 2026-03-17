import React, { useState, useEffect } from 'react';
import axios from 'axios';

const API_BASE = process.env.REACT_APP_API_BASE_URL || 'http://localhost:8000/api/v1';


// 도구별 아이콘 (UI 전용, 데모 데이터 아님)
const TOOL_ICONS = {
  sonarqube: '🔍',
  semgrep: '🧩',
  trivy: '📦',
  depcheck: '🔗',
  tfsec: '🏗️',
  checkov: '✅',
  zap: '🌐',
};

const CATEGORY_COLORS = {
  SAST: '#3b82f6',
  SCA: '#8b5cf6',
  IaC: '#06b6d4',
  DAST: '#f59e0b',
};

const CATEGORY_LABELS = {
  SAST: '정적 분석',
  SCA: '구성 요소 분석',
  IaC: '인프라 코드',
  DAST: '동적 분석',
};

const SEVERITY_COLORS = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#d97706',
  low: '#65a30d',
};

function ToolCard({ tool }) {
  const [expanded, setExpanded] = useState(false);
  const catColor = CATEGORY_COLORS[tool.category] || '#6b7280';
  const totalFindings = tool.findings?.total || 0;
  const hasFindings = totalFindings > 0;

  return (
    <div style={{
      background: '#1f2937',
      border: `1px solid ${expanded ? catColor + '60' : '#374151'}`,
      borderTop: `3px solid ${catColor}`,
      borderRadius: 10,
      overflow: 'hidden',
      transition: 'border-color 0.2s',
    }}>
      {/* Card Header */}
      <div style={{ padding: '16px 18px' }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12, marginBottom: 10 }}>
          <span style={{ fontSize: 24, lineHeight: 1 }}>{tool.icon}</span>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
              <span style={{ color: '#fff', fontWeight: 800, fontSize: 16 }}>{tool.name}</span>
              <span style={{
                background: catColor + '20',
                color: catColor,
                border: `1px solid ${catColor}40`,
                padding: '2px 8px',
                borderRadius: 4,
                fontSize: 10,
                fontWeight: 700,
                letterSpacing: 0.5,
              }}>
                {tool.category}
              </span>
              <span style={{ color: '#6b7280', fontSize: 11, marginLeft: 'auto' }}>
                v{tool.version}
              </span>
            </div>
            <div style={{ color: '#6b7280', fontSize: 11, marginTop: 2 }}>
              {CATEGORY_LABELS[tool.category] || tool.category}
            </div>
          </div>
          {/* Status indicator */}
          <span style={{
            background: tool.status === 'ACTIVE' ? '#14532d' : '#374151',
            color: tool.status === 'ACTIVE' ? '#4ade80' : '#9ca3af',
            padding: '3px 8px',
            borderRadius: 10,
            fontSize: 10,
            fontWeight: 600,
            whiteSpace: 'nowrap',
          }}>
            ● {tool.status === 'ACTIVE' ? '활성' : '비활성'}
          </span>
        </div>

        {/* Description */}
        <p style={{
          color: '#9ca3af',
          fontSize: 12,
          lineHeight: 1.6,
          margin: '0 0 12px 0',
        }}>
          {tool.description}
        </p>

        {/* Findings Summary */}
        <div style={{
          background: '#111827',
          borderRadius: 6,
          padding: '10px 12px',
          marginBottom: 10,
        }}>
          <div style={{ color: '#9ca3af', fontSize: 11, fontWeight: 600, marginBottom: 6 }}>
            탐지 결과 — 최신 스캔
          </div>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            {[
              { label: 'CRITICAL', key: 'critical', color: SEVERITY_COLORS.critical },
              { label: 'HIGH', key: 'high', color: SEVERITY_COLORS.high },
              { label: 'MEDIUM', key: 'medium', color: SEVERITY_COLORS.medium },
              { label: 'LOW', key: 'low', color: SEVERITY_COLORS.low },
            ].map(s => {
              const count = tool.findings?.[s.key] || 0;
              return (
                <div key={s.key} style={{ textAlign: 'center' }}>
                  <div style={{
                    color: count > 0 ? s.color : '#374151',
                    fontWeight: 800,
                    fontSize: 16,
                  }}>
                    {count}
                  </div>
                  <div style={{ color: '#6b7280', fontSize: 9, fontWeight: 600 }}>{s.label}</div>
                </div>
              );
            })}
            <div style={{
              marginLeft: 'auto',
              textAlign: 'right',
              borderLeft: '1px solid #374151',
              paddingLeft: 12,
            }}>
              <div style={{
                color: hasFindings ? '#f87171' : '#4ade80',
                fontWeight: 800,
                fontSize: 20,
              }}>
                {totalFindings}
              </div>
              <div style={{ color: '#6b7280', fontSize: 9, fontWeight: 600 }}>전체</div>
            </div>
          </div>
        </div>

        {/* Meta info */}
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', fontSize: 11, color: '#6b7280' }}>
          <span>⏱ {tool.scanDuration}</span>
          <span>🕐 {tool.lastScan}</span>
          {tool.rulesEnabled && <span>📋 {tool.rulesEnabled}개 규칙</span>}
        </div>
      </div>

      {/* Expand toggle */}
      <button
        onClick={() => setExpanded(v => !v)}
        style={{
          width: '100%',
          background: '#111827',
          border: 'none',
          borderTop: '1px solid #374151',
          color: '#6b7280',
          padding: '8px 18px',
          cursor: 'pointer',
          fontSize: 12,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}
      >
        <span>엔드포인트 및 상세 정보</span>
        <span>{expanded ? '▲' : '▼'}</span>
      </button>

      {expanded && (
        <div style={{
          background: '#111827',
          padding: '12px 18px',
          borderTop: '1px solid #1f2937',
        }}>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <span style={{ color: '#6b7280', fontSize: 12 }}>엔드포인트:</span>
            <code style={{
              color: '#60a5fa',
              fontFamily: 'monospace',
              fontSize: 12,
              background: '#1f2937',
              padding: '2px 8px',
              borderRadius: 4,
            }}>
              {tool.endpoint}
            </code>
          </div>
          <div style={{ marginTop: 8, color: '#6b7280', fontSize: 11 }}>
            통합 방식: CI/CD 파이프라인 Phase {
              tool.category === 'SAST' || tool.category === 'SCA' ? '1' :
              tool.category === 'IaC' || tool.category === 'DAST' ? '2' : '3'
            } 자동 실행
          </div>
        </div>
      )}
    </div>
  );
}

export default function ToolsPage() {
  const [tools, setTools] = useState([]);
  const [loading, setLoading] = useState(true);
  const [categoryFilter, setCategoryFilter] = useState('ALL');

  useEffect(() => {
    axios.get(`${API_BASE}/tools`)
      .then(res => {
        const data = Array.isArray(res.data) ? res.data : (res.data.tools || res.data.items || []);
        const enriched = data.map(t => ({
          ...t,
          id: t.name,
          icon: TOOL_ICONS[t.name] || '🔧',
          status: (t.status || '').toUpperCase(),
          endpoint: t.doc_url || t.endpoint || '-',
          findings: { critical: 0, high: 0, medium: 0, low: 0, total: 0 },
        }));
        setTools(enriched);
      })
      .catch(() => setTools([]))
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div style={{ color: 'white', padding: 60, textAlign: 'center', fontSize: 16, fontFamily: 'monospace' }}>
        <div style={{ fontSize: 24, marginBottom: 12 }}>🛠️</div>
        보안 도구 현황 로딩 중...
      </div>
    );
  }

  const filteredTools = categoryFilter === 'ALL'
    ? tools
    : tools.filter(t => t.category === categoryFilter);

  const categories = Array.from(new Set(tools.map(t => t.category)));

  const totalFindings = tools.reduce((acc, t) => acc + (t.findings?.total || 0), 0);
  const activeTools = tools.filter(t => t.status === 'ACTIVE').length;

  const containerStyle = {
    background: '#111827',
    minHeight: '100vh',
    color: '#fff',
    fontFamily: "'Segoe UI', system-ui, sans-serif",
    paddingBottom: 40,
  };

  return (
    <div style={containerStyle}>
      {/* Header */}
      <div style={{ marginBottom: 20 }}>
        <h1 style={{ fontSize: 24, fontWeight: 800, color: '#fff', margin: 0, marginBottom: 6 }}>
          통합 보안 도구
        </h1>
        <div style={{ color: '#6b7280', fontSize: 13 }}>
          SecureFlow 파이프라인에 통합된 보안 스캔 도구 현황
        </div>
      </div>

      {/* Summary */}
      <div style={{ display: 'flex', gap: 14, marginBottom: 20, flexWrap: 'wrap' }}>
        {[
          { label: '등록 도구', value: tools.length, color: '#60a5fa' },
          { label: '활성 도구', value: activeTools, color: '#4ade80' },
          { label: '총 탐지 건수', value: totalFindings, color: '#f87171' },
          { label: '커버리지', value: '4개 카테고리', color: '#fbbf24' },
        ].map(s => (
          <div key={s.label} style={{
            background: '#1f2937',
            border: `1px solid #374151`,
            borderRadius: 8,
            padding: '12px 20px',
            flex: 1,
            minWidth: 120,
          }}>
            <div style={{ color: '#9ca3af', fontSize: 12, marginBottom: 4 }}>{s.label}</div>
            <div style={{ color: s.color, fontSize: 22, fontWeight: 800 }}>{s.value}</div>
          </div>
        ))}
      </div>

      {/* Pipeline Flow Diagram */}
      <div style={{
        background: '#1f2937',
        border: '1px solid #374151',
        borderRadius: 10,
        padding: '16px 20px',
        marginBottom: 20,
      }}>
        <div style={{ color: '#9ca3af', fontSize: 12, fontWeight: 600, marginBottom: 12 }}>
          파이프라인 단계별 도구 배치
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          {/* Phase 1 */}
          <div style={{
            background: '#111827',
            border: '1px solid #3b82f640',
            borderRadius: 8,
            padding: '10px 14px',
            flex: 1,
            minWidth: 160,
          }}>
            <div style={{ color: '#3b82f6', fontSize: 11, fontWeight: 700, marginBottom: 6 }}>Phase 1</div>
            <div style={{ color: '#9ca3af', fontSize: 12 }}>SAST: SonarQube, Semgrep</div>
            <div style={{ color: '#9ca3af', fontSize: 12 }}>SCA: Trivy, Dependency-Check</div>
          </div>
          <div style={{ color: '#374151', fontSize: 20 }}>→</div>
          {/* Phase 2 */}
          <div style={{
            background: '#111827',
            border: '1px solid #06b6d440',
            borderRadius: 8,
            padding: '10px 14px',
            flex: 1,
            minWidth: 160,
          }}>
            <div style={{ color: '#06b6d4', fontSize: 11, fontWeight: 700, marginBottom: 6 }}>Phase 2</div>
            <div style={{ color: '#9ca3af', fontSize: 12 }}>IaC: tfsec, Checkov</div>
            <div style={{ color: '#9ca3af', fontSize: 12 }}>DAST: OWASP ZAP</div>
          </div>
          <div style={{ color: '#374151', fontSize: 20 }}>→</div>
          {/* Phase 3 */}
          <div style={{
            background: '#111827',
            border: '1px solid #ec489940',
            borderRadius: 8,
            padding: '10px 14px',
            flex: 1,
            minWidth: 160,
          }}>
            <div style={{ color: '#ec4899', fontSize: 11, fontWeight: 700, marginBottom: 6 }}>Phase 3</div>
            <div style={{ color: '#9ca3af', fontSize: 12 }}>교차 검증 엔진</div>
            <div style={{ color: '#9ca3af', fontSize: 12 }}>게이트 판정 (ALLOW/REVIEW/BLOCK)</div>
          </div>
        </div>
      </div>

      {/* Category Filter */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 20, flexWrap: 'wrap' }}>
        {['ALL', ...categories].map(cat => {
          const catColor = CATEGORY_COLORS[cat] || '#9ca3af';
          const isActive = categoryFilter === cat;
          const count = cat === 'ALL' ? tools.length : tools.filter(t => t.category === cat).length;
          return (
            <button
              key={cat}
              onClick={() => setCategoryFilter(cat)}
              style={{
                background: isActive ? (cat === 'ALL' ? '#374151' : catColor + '20') : '#1f2937',
                color: isActive ? (cat === 'ALL' ? '#fff' : catColor) : '#9ca3af',
                border: `1px solid ${isActive ? (cat === 'ALL' ? '#6b7280' : catColor + '60') : '#374151'}`,
                borderRadius: 6,
                padding: '6px 14px',
                fontSize: 12,
                fontWeight: 600,
                cursor: 'pointer',
              }}
            >
              {cat === 'ALL' ? '전체' : cat}
              <span style={{
                marginLeft: 6,
                background: 'rgba(255,255,255,0.1)',
                borderRadius: 8,
                padding: '1px 5px',
                fontSize: 11,
              }}>
                {count}
              </span>
            </button>
          );
        })}
      </div>

      {/* Tool Cards Grid */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fill, minmax(340px, 1fr))',
        gap: 18,
      }}>
        {filteredTools.map(tool => (
          <ToolCard key={tool.id} tool={tool} />
        ))}
      </div>

      {filteredTools.length === 0 && (
        <div style={{
          background: '#1f2937',
          border: '1px solid #374151',
          borderRadius: 10,
          padding: 40,
          textAlign: 'center',
          color: '#6b7280',
        }}>
          해당 카테고리의 도구가 없습니다.
        </div>
      )}
    </div>
  );
}
