import React, { useState, useEffect } from 'react';
import axios from 'axios';
import {
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend
} from 'recharts';
import SeverityChart from '../components/dashboard/SeverityChart';

const API_BASE = process.env.REACT_APP_API_BASE_URL || 'http://localhost:8000/api/v1';

const EMPTY_SUMMARY = { critical: 0, high: 0, medium: 0, low: 0, gateDecision: 'ALLOW', totalScore: 0 };

const GATE_COLORS = {
  ALLOW: { bg: '#14532d', border: '#16a34a', text: '#4ade80', label: '배포 허용' },
  REVIEW: { bg: '#451a03', border: '#d97706', text: '#fbbf24', label: '검토 필요' },
  BLOCK: { bg: '#450a0a', border: '#dc2626', text: '#f87171', label: '배포 차단' },
};

const SEVERITY_COLORS = {
  CRITICAL: '#dc2626',
  HIGH: '#ea580c',
  MEDIUM: '#d97706',
  LOW: '#65a30d',
};

function StatCard({ label, count, color }) {
  return (
    <div style={{
      background: '#1f2937',
      border: `1px solid ${color}40`,
      borderLeft: `4px solid ${color}`,
      borderRadius: 8,
      padding: '16px 20px',
      flex: 1,
      minWidth: 130,
    }}>
      <div style={{ color: '#9ca3af', fontSize: 12, marginBottom: 8, fontWeight: 600, letterSpacing: 0.5 }}>
        {label}
      </div>
      <div style={{ color, fontSize: 36, fontWeight: 800, lineHeight: 1 }}>
        {count}
      </div>
      <div style={{ color: '#4b5563', fontSize: 11, marginTop: 4 }}>건 탐지</div>
    </div>
  );
}

const CustomPieTooltip = ({ active, payload }) => {
  if (active && payload && payload.length) {
    return (
      <div style={{
        background: '#1f2937', border: '1px solid #374151',
        padding: '8px 12px', borderRadius: 6, color: '#fff', fontSize: 13,
      }}>
        <div style={{ fontWeight: 700, color: payload[0].payload.fill }}>{payload[0].name}</div>
        <div>{payload[0].value}건</div>
      </div>
    );
  }
  return null;
};

export default function OverviewPage() {
  const [summary, setSummary] = useState(null);
  const [toolPie, setToolPie] = useState([]);
  const [recentScans, setRecentScans] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let vulnSummary = null;
    let crossData = null;

    const fetchVulns = axios.get(`${API_BASE}/vulns`)
      .then(res => {
        const vulns = Array.isArray(res.data) ? res.data : (res.data.items || []);
        const counts = { critical: 0, high: 0, medium: 0, low: 0 };
        vulns.forEach(v => {
          const s = (v.severity || '').toUpperCase();
          if (counts[s.toLowerCase()] !== undefined) counts[s.toLowerCase()]++;
        });

        const pieMap = {};
        vulns.forEach(v => {
          const cat = (v.category || 'OTHER').toUpperCase();
          pieMap[cat] = (pieMap[cat] || 0) + 1;
        });

        const CAT_COLORS = { SAST: '#3b82f6', SCA: '#8b5cf6', IAC: '#06b6d4', DAST: '#f59e0b' };
        const pieArr = Object.entries(pieMap).map(([name, value]) => ({
          name, value, fill: CAT_COLORS[name] || '#6b7280',
        }));

        vulnSummary = counts;
        if (pieArr.length > 0) setToolPie(pieArr);
      })
      .catch(() => {});

    const fetchCross = axios.get(`${API_BASE}/cross`)
      .then(res => {
        const data = res.data;
        if (data && data.total_score !== undefined) {
          const summary = data.summary || {};
          const sev = summary.severity_counts || {};
          crossData = {
            critical: sev.CRITICAL || 0,
            high: sev.HIGH || 0,
            medium: sev.MEDIUM || 0,
            low: sev.LOW || 0,
            gateDecision: data.gate_decision || 'ALLOW',
            totalScore: data.total_score || 0,
          };
        }
      })
      .catch(() => {});

    const fetchScans = axios.get(`${API_BASE}/scans?limit=5`)
      .then(res => {
        const scans = Array.isArray(res.data) ? res.data : (res.data.scans || res.data.items || []);
        setRecentScans(scans);
      })
      .catch(() => {});

    Promise.allSettled([fetchVulns, fetchCross, fetchScans]).then(() => {
      const finalSummary = crossData || vulnSummary || null;
      setSummary(finalSummary);
      setLoading(false);
    });
  }, []);

  if (loading) {
    return (
      <div style={{ color: 'white', padding: 60, textAlign: 'center', fontSize: 16, fontFamily: 'monospace' }}>
        <div style={{ marginBottom: 12, fontSize: 24 }}>⚡</div>
        로딩 중...
      </div>
    );
  }

  const s = summary || EMPTY_SUMMARY;
  const gate = s.gateDecision || 'REVIEW';
  const gateStyle = GATE_COLORS[gate] || GATE_COLORS.REVIEW;

  const barData = [
    { name: 'CRITICAL', count: s.critical || 0, fill: SEVERITY_COLORS.CRITICAL },
    { name: 'HIGH', count: s.high || 0, fill: SEVERITY_COLORS.HIGH },
    { name: 'MEDIUM', count: s.medium || 0, fill: SEVERITY_COLORS.MEDIUM },
    { name: 'LOW', count: s.low || 0, fill: SEVERITY_COLORS.LOW },
  ];

  const containerStyle = {
    background: '#111827',
    minHeight: '100vh',
    color: '#fff',
    fontFamily: "'Segoe UI', system-ui, sans-serif",
    padding: '0 0 40px 0',
  };

  const sectionStyle = {
    background: '#1f2937',
    border: '1px solid #374151',
    borderRadius: 10,
    padding: 20,
    marginBottom: 20,
  };

  const sectionTitleStyle = {
    color: '#e5e7eb',
    fontSize: 15,
    fontWeight: 700,
    marginBottom: 16,
    paddingBottom: 10,
    borderBottom: '1px solid #374151',
  };

  return (
    <div style={containerStyle}>
      {/* Header */}
      <div style={{ marginBottom: 24 }}>
        <h1 style={{ fontSize: 24, fontWeight: 800, color: '#fff', margin: 0, marginBottom: 6 }}>
          SecureFlow 보안 대시보드
        </h1>
        <div style={{ color: '#6b7280', fontSize: 13 }}>
          통합 DevSecOps 보안 현황 — {new Date().toLocaleDateString('ko-KR', { year: 'numeric', month: 'long', day: 'numeric' })}
        </div>
      </div>

      {/* Gate Decision Banner */}
      <div style={{
        background: gateStyle.bg,
        border: `1px solid ${gateStyle.border}`,
        borderRadius: 8,
        padding: '14px 20px',
        marginBottom: 20,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <span style={{ fontSize: 20 }}>
            {gate === 'ALLOW' ? '✅' : gate === 'BLOCK' ? '🚫' : '⚠️'}
          </span>
          <div>
            <div style={{ color: gateStyle.text, fontWeight: 700, fontSize: 16 }}>
              배포 게이트: {gate} — {gateStyle.label}
            </div>
            <div style={{ color: '#9ca3af', fontSize: 12, marginTop: 2 }}>
              총점 {s.totalScore?.toFixed(1) || '0.0'} / 100 · 마지막 파이프라인 실행 결과
            </div>
          </div>
        </div>
        <div style={{
          background: gateStyle.border,
          color: '#fff',
          padding: '6px 16px',
          borderRadius: 20,
          fontWeight: 800,
          fontSize: 14,
          letterSpacing: 1,
        }}>
          {gate}
        </div>
      </div>

      {/* Severity Summary Cards */}
      <div style={{ display: 'flex', gap: 16, marginBottom: 20, flexWrap: 'wrap' }}>
        <StatCard label="CRITICAL" count={s.critical || 0} color={SEVERITY_COLORS.CRITICAL} />
        <StatCard label="HIGH" count={s.high || 0} color={SEVERITY_COLORS.HIGH} />
        <StatCard label="MEDIUM" count={s.medium || 0} color={SEVERITY_COLORS.MEDIUM} />
        <StatCard label="LOW" count={s.low || 0} color={SEVERITY_COLORS.LOW} />
        <div style={{
          background: '#1f2937',
          border: '1px solid #374151',
          borderRadius: 8,
          padding: '16px 20px',
          flex: 1,
          minWidth: 130,
        }}>
          <div style={{ color: '#9ca3af', fontSize: 12, marginBottom: 8, fontWeight: 600 }}>전체 취약점</div>
          <div style={{ color: '#fff', fontSize: 36, fontWeight: 800, lineHeight: 1 }}>
            {(s.critical || 0) + (s.high || 0) + (s.medium || 0) + (s.low || 0)}
          </div>
          <div style={{ color: '#4b5563', fontSize: 11, marginTop: 4 }}>건 탐지</div>
        </div>
      </div>

      {/* Charts Row */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20, marginBottom: 20 }}>
        {/* Bar Chart */}
        <div style={sectionStyle}>
          <div style={sectionTitleStyle}>심각도별 취약점 분포</div>
          <SeverityChart data={barData} />
        </div>

        {/* Pie Chart */}
        <div style={sectionStyle}>
          <div style={sectionTitleStyle}>도구 카테고리별 발견 현황</div>
          <ResponsiveContainer width="100%" height={250}>
            <PieChart>
              <Pie
                data={toolPie}
                cx="50%"
                cy="45%"
                innerRadius={55}
                outerRadius={90}
                paddingAngle={3}
                dataKey="value"
              >
                {toolPie.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.fill} />
                ))}
              </Pie>
              <Tooltip content={<CustomPieTooltip />} />
              <Legend
                formatter={(value) => (
                  <span style={{ color: '#9ca3af', fontSize: 12 }}>{value}</span>
                )}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Pipeline Status */}
      <div style={{ ...sectionStyle, marginBottom: 20 }}>
        <div style={sectionTitleStyle}>최근 파이프라인 상태</div>
        <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
          {[
            { phase: 'Phase 1', label: 'SAST / SCA', status: 'PASS', tools: 'SonarQube, Semgrep, Trivy' },
            { phase: 'Phase 2', label: 'IaC / DAST', status: 'PASS', tools: 'tfsec, Checkov, OWASP ZAP' },
            { phase: 'Phase 3', label: '교차 검증', status: 'REVIEW', tools: '교차검증 엔진' },
          ].map(p => {
            const statusColor = p.status === 'PASS' ? '#16a34a' : p.status === 'FAIL' ? '#dc2626' : '#d97706';
            const statusBg = p.status === 'PASS' ? '#14532d' : p.status === 'FAIL' ? '#450a0a' : '#451a03';
            return (
              <div key={p.phase} style={{
                background: '#111827',
                border: '1px solid #374151',
                borderRadius: 8,
                padding: '12px 16px',
                flex: 1,
                minWidth: 180,
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                  <span style={{ color: '#9ca3af', fontSize: 12, fontWeight: 600 }}>{p.phase}</span>
                  <span style={{
                    background: statusBg,
                    color: statusColor,
                    padding: '2px 8px',
                    borderRadius: 4,
                    fontSize: 11,
                    fontWeight: 700,
                  }}>{p.status}</span>
                </div>
                <div style={{ color: '#fff', fontSize: 13, fontWeight: 600, marginBottom: 4 }}>{p.label}</div>
                <div style={{ color: '#6b7280', fontSize: 11 }}>{p.tools}</div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Recent Scan History */}
      <div style={sectionStyle}>
        <div style={sectionTitleStyle}>최근 스캔 이력</div>
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr>
                {['스캔 ID', '도구', '카테고리', '브랜치', '발견 수', '상태', '실행 시각'].map(h => (
                  <th key={h} style={{
                    padding: '8px 12px',
                    textAlign: 'left',
                    color: '#9ca3af',
                    fontSize: 12,
                    fontWeight: 600,
                    borderBottom: '1px solid #374151',
                  }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {recentScans.length === 0 ? (
                <tr>
                  <td colSpan={7} style={{ padding: '32px 12px', textAlign: 'center', color: '#4b5563', fontSize: 13 }}>
                    스캔 이력이 없습니다. CI 파이프라인을 실행하면 결과가 표시됩니다.
                  </td>
                </tr>
              ) : recentScans.map((scan, idx) => {
                const CAT_COLORS = { SAST: '#3b82f6', SCA: '#8b5cf6', IaC: '#06b6d4', DAST: '#f59e0b' };
                const catColor = CAT_COLORS[scan.category] || '#6b7280';
                return (
                  <tr key={scan.id} style={{ background: idx % 2 === 0 ? '#111827' : '#1a2332' }}>
                    <td style={{ padding: '10px 12px', color: '#60a5fa', fontFamily: 'monospace', fontSize: 12 }}>
                      {scan.id}
                    </td>
                    <td style={{ padding: '10px 12px', color: '#fff', fontSize: 13 }}>{scan.tool}</td>
                    <td style={{ padding: '10px 12px' }}>
                      <span style={{
                        background: catColor + '30',
                        color: catColor,
                        padding: '2px 8px',
                        borderRadius: 4,
                        fontSize: 11,
                        fontWeight: 600,
                      }}>{scan.category}</span>
                    </td>
                    <td style={{ padding: '10px 12px', color: '#9ca3af', fontFamily: 'monospace', fontSize: 12 }}>
                      {scan.branch}
                    </td>
                    <td style={{ padding: '10px 12px', color: scan.findings > 0 ? '#f87171' : '#4ade80', fontWeight: 700, fontSize: 13 }}>
                      {scan.findings}
                    </td>
                    <td style={{ padding: '10px 12px' }}>
                      <span style={{
                        background: '#14532d',
                        color: '#4ade80',
                        padding: '2px 8px',
                        borderRadius: 4,
                        fontSize: 11,
                        fontWeight: 600,
                      }}>{scan.status}</span>
                    </td>
                    <td style={{ padding: '10px 12px', color: '#6b7280', fontSize: 12 }}>{scan.time}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
