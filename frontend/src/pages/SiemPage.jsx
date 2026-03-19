<<<<<<< HEAD
import React, { useState, useEffect } from "react";
import api from "../services/api";
=======
﻿import React, { useState, useEffect } from 'react';
import axios from 'axios';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell,
  LineChart, Line, Legend
} from 'recharts';

const API_BASE = process.env.REACT_APP_API_BASE_URL || 'http://localhost:8000/api/v1';


const SEVERITY_COLORS = {
  CRITICAL: { bg: '#dc2626', color: '#fff' },
  HIGH: { bg: '#ea580c', color: '#fff' },
  MEDIUM: { bg: '#d97706', color: '#fff' },
  LOW: { bg: '#65a30d', color: '#fff' },
  INFO: { bg: '#6b7280', color: '#fff' },
};

const STATUS_STYLES = {
  ACTIVE: { bg: '#450a0a', color: '#f87171', label: '활성' },
  RESOLVED: { bg: '#14532d', color: '#4ade80', label: '해결됨' },
  REVIEWED: { bg: '#1e3a5f', color: '#60a5fa', label: '검토완료' },
};

const SOURCE_COLORS = {
  GuardDuty: '#8b5cf6',
  CloudWatch: '#f59e0b',
  CloudTrail: '#06b6d4',
};

function SeverityBadge({ severity }) {
  const s = SEVERITY_COLORS[(severity || '').toUpperCase()] || SEVERITY_COLORS.INFO;
  return (
    <span style={{
      background: s.bg, color: s.color,
      padding: '2px 8px', borderRadius: 4,
      fontSize: 11, fontWeight: 700,
    }}>
      {(severity || 'INFO').toUpperCase()}
    </span>
  );
}

function StatusBadge({ status }) {
  const s = STATUS_STYLES[status] || STATUS_STYLES.REVIEWED;
  return (
    <span style={{
      background: s.bg, color: s.color,
      padding: '2px 8px', borderRadius: 4,
      fontSize: 11, fontWeight: 600,
    }}>
      {s.label}
    </span>
  );
}

const CustomTooltip = ({ active, payload, label }) => {
  if (active && payload && payload.length) {
    return (
      <div style={{
        background: '#1f2937', border: '1px solid #374151',
        padding: '8px 12px', borderRadius: 6, color: '#fff', fontSize: 12,
      }}>
        <div style={{ fontWeight: 700, marginBottom: 4 }}>{label}</div>
        {payload.map(p => (
          <div key={p.name} style={{ color: p.color }}>{p.name}: {p.value}</div>
        ))}
      </div>
    );
  }
  return null;
};
>>>>>>> origin/nayoung

export default function SiemPage() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
<<<<<<< HEAD

  useEffect(() => {
    api.get("/siem")
      .then((res) => setData(res.data))
=======
  const [sourceFilter, setSourceFilter] = useState('ALL');
  const [severityFilter, setSeverityFilter] = useState('ALL');

  useEffect(() => {
    axios.get(`${API_BASE}/siem`)
      .then(res => {
        if (res.data) {
          setData(res.data);
        }
      })
>>>>>>> origin/nayoung
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

<<<<<<< HEAD
  if (loading) return <div className="loading-center">로딩 중...</div>;
=======
  if (loading) {
    return (
      <div style={{ color: 'white', padding: 60, textAlign: 'center', fontSize: 16, fontFamily: 'monospace' }}>
        <div style={{ fontSize: 24, marginBottom: 12 }}>📡</div>
        SIEM 모니터링 로딩 중...
      </div>
    );
  }
>>>>>>> origin/nayoung

  const d = data || {};
  const services = d.services || {};
  const events = d.recentEvents || d.recent_critical_events || [];
<<<<<<< HEAD

  const serviceCards = [
    { name: "CloudWatch", key: "cloudwatch", color: "var(--hi)", metrics: [
      { label: "CPU 사용률", value: services.cloudwatch?.cpu || "—" },
      { label: "메모리", value: services.cloudwatch?.memory || "—" },
      { label: "에러율", value: services.cloudwatch?.errorRate || "—" },
    ]},
    { name: "GuardDuty", key: "guardduty", color: "var(--pu)", metrics: [
      { label: "위협 탐지", value: services.guardduty?.findings || "0건" },
      { label: "최고 심각도", value: services.guardduty?.severity || "—" },
      { label: "마지막 점검", value: services.guardduty?.lastCheck || "—" },
    ]},
    { name: "Security Hub", key: "securityhub", color: "var(--cr)", metrics: [
      { label: "보안 점수", value: services.securityhub?.score || "—" },
      { label: "Critical", value: services.securityhub?.critical || "0건" },
      { label: "CIS", value: services.securityhub?.cis || "—" },
    ]},
    { name: "CloudTrail", key: "cloudtrail", color: "var(--run)", metrics: [
      { label: "API 호출", value: services.cloudtrail?.events?.toLocaleString() || "—" },
      { label: "Trail 수", value: services.cloudtrail?.trails || "—" },
      { label: "S3 로그", value: services.cloudtrail?.active ? "정상" : "—" },
    ]},
  ];

  return (
    <div className="full-page">
      <div className="page-head">
        <h2>SIEM 모니터링</h2>
        <p>CloudWatch · GuardDuty · CloudTrail · Security Hub</p>
      </div>

      <div className="siem-grid">
        {serviceCards.map((svc) => {
          const svcData = services[svc.key];
          const isActive = svcData?.active !== false;
          return (
            <div className="siem-card" key={svc.key}>
              <div className="siem-card-head">
                <div className="siem-card-title">{svc.name}</div>
                <span className={`sev-b ${isActive ? "s-ok" : "s-ac"}`}>{isActive ? "정상" : "비활성"}</span>
              </div>
              {svc.metrics.map((m, i) => (
                <div className="siem-row" key={i}>
                  <div className="siem-dot" style={{ background: svc.color }} />
                  <div className="siem-info"><div className="siem-title">{m.label}</div></div>
                  <span className="siem-badge b-ok">{m.value}</span>
                </div>
              ))}
            </div>
          );
        })}
      </div>

      {/* Recent Events */}
      <div className="siem-card">
        <div className="siem-card-head">
          <div className="siem-card-title">최근 보안 이벤트</div>
          <span style={{ fontSize: 11, color: "var(--tx3)", fontFamily: "monospace" }}>최근 24시간</span>
        </div>
        {events.length === 0 ? (
          <div style={{ padding: 20, textAlign: "center", color: "var(--tx3)", fontSize: 12 }}>보안 이벤트가 없습니다</div>
        ) : (
          events.map((evt, i) => (
            <div className="ev-item" key={evt.id || i}>
              <span className="ev-time">{evt.time || "—"}</span>
              <div className="ev-body">
                <div className="ev-title">{evt.description || evt.type || "이벤트"}</div>
                <div className="ev-meta">{evt.source || "—"} · {evt.resource || "—"}</div>
              </div>
              <span className={`siem-badge ${evt.severity === "CRITICAL" || evt.severity === "HIGH" ? "b-fail" : evt.severity === "MEDIUM" ? "b-warn" : "b-ok"}`}>
                {evt.severity || evt.status || "—"}
              </span>
            </div>
          ))
=======
  const severityDist = d.severityDistribution || [];
  const trendData = d.trendData || d.event_trends || [];

  const filteredEvents = events
    .filter(e => sourceFilter === 'ALL' || e.source === sourceFilter)
    .filter(e => severityFilter === 'ALL' || (e.severity || '').toUpperCase() === severityFilter);

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
    display: 'flex',
    alignItems: 'center',
    gap: 8,
  };

  return (
    <div style={containerStyle}>
      {/* Header */}
      <div style={{ marginBottom: 20 }}>
        <h1 style={{ fontSize: 24, fontWeight: 800, color: '#fff', margin: 0, marginBottom: 6 }}>
          SIEM 모니터링
        </h1>
        <div style={{ color: '#6b7280', fontSize: 13 }}>
          AWS CloudWatch / GuardDuty / CloudTrail 통합 보안 이벤트 모니터링
        </div>
      </div>

      {/* Service Status Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 16, marginBottom: 20 }}>
        {/* CloudWatch */}
        <div style={{
          ...sectionStyle,
          borderLeft: `4px solid ${services.cloudwatch.active ? '#f59e0b' : '#6b7280'}`,
          padding: '16px 20px',
          marginBottom: 0,
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
            <span style={{ fontSize: 20 }}>📊</span>
            <span style={{ color: '#fff', fontWeight: 700, fontSize: 15 }}>CloudWatch</span>
            <span style={{
              marginLeft: 'auto',
              background: services.cloudwatch.active ? '#14532d' : '#374151',
              color: services.cloudwatch.active ? '#4ade80' : '#9ca3af',
              padding: '2px 8px', borderRadius: 10, fontSize: 11, fontWeight: 600,
            }}>
              {services.cloudwatch.active ? '● 활성' : '● 비활성'}
            </span>
          </div>
          <div style={{ display: 'flex', gap: 16 }}>
            <div>
              <div style={{ color: '#f87171', fontSize: 22, fontWeight: 800 }}>{services.cloudwatch.alarms}</div>
              <div style={{ color: '#9ca3af', fontSize: 11 }}>알람 활성</div>
            </div>
            <div>
              <div style={{ color: '#4ade80', fontSize: 22, fontWeight: 800 }}>{services.cloudwatch.okAlarms}</div>
              <div style={{ color: '#9ca3af', fontSize: 11 }}>정상</div>
            </div>
            <div style={{ marginLeft: 'auto', textAlign: 'right' }}>
              <div style={{ color: '#6b7280', fontSize: 11 }}>리전</div>
              <div style={{ color: '#9ca3af', fontSize: 12, fontFamily: 'monospace' }}>{services.cloudwatch.region}</div>
            </div>
          </div>
        </div>

        {/* GuardDuty */}
        <div style={{
          ...sectionStyle,
          borderLeft: `4px solid ${services.guardduty.active ? '#8b5cf6' : '#6b7280'}`,
          padding: '16px 20px',
          marginBottom: 0,
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
            <span style={{ fontSize: 20 }}>🛡️</span>
            <span style={{ color: '#fff', fontWeight: 700, fontSize: 15 }}>GuardDuty</span>
            <span style={{
              marginLeft: 'auto',
              background: services.guardduty.active ? '#14532d' : '#374151',
              color: services.guardduty.active ? '#4ade80' : '#9ca3af',
              padding: '2px 8px', borderRadius: 10, fontSize: 11, fontWeight: 600,
            }}>
              {services.guardduty.active ? '● 활성' : '● 비활성'}
            </span>
          </div>
          <div style={{ display: 'flex', gap: 16 }}>
            <div>
              <div style={{ color: '#f87171', fontSize: 22, fontWeight: 800 }}>{services.guardduty.findings}</div>
              <div style={{ color: '#9ca3af', fontSize: 11 }}>위협 탐지</div>
            </div>
            <div>
              <div style={{ color: SEVERITY_COLORS[services.guardduty.severity]?.bg || '#d97706', fontSize: 14, fontWeight: 700, paddingTop: 4 }}>
                {services.guardduty.severity}
              </div>
              <div style={{ color: '#9ca3af', fontSize: 11 }}>최고 심각도</div>
            </div>
            <div style={{ marginLeft: 'auto', textAlign: 'right' }}>
              <div style={{ color: '#6b7280', fontSize: 11 }}>마지막 점검</div>
              <div style={{ color: '#9ca3af', fontSize: 12 }}>{services.guardduty.lastCheck}</div>
            </div>
          </div>
        </div>

        {/* CloudTrail */}
        <div style={{
          ...sectionStyle,
          borderLeft: `4px solid ${services.cloudtrail.active ? '#06b6d4' : '#6b7280'}`,
          padding: '16px 20px',
          marginBottom: 0,
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
            <span style={{ fontSize: 20 }}>📜</span>
            <span style={{ color: '#fff', fontWeight: 700, fontSize: 15 }}>CloudTrail</span>
            <span style={{
              marginLeft: 'auto',
              background: services.cloudtrail.active ? '#14532d' : '#374151',
              color: services.cloudtrail.active ? '#4ade80' : '#9ca3af',
              padding: '2px 8px', borderRadius: 10, fontSize: 11, fontWeight: 600,
            }}>
              {services.cloudtrail.active ? '● 활성' : '● 비활성'}
            </span>
          </div>
          <div style={{ display: 'flex', gap: 16 }}>
            <div>
              <div style={{ color: '#60a5fa', fontSize: 22, fontWeight: 800 }}>{services.cloudtrail.events?.toLocaleString()}</div>
              <div style={{ color: '#9ca3af', fontSize: 11 }}>오늘 이벤트</div>
            </div>
            <div>
              <div style={{ color: '#9ca3af', fontSize: 22, fontWeight: 800 }}>{services.cloudtrail.trails}</div>
              <div style={{ color: '#9ca3af', fontSize: 11 }}>Trail 수</div>
            </div>
            <div style={{ marginLeft: 'auto', textAlign: 'right' }}>
              <div style={{ color: '#6b7280', fontSize: 11 }}>마지막 이벤트</div>
              <div style={{ color: '#9ca3af', fontSize: 12 }}>{services.cloudtrail.lastEvent}</div>
            </div>
          </div>
        </div>
      </div>

      {/* Charts Row */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: 20, marginBottom: 20 }}>
        {/* Severity Distribution */}
        <div style={sectionStyle}>
          <div style={sectionTitleStyle}>
            <span>📊</span>
            <span>심각도별 이벤트 분포</span>
          </div>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={severityDist} layout="vertical" margin={{ left: 10, right: 20 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#374151" horizontal={false} />
              <XAxis type="number" tick={{ fill: '#9ca3af', fontSize: 11 }} axisLine={false} tickLine={false} />
              <YAxis type="category" dataKey="name" tick={{ fill: '#9ca3af', fontSize: 11 }} axisLine={false} tickLine={false} width={60} />
              <Tooltip
                content={({ active, payload, label }) => active && payload?.length ? (
                  <div style={{ background: '#1f2937', border: '1px solid #374151', padding: '8px 12px', borderRadius: 6, color: '#fff', fontSize: 12 }}>
                    <div style={{ fontWeight: 700 }}>{label}: {payload[0].value}건</div>
                  </div>
                ) : null}
              />
              <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                {severityDist.map((entry, i) => <Cell key={i} fill={entry.fill} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Event Trend */}
        <div style={sectionStyle}>
          <div style={sectionTitleStyle}>
            <span>📈</span>
            <span>시간대별 이벤트 추이 (오늘)</span>
          </div>
          <ResponsiveContainer width="100%" height={220}>
            <LineChart data={trendData} margin={{ top: 5, right: 20, left: 0, bottom: 5 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
              <XAxis dataKey="time" tick={{ fill: '#9ca3af', fontSize: 11 }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: '#9ca3af', fontSize: 11 }} axisLine={false} tickLine={false} />
              <Tooltip content={<CustomTooltip />} />
              <Legend formatter={(v) => <span style={{ color: '#9ca3af', fontSize: 11 }}>{v}</span>} />
              <Line type="monotone" dataKey="cloudwatch" stroke="#f59e0b" strokeWidth={2} dot={false} name="CloudWatch" />
              <Line type="monotone" dataKey="guardduty" stroke="#8b5cf6" strokeWidth={2} dot={false} name="GuardDuty" />
              <Line type="monotone" dataKey="cloudtrail" stroke="#06b6d4" strokeWidth={2} dot={false} name="CloudTrail" />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Events Table */}
      <div style={sectionStyle}>
        <div style={sectionTitleStyle}>
          <span>🚨</span>
          <span>최근 보안 이벤트</span>
          <span style={{
            marginLeft: 'auto',
            background: '#374151',
            color: '#9ca3af',
            padding: '2px 10px',
            borderRadius: 10,
            fontSize: 12,
          }}>
            {filteredEvents.length}건
          </span>
        </div>

        {/* Filters */}
        <div style={{ display: 'flex', gap: 12, marginBottom: 16, flexWrap: 'wrap', alignItems: 'center' }}>
          <div style={{ display: 'flex', gap: 6 }}>
            {['ALL', 'GuardDuty', 'CloudWatch', 'CloudTrail'].map(src => (
              <button
                key={src}
                onClick={() => setSourceFilter(src)}
                style={{
                  background: sourceFilter === src ? (SOURCE_COLORS[src] || '#374151') : '#1f2937',
                  color: sourceFilter === src ? '#fff' : '#9ca3af',
                  border: `1px solid ${sourceFilter === src ? (SOURCE_COLORS[src] || '#374151') : '#374151'}`,
                  borderRadius: 6,
                  padding: '5px 12px',
                  fontSize: 12,
                  fontWeight: 600,
                  cursor: 'pointer',
                }}
              >
                {src === 'ALL' ? '전체 소스' : src}
              </button>
            ))}
          </div>
          <div style={{ display: 'flex', gap: 6 }}>
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(sev => {
              const sevColor = SEVERITY_COLORS[sev]?.bg || '#374151';
              return (
                <button
                  key={sev}
                  onClick={() => setSeverityFilter(sev)}
                  style={{
                    background: severityFilter === sev ? (sev === 'ALL' ? '#374151' : sevColor) : '#1f2937',
                    color: severityFilter === sev ? '#fff' : '#9ca3af',
                    border: `1px solid ${severityFilter === sev ? (sev === 'ALL' ? '#374151' : sevColor) : '#374151'}`,
                    borderRadius: 6,
                    padding: '5px 12px',
                    fontSize: 11,
                    fontWeight: 600,
                    cursor: 'pointer',
                  }}
                >
                  {sev === 'ALL' ? '전체' : sev}
                </button>
              );
            })}
          </div>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ background: '#111827' }}>
                {['소스', '심각도', '이벤트 유형', '설명', '리소스', '리전', '상태', '시각'].map(h => (
                  <th key={h} style={{
                    padding: '10px 12px',
                    textAlign: 'left',
                    color: '#9ca3af',
                    fontSize: 11,
                    fontWeight: 700,
                    borderBottom: '1px solid #374151',
                    whiteSpace: 'nowrap',
                  }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filteredEvents.map((evt, idx) => {
                const srcColor = SOURCE_COLORS[evt.source] || '#6b7280';
                const rowBg = idx % 2 === 0 ? '#1f2937' : '#1a2332';
                const isActive = evt.status === 'ACTIVE';
                return (
                  <tr key={evt.id} style={{
                    background: rowBg,
                    borderLeft: isActive ? '3px solid #dc2626' : '3px solid transparent',
                  }}>
                    <td style={{ padding: '10px 12px', whiteSpace: 'nowrap' }}>
                      <span style={{
                        background: srcColor + '20',
                        color: srcColor,
                        padding: '2px 8px',
                        borderRadius: 4,
                        fontSize: 11,
                        fontWeight: 700,
                      }}>{evt.source}</span>
                    </td>
                    <td style={{ padding: '10px 12px', whiteSpace: 'nowrap' }}>
                      <SeverityBadge severity={evt.severity} />
                    </td>
                    <td style={{ padding: '10px 12px', maxWidth: 200 }}>
                      <div style={{ color: '#e5e7eb', fontFamily: 'monospace', fontSize: 11, wordBreak: 'break-all' }}>
                        {evt.type}
                      </div>
                    </td>
                    <td style={{ padding: '10px 12px', maxWidth: 240 }}>
                      <div style={{ color: '#9ca3af', fontSize: 12, lineHeight: 1.4 }}>
                        {evt.description}
                      </div>
                    </td>
                    <td style={{ padding: '10px 12px' }}>
                      <div style={{ color: '#60a5fa', fontFamily: 'monospace', fontSize: 11 }}>
                        {evt.resource}
                      </div>
                    </td>
                    <td style={{ padding: '10px 12px' }}>
                      <span style={{ color: '#6b7280', fontFamily: 'monospace', fontSize: 11 }}>
                        {evt.region}
                      </span>
                    </td>
                    <td style={{ padding: '10px 12px', whiteSpace: 'nowrap' }}>
                      <StatusBadge status={evt.status} />
                    </td>
                    <td style={{ padding: '10px 12px', whiteSpace: 'nowrap' }}>
                      <span style={{ color: '#6b7280', fontSize: 11 }}>{evt.time}</span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        {filteredEvents.length === 0 && (
          <div style={{ padding: 30, textAlign: 'center', color: '#6b7280', fontSize: 14 }}>
            이벤트가 없습니다.
          </div>
>>>>>>> origin/nayoung
        )}
      </div>
    </div>
  );
}
