<<<<<<< HEAD
import React, { useState, useEffect } from "react";
import api from "../services/api";
=======
﻿import React, { useState, useEffect } from 'react';
import axios from 'axios';

const API_BASE = process.env.REACT_APP_API_BASE_URL || 'http://localhost:8000/api/v1';


const STATUS_STYLES = {
  PASS: { bg: '#14532d', color: '#4ade80', label: '충족', icon: '✓' },
  FAIL: { bg: '#450a0a', color: '#f87171', label: '미충족', icon: '✗' },
  NA: { bg: '#1f2937', color: '#9ca3af', label: 'N/A', icon: '—' },
};

const SEVERITY_COLORS = {
  CRITICAL: { bg: '#dc2626', color: '#fff' },
  HIGH: { bg: '#ea580c', color: '#fff' },
  MEDIUM: { bg: '#d97706', color: '#fff' },
  LOW: { bg: '#65a30d', color: '#fff' },
};

function StatusBadge({ status }) {
  const s = STATUS_STYLES[status] || STATUS_STYLES.NA;
  return (
    <span style={{
      background: s.bg,
      color: s.color,
      padding: '3px 10px',
      borderRadius: 4,
      fontSize: 12,
      fontWeight: 700,
      display: 'inline-flex',
      alignItems: 'center',
      gap: 4,
    }}>
      <span>{s.icon}</span>
      <span>{s.label}</span>
    </span>
  );
}

function SeverityBadge({ severity }) {
  const s = SEVERITY_COLORS[(severity || '').toUpperCase()] || { bg: '#6b7280', color: '#fff' };
  return (
    <span style={{
      background: s.bg,
      color: s.color,
      padding: '2px 8px',
      borderRadius: 4,
      fontSize: 11,
      fontWeight: 700,
    }}>
      {(severity || 'INFO').toUpperCase()}
    </span>
  );
}
>>>>>>> origin/nayoung

export default function IsmsPage() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
<<<<<<< HEAD
  const [statusFilter, setStatusFilter] = useState("ALL");

  useEffect(() => {
    api.get("/isms")
      .then((res) => setData(res.data))
=======
  const [expandedCategories, setExpandedCategories] = useState({});
  const [statusFilter, setStatusFilter] = useState('ALL');

  useEffect(() => {
    axios.get(`${API_BASE}/isms`)
      .then(res => {
        if (res.data) {
          setData(res.data);
          const expanded = {};
          (res.data.categories || []).forEach(c => { expanded[c.id] = true; });
          setExpandedCategories(expanded);
        }
      })
>>>>>>> origin/nayoung
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

<<<<<<< HEAD
  if (loading) return <div className="loading-center">로딩 중...</div>;

  const d = data || {};
  const summary = d.summary || d.overall || { total: 0, pass: 0, fail: 0, na: 0 };
  const categories = d.categories || [];
  const total = summary.total || 1;
  const passRate = Math.round((summary.pass / total) * 100);

  const allItems = categories.flatMap((c) => c.items || []);
  const filtered = allItems.filter((item) => statusFilter === "ALL" || item.status === statusFilter);

  return (
    <div className="full-page">
      <div className="page-head">
        <h2>ISMS-P 컴플라이언스</h2>
        <p>AWS 설정 자동 점검 · boto3 API 수집 결과</p>
      </div>

      {/* Summary */}
      <div className="isms-summary">
        <div className="isms-big">
          <div className="isms-pct">{passRate}%</div>
          <div>
            <div style={{ fontSize: 13, color: "var(--tx2)" }}>기술 항목 자동 점검 결과</div>
            <div style={{ height: 6, background: "var(--bd)", borderRadius: 3, marginTop: 8, overflow: "hidden", width: 180 }}>
              <div style={{ height: "100%", background: "var(--pu)", borderRadius: 3, width: `${passRate}%` }} />
            </div>
            <div style={{ fontSize: 11, color: "var(--tx3)", fontFamily: "monospace", marginTop: 4 }}>
              {summary.total}개 점검 · {summary.pass}개 충족 · {summary.fail}개 미충족
            </div>
          </div>
        </div>
        <div className="isms-stat"><div className="isms-stat-n" style={{ color: "var(--ok)" }}>{summary.pass}</div><div className="isms-stat-l">충족</div></div>
        <div className="isms-stat"><div className="isms-stat-n" style={{ color: "var(--cr)" }}>{summary.fail}</div><div className="isms-stat-l">미충족</div></div>
        <div className="isms-stat"><div className="isms-stat-n" style={{ color: "var(--pu)" }}>{summary.total}</div><div className="isms-stat-l">자동 점검</div></div>
      </div>

      {/* Filter */}
      <div className="filter-row">
        {[
          { v: "ALL", l: "전체" },
          { v: "PASS", l: "충족" },
          { v: "FAIL", l: "미충족" },
          { v: "NA", l: "N/A" },
        ].map((f) => (
          <span key={f.v} className={`filter-chip${statusFilter === f.v ? " active" : ""}`} onClick={() => setStatusFilter(f.v)}>{f.l}</span>
        ))}
      </div>

      {filtered.length === 0 ? (
        <div style={{ padding: 40, textAlign: "center", color: "var(--tx3)", fontFamily: "monospace" }}>
          ISMS-P 점검 데이터가 없습니다.<br />POST /api/v1/isms/run 으로 점검을 실행하세요.
        </div>
      ) : (
        <table className="vtbl">
          <thead>
            <tr><th>항목 ID</th><th>통제 항목</th><th>AWS 점검 내용</th><th>판정</th><th>조치 사항</th></tr>
          </thead>
          <tbody>
            {filtered.map((item, i) => {
              const ok = item.status === "PASS";
              return (
                <tr key={item.id || i} style={{ background: !ok && item.status === "FAIL" ? "rgba(220,38,38,.02)" : undefined }}>
                  <td><code>{item.id}</code></td>
                  <td style={{ fontWeight: 500 }}>{item.name}</td>
                  <td style={{ fontSize: 12, color: "var(--tx2)" }}>{item.description || item.evidence || "—"}</td>
                  <td><span className={`ist ${ok ? "ist-ok" : "ist-fail"}`}>{ok ? "충족" : "미충족"}</span></td>
                  <td style={{ fontSize: 12, color: "var(--tx2)" }}>{item.action || (ok ? "—" : "조치 필요")}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
=======
  if (loading) {
    return (
      <div style={{ color: 'white', padding: 60, textAlign: 'center', fontSize: 16, fontFamily: 'monospace' }}>
        <div style={{ fontSize: 24, marginBottom: 12 }}>📋</div>
        ISMS-P 점검 결과 로딩 중...
      </div>
    );
  }

  const d = data || {};
  const summary = d.summary || d.overall || { total: 0, pass: 0, passed: 0, fail: 0, failed: 0, na: 0 };
  const categories = d.categories || [];

  const passRate = summary.total > 0 ? ((summary.pass / summary.total) * 100).toFixed(1) : 0;

  const toggleCategory = (id) => {
    setExpandedCategories(prev => ({ ...prev, [id]: !prev[id] }));
  };

  const filterItem = (item) => {
    if (statusFilter === 'ALL') return true;
    return item.status === statusFilter;
  };

  const containerStyle = {
    background: '#111827',
    minHeight: '100vh',
    color: '#fff',
    fontFamily: "'Segoe UI', system-ui, sans-serif",
    paddingBottom: 40,
  };

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
    <div style={containerStyle}>
      {/* Header */}
      <div style={{ marginBottom: 20 }}>
        <h1 style={{ fontSize: 24, fontWeight: 800, color: '#fff', margin: 0, marginBottom: 6 }}>
          ISMS-P 자동 점검 결과
        </h1>
        <div style={{
          background: '#1e3a5f',
          border: '1px solid #1d4ed8',
          borderRadius: 6,
          padding: '8px 14px',
          display: 'inline-block',
          color: '#93c5fd',
          fontSize: 12,
          marginTop: 6,
        }}>
          ℹ️ 38개 기술 항목 자동 점검 / 64개 관리적 항목은 수동 점검 필요
        </div>
      </div>

      {/* Summary Cards */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
        gap: 14,
        marginBottom: 20,
      }}>
        {[
          { label: '총 점검 항목', value: summary.total, color: '#60a5fa', sub: '기술 항목' },
          { label: '충족', value: summary.pass, color: '#4ade80', sub: '항목 충족' },
          { label: '미충족', value: summary.fail, color: '#f87171', sub: '항목 실패' },
          { label: 'N/A', value: summary.na, color: '#9ca3af', sub: '해당 없음' },
          { label: '충족률', value: `${passRate}%`, color: parseFloat(passRate) >= 80 ? '#4ade80' : parseFloat(passRate) >= 60 ? '#fbbf24' : '#f87171', sub: '자동 점검 기준' },
        ].map(card => (
          <div key={card.label} style={{
            background: '#1f2937',
            border: `1px solid ${card.color}30`,
            borderLeft: `4px solid ${card.color}`,
            borderRadius: 8,
            padding: '14px 16px',
          }}>
            <div style={{ color: '#9ca3af', fontSize: 11, fontWeight: 600, marginBottom: 6 }}>{card.label}</div>
            <div style={{ color: card.color, fontSize: 28, fontWeight: 800, lineHeight: 1 }}>{card.value}</div>
            <div style={{ color: '#4b5563', fontSize: 11, marginTop: 4 }}>{card.sub}</div>
          </div>
        ))}
      </div>

      {/* Pass Rate Progress Bar */}
      <div style={{
        background: '#1f2937',
        border: '1px solid #374151',
        borderRadius: 10,
        padding: '16px 20px',
        marginBottom: 20,
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
          <span style={{ color: '#e5e7eb', fontSize: 14, fontWeight: 600 }}>ISMS-P 충족률 (자동 점검)</span>
          <span style={{
            color: parseFloat(passRate) >= 80 ? '#4ade80' : parseFloat(passRate) >= 60 ? '#fbbf24' : '#f87171',
            fontSize: 16,
            fontWeight: 800,
          }}>
            {passRate}%
          </span>
        </div>
        <div style={{ background: '#374151', borderRadius: 20, height: 10, overflow: 'hidden' }}>
          <div style={{
            width: `${passRate}%`,
            height: '100%',
            background: parseFloat(passRate) >= 80 ? '#16a34a' : parseFloat(passRate) >= 60 ? '#d97706' : '#dc2626',
            borderRadius: 20,
            transition: 'width 0.5s ease',
          }} />
        </div>
        <div style={{ display: 'flex', gap: 20, marginTop: 8 }}>
          {[
            { label: `충족 ${summary.pass}개`, color: '#4ade80' },
            { label: `미충족 ${summary.fail}개`, color: '#f87171' },
            { label: `N/A ${summary.na}개`, color: '#9ca3af' },
          ].map(item => (
            <span key={item.label} style={{ color: item.color, fontSize: 12 }}>{item.label}</span>
          ))}
        </div>
      </div>

      {/* Status Filter */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 20, flexWrap: 'wrap' }}>
        {[
          { label: '전체', value: 'ALL', color: '#9ca3af', bg: '#374151' },
          { label: '충족 (PASS)', value: 'PASS', color: '#4ade80', bg: '#14532d' },
          { label: '미충족 (FAIL)', value: 'FAIL', color: '#f87171', bg: '#450a0a' },
          { label: 'N/A', value: 'NA', color: '#9ca3af', bg: '#1f2937' },
        ].map(btn => (
          <button
            key={btn.value}
            onClick={() => setStatusFilter(btn.value)}
            style={{
              background: statusFilter === btn.value ? btn.bg : '#1f2937',
              color: statusFilter === btn.value ? btn.color : '#9ca3af',
              border: `1px solid ${statusFilter === btn.value ? btn.color + '60' : '#374151'}`,
              borderRadius: 6,
              padding: '6px 14px',
              fontSize: 12,
              fontWeight: 600,
              cursor: 'pointer',
            }}
          >
            {btn.label}
          </button>
        ))}
      </div>

      {/* Category Tables */}
      {categories.map(category => {
        const filteredItems = category.items.filter(filterItem);
        if (filteredItems.length === 0 && statusFilter !== 'ALL') return null;

        const catPass = category.items.filter(i => i.status === 'PASS').length;
        const catFail = category.items.filter(i => i.status === 'FAIL').length;
        const isExpanded = expandedCategories[category.id] !== false;

        return (
          <div key={category.id} style={{
            background: '#1f2937',
            border: '1px solid #374151',
            borderRadius: 10,
            marginBottom: 16,
            overflow: 'hidden',
          }}>
            {/* Category Header */}
            <button
              onClick={() => toggleCategory(category.id)}
              style={{
                width: '100%',
                background: '#161e2e',
                border: 'none',
                borderBottom: isExpanded ? '1px solid #374151' : 'none',
                padding: '14px 20px',
                display: 'flex',
                alignItems: 'center',
                gap: 12,
                cursor: 'pointer',
                textAlign: 'left',
              }}
            >
              <span style={{ color: '#60a5fa', fontSize: 13, fontFamily: 'monospace', fontWeight: 700 }}>
                {category.id}
              </span>
              <span style={{ color: '#fff', fontWeight: 700, fontSize: 15, flex: 1 }}>
                {category.name}
              </span>
              <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                <span style={{ color: '#4ade80', fontSize: 12, fontWeight: 600 }}>✓ {catPass}</span>
                <span style={{ color: '#f87171', fontSize: 12, fontWeight: 600 }}>✗ {catFail}</span>
                <span style={{
                  color: '#9ca3af',
                  fontSize: 12,
                  background: '#374151',
                  padding: '2px 8px',
                  borderRadius: 8,
                }}>
                  {category.items.length}건
                </span>
                <span style={{ color: '#9ca3af', fontSize: 14 }}>{isExpanded ? '▲' : '▼'}</span>
              </div>
            </button>

            {isExpanded && (
              <div style={{ overflowX: 'auto' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                  <thead>
                    <tr style={{ background: '#111827' }}>
                      <th style={thStyle}>항목 ID</th>
                      <th style={thStyle}>점검 항목</th>
                      <th style={thStyle}>상태</th>
                      <th style={thStyle}>심각도</th>
                      <th style={thStyle}>증적/근거</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredItems.map((item, idx) => {
                      const rowBg = idx % 2 === 0 ? '#1f2937' : '#1a2332';
                      const isFail = item.status === 'FAIL';
                      return (
                        <tr key={item.id} style={{
                          background: rowBg,
                          borderLeft: isFail ? '3px solid #dc2626' : '3px solid transparent',
                        }}>
                          <td style={{ ...tdStyle, fontFamily: 'monospace', color: '#60a5fa', fontSize: 12, whiteSpace: 'nowrap' }}>
                            {item.id}
                          </td>
                          <td style={{ ...tdStyle, maxWidth: 260 }}>
                            <div style={{ color: '#fff', fontWeight: 600, fontSize: 13, marginBottom: 3 }}>
                              {item.name}
                            </div>
                            <div style={{ color: '#6b7280', fontSize: 11, lineHeight: 1.5 }}>
                              {item.description}
                            </div>
                          </td>
                          <td style={tdStyle}>
                            <StatusBadge status={item.status} />
                          </td>
                          <td style={tdStyle}>
                            <SeverityBadge severity={item.severity} />
                          </td>
                          <td style={{ ...tdStyle, color: '#9ca3af', fontSize: 12, maxWidth: 320, lineHeight: 1.5 }}>
                            {item.evidence || '-'}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        );
      })}

      {/* Manual Check Notice */}
      <div style={{
        background: '#1e3a5f',
        border: '1px solid #1d4ed8',
        borderRadius: 10,
        padding: '16px 20px',
        marginTop: 20,
      }}>
        <div style={{ color: '#93c5fd', fontWeight: 700, fontSize: 14, marginBottom: 8 }}>
          📌 수동 점검 필요 항목 (64개)
        </div>
        <div style={{ color: '#6b7280', fontSize: 13, lineHeight: 1.6 }}>
          조직 정책, 보안 교육, 물리적 보안, 인사 보안 등 관리적 항목은 자동화된 도구로 점검할 수 없으며 수동 감사가 필요합니다.
          담당 보안 담당자 및 ISMS-P 심사원과 별도 협의가 필요합니다.
        </div>
        <div style={{ display: 'flex', gap: 8, marginTop: 12, flexWrap: 'wrap' }}>
          {['1. 관리체계 수립 및 운영', '2.1 정책 및 조직', '2.2 위험관리', '2.3 인적 보안', '2.4 물리보안', '3. 개인정보 처리 단계별 보호조치'].map(item => (
            <span key={item} style={{
              background: '#1f4e79',
              color: '#93c5fd',
              padding: '3px 10px',
              borderRadius: 4,
              fontSize: 11,
            }}>
              {item}
            </span>
          ))}
        </div>
      </div>
>>>>>>> origin/nayoung
    </div>
  );
}
