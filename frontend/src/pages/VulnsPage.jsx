<<<<<<< HEAD
import React, { useState, useEffect } from "react";
import api from "../services/api";

const SEV_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
=======
import React, { useState, useEffect } from 'react';
import axios from 'axios';
import VulnTable from '../components/vulns/VulnTable';

const API_BASE = process.env.REACT_APP_API_BASE_URL || 'http://localhost:8000/api/v1';


const SEVERITY_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };


function countBySeverity(vulns) {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  vulns.forEach(v => {
    const s = (v.severity || '').toUpperCase();
    if (counts[s] !== undefined) counts[s]++;
  });
  return counts;
}
>>>>>>> origin/nayoung

export default function VulnsPage() {
  const [vulns, setVulns] = useState([]);
  const [loading, setLoading] = useState(true);
<<<<<<< HEAD
  const [filter, setFilter] = useState("ALL");

  useEffect(() => {
    api.get("/vulns")
      .then((res) => setVulns(Array.isArray(res.data) ? res.data : (res.data.vulnerabilities || [])))
=======
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [toolFilter, setToolFilter] = useState('ALL');
  const [categoryFilter, setCategoryFilter] = useState('ALL');

  useEffect(() => {
    axios.get(`${API_BASE}/vulns`)
      .then(res => {
        const data = Array.isArray(res.data) ? res.data : (res.data.vulnerabilities || res.data.items || []);
        setVulns(data);
      })
>>>>>>> origin/nayoung
      .catch(() => setVulns([]))
      .finally(() => setLoading(false));
  }, []);

<<<<<<< HEAD
  if (loading) return <div className="loading-center">로딩 중...</div>;

  const counts = { ALL: vulns.length, CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  vulns.forEach((v) => { const s = (v.severity || "").toUpperCase(); if (counts[s] !== undefined) counts[s]++; });

  const filtered = vulns
    .filter((v) => filter === "ALL" || (v.severity || "").toUpperCase() === filter)
    .sort((a, b) => (SEV_ORDER[(a.severity || "").toUpperCase()] ?? 99) - (SEV_ORDER[(b.severity || "").toUpperCase()] ?? 99));

  const sevClass = (s) => {
    s = (s || "").toUpperCase();
    return s === "CRITICAL" ? "s-cr" : s === "HIGH" ? "s-hi" : s === "MEDIUM" ? "s-ac" : "s-ok";
  };

  const catClass = (c) => {
    c = (c || "").toUpperCase();
    return c === "SAST" ? "cat-sast" : c === "SCA" ? "cat-sca" : c === "IAC" ? "cat-iac" : c === "DAST" ? "cat-dast" : "";
  };

  return (
    <div className="full-page">
      <div className="page-head">
        <h2>취약점 목록</h2>
        <p>전체 파이프라인 탐지 결과 통합 · 현재 {filtered.length}건 표시</p>
      </div>

      <div className="filter-row">
        {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map((s) => (
          <span key={s} className={`filter-chip${filter === s ? " active" : ""}`} onClick={() => setFilter(s)}>
            {s === "ALL" ? "전체" : s} {counts[s] > 0 && `(${counts[s]})`}
          </span>
        ))}
      </div>

      {filtered.length === 0 ? (
        <div style={{ padding: 40, textAlign: "center", color: "var(--tx3)", fontFamily: "monospace" }}>탐지된 취약점이 없습니다</div>
      ) : (
        <table className="vtbl">
          <thead>
            <tr><th>심각도</th><th>단계</th><th>취약점</th><th>위치</th><th>도구</th><th>상태</th></tr>
          </thead>
          <tbody>
            {filtered.map((v, i) => (
              <tr key={v.id || i}>
                <td><span className={`sev-b ${sevClass(v.severity)}`}>{(v.severity || "—").toUpperCase()}</span></td>
                <td><span className={`sev-b ${catClass(v.category)}`} style={{ fontWeight: 600 }}>{v.category || "—"}</span></td>
                <td style={{ fontWeight: 500 }}>{v.title || "—"}</td>
                <td><code>{v.file_path || "—"}{v.line_number ? `:${v.line_number}` : ""}</code></td>
                <td style={{ color: "var(--tx2)", fontSize: 11 }}>{v.tool || "—"}</td>
                <td><span className={`sev-b ${v.status === "RESOLVED" ? "s-ok" : v.status === "IGNORED" ? "s-pu" : "s-ac"}`}>{v.status || "OPEN"}</span></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
=======
  if (loading) {
    return (
      <div style={{ color: 'white', padding: 60, textAlign: 'center', fontSize: 16, fontFamily: 'monospace' }}>
        <div style={{ fontSize: 24, marginBottom: 12 }}>🔎</div>
        취약점 목록 로딩 중...
      </div>
    );
  }

  // Derive filter options
  const allTools = ['ALL', ...Array.from(new Set(vulns.map(v => v.tool).filter(Boolean))).sort()];
  const allCategories = ['ALL', ...Array.from(new Set(vulns.map(v => v.category).filter(Boolean))).sort()];
  const allSeverities = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

  // Apply filters
  const filtered = vulns
    .filter(v => severityFilter === 'ALL' || (v.severity || '').toUpperCase() === severityFilter)
    .filter(v => toolFilter === 'ALL' || v.tool === toolFilter)
    .filter(v => categoryFilter === 'ALL' || (v.category || '').toUpperCase() === categoryFilter.toUpperCase())
    .sort((a, b) => {
      const ao = SEVERITY_ORDER[(a.severity || '').toUpperCase()] ?? 99;
      const bo = SEVERITY_ORDER[(b.severity || '').toUpperCase()] ?? 99;
      return ao - bo;
    });

  const counts = countBySeverity(filtered);
  const totalCounts = countBySeverity(vulns);

  const containerStyle = {
    background: '#111827',
    minHeight: '100vh',
    color: '#fff',
    fontFamily: "'Segoe UI', system-ui, sans-serif",
    paddingBottom: 40,
  };

  const selectStyle = {
    background: '#1f2937',
    color: '#e5e7eb',
    border: '1px solid #374151',
    borderRadius: 6,
    padding: '7px 12px',
    fontSize: 13,
    cursor: 'pointer',
    outline: 'none',
  };

  return (
    <div style={containerStyle}>
      {/* Header */}
      <div style={{ marginBottom: 20 }}>
        <h1 style={{ fontSize: 24, fontWeight: 800, color: '#fff', margin: 0, marginBottom: 6 }}>
          취약점 목록
        </h1>
        <div style={{ color: '#6b7280', fontSize: 13 }}>
          전체 보안 도구에서 탐지된 취약점 통합 목록
        </div>
      </div>

      {/* Stats Bar */}
      <div style={{
        display: 'flex',
        gap: 12,
        marginBottom: 20,
        flexWrap: 'wrap',
        background: '#1f2937',
        border: '1px solid #374151',
        borderRadius: 10,
        padding: '14px 20px',
        alignItems: 'center',
      }}>
        <div style={{ color: '#9ca3af', fontSize: 13 }}>
          전체&nbsp;
          <span style={{ color: '#fff', fontWeight: 800, fontSize: 16 }}>
            {filtered.length}
          </span>
          <span style={{ color: '#6b7280', fontSize: 12 }}>/{vulns.length}</span>
        </div>
        {[['CRITICAL', '#dc2626'], ['HIGH', '#ea580c'], ['MEDIUM', '#d97706'], ['LOW', '#65a30d']].map(([sev, color]) => (
          <React.Fragment key={sev}>
            <span style={{ color: '#374151' }}>|</span>
            <div style={{ color: '#9ca3af', fontSize: 13 }}>
              <span style={{ color, fontWeight: 700 }}>{sev}</span>
              {' '}
              <span style={{ color: '#fff', fontWeight: 800 }}>{counts[sev]}</span>
            </div>
          </React.Fragment>
        ))}
        <div style={{ marginLeft: 'auto', color: '#6b7280', fontSize: 12 }}>
          (전체 통계: C:{totalCounts.CRITICAL} H:{totalCounts.HIGH} M:{totalCounts.MEDIUM} L:{totalCounts.LOW})
        </div>
      </div>

      {/* Filter Bar */}
      <div style={{
        display: 'flex',
        gap: 12,
        marginBottom: 20,
        flexWrap: 'wrap',
        alignItems: 'center',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ color: '#9ca3af', fontSize: 13 }}>심각도</span>
          <select
            value={severityFilter}
            onChange={e => setSeverityFilter(e.target.value)}
            style={selectStyle}
          >
            {allSeverities.map(s => (
              <option key={s} value={s}>{s === 'ALL' ? '전체' : s}</option>
            ))}
          </select>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ color: '#9ca3af', fontSize: 13 }}>도구</span>
          <select
            value={toolFilter}
            onChange={e => setToolFilter(e.target.value)}
            style={selectStyle}
          >
            {allTools.map(t => (
              <option key={t} value={t}>{t === 'ALL' ? '전체 도구' : t}</option>
            ))}
          </select>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ color: '#9ca3af', fontSize: 13 }}>카테고리</span>
          <select
            value={categoryFilter}
            onChange={e => setCategoryFilter(e.target.value)}
            style={selectStyle}
          >
            {allCategories.map(c => (
              <option key={c} value={c}>{c === 'ALL' ? '전체 카테고리' : c}</option>
            ))}
          </select>
        </div>
        {(severityFilter !== 'ALL' || toolFilter !== 'ALL' || categoryFilter !== 'ALL') && (
          <button
            onClick={() => { setSeverityFilter('ALL'); setToolFilter('ALL'); setCategoryFilter('ALL'); }}
            style={{
              background: '#374151',
              color: '#9ca3af',
              border: 'none',
              borderRadius: 6,
              padding: '7px 14px',
              fontSize: 13,
              cursor: 'pointer',
            }}
          >
            필터 초기화
          </button>
        )}
      </div>

      {/* Severity filter quick buttons */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 20, flexWrap: 'wrap' }}>
        {[
          { label: '전체', value: 'ALL', color: '#9ca3af', bg: '#374151' },
          { label: 'CRITICAL', value: 'CRITICAL', color: '#fff', bg: '#dc2626' },
          { label: 'HIGH', value: 'HIGH', color: '#fff', bg: '#ea580c' },
          { label: 'MEDIUM', value: 'MEDIUM', color: '#fff', bg: '#d97706' },
          { label: 'LOW', value: 'LOW', color: '#fff', bg: '#65a30d' },
        ].map(btn => (
          <button
            key={btn.value}
            onClick={() => setSeverityFilter(btn.value)}
            style={{
              background: severityFilter === btn.value ? btn.bg : '#1f2937',
              color: severityFilter === btn.value ? btn.color : '#9ca3af',
              border: `1px solid ${severityFilter === btn.value ? btn.bg : '#374151'}`,
              borderRadius: 6,
              padding: '5px 14px',
              fontSize: 12,
              fontWeight: 600,
              cursor: 'pointer',
              transition: 'all 0.15s',
            }}
          >
            {btn.label}
            {btn.value !== 'ALL' && (
              <span style={{
                marginLeft: 6,
                background: 'rgba(0,0,0,0.3)',
                borderRadius: 8,
                padding: '1px 5px',
                fontSize: 11,
              }}>
                {totalCounts[btn.value] || 0}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Table */}
      <div style={{
        background: '#1f2937',
        border: '1px solid #374151',
        borderRadius: 10,
        overflow: 'hidden',
      }}>
        <div style={{
          padding: '12px 20px',
          borderBottom: '1px solid #374151',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}>
          <span style={{ color: '#e5e7eb', fontWeight: 700, fontSize: 14 }}>
            취약점 상세 목록
          </span>
          <span style={{ color: '#6b7280', fontSize: 13 }}>
            {filtered.length}건 표시
          </span>
        </div>
        <VulnTable vulns={filtered} showTool={true} />
      </div>
>>>>>>> origin/nayoung
    </div>
  );
}
