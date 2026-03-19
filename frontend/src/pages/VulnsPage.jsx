import React, { useState, useEffect } from "react";
import api from "../services/api";

const SEV_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };

export default function VulnsPage() {
  const [vulns, setVulns] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState("ALL");

  useEffect(() => {
    api.get("/vulns")
      .then((res) => setVulns(Array.isArray(res.data) ? res.data : (res.data.vulnerabilities || [])))
      .catch(() => setVulns([]))
      .finally(() => setLoading(false));
  }, []);

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
    </div>
  );
}