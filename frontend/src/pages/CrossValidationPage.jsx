import React, { useState, useEffect } from "react";
import api from "../services/api";

const CAT_TOOLS = { SAST: "SonarQube ↔ Semgrep", SCA: "Trivy ↔ Dep-Check", IaC: "tfsec ↔ Checkov", DAST: "OWASP ZAP" };

export default function CrossValidationPage() {
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState(null);

  useEffect(() => {
    api.get("/cross")
      .then((res) => {
        const d = res.data?.dashboard_report || res.data || {};
        setReport(d);
        const cats = Object.keys(d.sections || {});
        if (cats.length > 0) setActiveTab(cats[0]);
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="loading-center">로딩 중...</div>;

  const dr = report || {};
  const cards = dr.summary_cards || dr.summary || {};
  const rawSections = dr.sections || {};
  // Normalize: sections can be { SAST: [...] } or { SAST: { rows: [...] } }
  const sections = {};
  Object.entries(rawSections).forEach(([cat, val]) => {
    sections[cat] = Array.isArray(val) ? val : (val?.rows || []);
  });
  const gate = (cards.gate_decision || dr.gate_decision || "—").toUpperCase();
  const totalScore = cards.total_score ?? dr.total_score ?? 0;
  const catKeys = Object.keys(sections);
  const rows = sections[activeTab] || [];

  const gateClass = gate === "BLOCK" ? "fail" : gate === "REVIEW" ? "review" : "ok";

  return (
    <div className="full-page">
      <div className="page-head">
        <h2>교차 검증 결과</h2>
        <p>다중 보안 도구 교차 검증 리포트 — Gemini LLM 분석</p>
      </div>

      {/* Gate Banner */}
      <div className={`verdict ${gateClass}`} style={{ marginBottom: 20 }}>
        <div className="verdict-top">
          <div className="verdict-icon">{gate === "BLOCK" ? "✕" : gate === "REVIEW" ? "!" : "✓"}</div>
          <div>
            <div className="verdict-title">배포 판정: {gate}</div>
            <div className="verdict-meta">총점: {typeof totalScore === "number" ? totalScore.toFixed(1) : totalScore}</div>
          </div>
        </div>
        <div className="verdict-counts">
          <div className="vc"><span className="vc-n" style={{ color: "var(--cr)" }}>{cards.critical_count || cards.by_severity?.CRITICAL || 0}</span><span className="vc-l">Critical</span></div>
          <div className="vc"><span className="vc-n" style={{ color: "var(--hi)" }}>{cards.high_count || cards.by_severity?.HIGH || 0}</span><span className="vc-l">High</span></div>
          <div className="vc"><span className="vc-n" style={{ color: "var(--ac)" }}>{cards.medium_count || cards.by_severity?.MEDIUM || 0}</span><span className="vc-l">Medium</span></div>
          <div className="vc"><span className="vc-n">{cards.low_count || cards.by_severity?.LOW || 0}</span><span className="vc-l">Low</span></div>
        </div>
      </div>

      {/* Category Tabs */}
      <div className="filter-row">
        {catKeys.map((cat) => (
          <span key={cat} className={`filter-chip${activeTab === cat ? " active" : ""}`} onClick={() => setActiveTab(cat)}>
            {cat} ({(sections[cat] || []).length})
          </span>
        ))}
      </div>

      {catKeys.length === 0 && <div style={{ padding: 40, textAlign: "center", color: "var(--tx3)" }}>교차 검증 데이터가 없습니다</div>}

      {activeTab && rows.length > 0 && (
        <>
          <div className="sec-label" style={{ marginTop: 0 }}>{activeTab} — {CAT_TOOLS[activeTab] || activeTab}</div>
          <table className="vtbl">
            <thead>
              <tr><th>대상</th><th>심각도</th><th>판정</th><th>신뢰도</th><th>점수</th><th>근거</th><th>조치</th></tr>
            </thead>
            <tbody>
              {rows.map((r, i) => {
                const sevCls = r.severity === "CRITICAL" ? "s-cr" : r.severity === "HIGH" ? "s-hi" : r.severity === "MEDIUM" ? "s-ac" : "s-ok";
                const jud = r.judgement || r.judgement_code || "";
                const judCls = jud === "TRUE_POSITIVE" ? "s-cr" : jud === "FALSE_POSITIVE" ? "s-pu" : "s-ac";
                const judLabel = jud.replace("_", " ") || "REVIEW";
                const label = r.target_label || (r.finding_a || r.finding_b)?.file_path || r.correlation_key || "—";
                return (
                  <tr key={r.row_id || i} style={{ borderLeft: r.severity === "CRITICAL" ? "3px solid var(--cr)" : r.severity === "HIGH" ? "3px solid var(--hi)" : "none" }}>
                    <td><code>{label}</code></td>
                    <td><span className={`sev-b ${sevCls}`}>{r.severity}</span></td>
                    <td><span className={`sev-b ${judCls}`}>{judLabel}</span></td>
                    <td><span className="sev-b s-ac">{r.confidence_level || r.confidence || "—"}</span></td>
                    <td style={{ fontFamily: "monospace", fontWeight: 700, color: (r.row_score || 0) >= 50 ? "var(--cr)" : "var(--tx2)" }}>{typeof r.row_score === "number" ? r.row_score.toFixed(1) : "—"}</td>
                    <td style={{ fontSize: 11, color: "var(--tx2)", maxWidth: 250 }}>{r.reason || "—"}</td>
                    <td style={{ fontSize: 11, color: "var(--ac)", maxWidth: 200 }}>{r.action || r.action_text || "—"}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </>
      )}

      {activeTab && rows.length === 0 && <div style={{ padding: 20, textAlign: "center", color: "var(--tx3)", fontFamily: "monospace" }}>이 카테고리에 데이터가 없습니다</div>}
    </div>
  );
}
