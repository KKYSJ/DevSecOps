import React, { useEffect, useState } from "react";
import api from "../services/api";

const ICONS = {
  ok: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><polyline points="20 6 9 17 4 12" /></svg>,
  fail: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" /></svg>,
  warn: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" /><line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" /></svg>,
  skip: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10" /><line x1="8" y1="12" x2="16" y2="12" /></svg>,
};

const TOOL_PAIRS = {
  SAST: { a: "SonarQube", b: "Semgrep" },
  SCA: { a: "Trivy", b: "Dep-Check" },
  IaC: { a: "tfsec", b: "Checkov" },
  DAST: { a: "OWASP ZAP", b: null },
};

function getBadgeClass(g) { return g === "BLOCK" ? "b-fail" : g === "REVIEW" ? "b-warn" : g === "ALLOW" ? "b-ok" : "b-skip"; }
function getBadgeLabel(g) { return g === "BLOCK" ? "차단" : g === "REVIEW" ? "검토" : g === "ALLOW" ? "통과" : "미실행"; }
function getStatusClass(g) { return g === "BLOCK" ? "ds-fail" : g === "REVIEW" ? "ds-warn" : g === "ALLOW" ? "ds-ok" : "ds-skip"; }
function nodeToGate(n) { return n === "fail" ? "BLOCK" : n === "warn" ? "REVIEW" : n === "ok" ? "ALLOW" : null; }

// API sections can be { SAST: [...] } (array) or { SAST: { rows: [...] } } (object with rows)
function normalizeSections(raw) {
  const out = {};
  Object.entries(raw || {}).forEach(([cat, val]) => {
    if (Array.isArray(val)) out[cat] = { rows: val };
    else if (val && typeof val === "object") out[cat] = { rows: val.rows || [] };
    else out[cat] = { rows: [] };
  });
  return out;
}

function buildSteps(pipeline, crossData) {
  const gate = pipeline?.gate_result || crossData?.gate_decision || null;
  const status = pipeline?.status || "";
  const isBlocked = status === "blocked";
  const sections = normalizeSections(crossData?.sections);
  const steps = [];

  ["IaC", "SAST", "SCA"].forEach((cat) => {
    const sec = sections[cat];
    const hasCrit = sec?.rows?.some((r) => r.severity === "CRITICAL" && r.judgement === "TRUE_POSITIVE");
    const node = sec ? (hasCrit ? "fail" : "ok") : "skip";
    steps.push({ id: cat.toLowerCase(), name: cat === "IaC" ? "IaC 스캔" : cat, sub: TOOL_PAIRS[cat] ? `${TOOL_PAIRS[cat].a} + ${TOOL_PAIRS[cat].b}` : cat, node, category: cat, section: sec });
  });

  steps.push({ id: "cross", name: "교차 검증", sub: "정규화 + 스코어링", node: gate === "BLOCK" ? "fail" : gate === "REVIEW" ? "warn" : gate ? "ok" : "skip", isSummary: true, gate, totalScore: crossData?.total_score, sections });

  const dastSec = sections["DAST"];
  steps.push({ id: "dast", name: "DAST", sub: "OWASP ZAP", node: isBlocked && !dastSec ? "skip" : dastSec ? "ok" : "skip", category: "DAST", section: dastSec });

  return steps;
}

function SummaryDetail({ step }) {
  const { gate, totalScore } = step;
  const sections = normalizeSections(step.sections);
  const cats = ["IaC", "SAST", "SCA", "DAST"];
  return (
    <div className="detail-panel">
      <div className="detail-head">
        <div><div className="detail-title">교차 검증</div><div className="detail-sub">정규화 + 스코어링</div></div>
        <div className={`detail-status ${getStatusClass(gate)}`}>{getBadgeLabel(gate)}</div>
      </div>
      <div className="stat-row">
        <div className="stat-card"><div className="stat-n" style={{ color: gate === "BLOCK" ? "var(--cr)" : gate === "REVIEW" ? "var(--hi)" : "var(--ok)" }}>{getBadgeLabel(gate)}</div><div className="stat-l">판정</div></div>
        <div className="stat-card"><div className="stat-n" style={{ color: "var(--ac)" }}>{totalScore?.toFixed(1) || "0"}</div><div className="stat-l">Total Score</div></div>
      </div>
      <div className="sec-label" style={{ marginTop: 0 }}>단계별 LLM 판정 집계</div>
      <table className="vtbl">
        <thead><tr><th>단계</th><th>도구</th><th>TRUE_POS</th><th>REVIEW</th><th>FALSE_POS</th></tr></thead>
        <tbody>{cats.map((cat) => {
          const rows = (sections[cat]?.rows) || [];
          const tp = rows.filter((r) => r.judgement === "TRUE_POSITIVE").length;
          const rv = rows.filter((r) => r.judgement === "REVIEW_NEEDED").length;
          const fp = rows.filter((r) => r.judgement === "FALSE_POSITIVE").length;
          const p = TOOL_PAIRS[cat];
          return (<tr key={cat}><td><span className={`sev-b cat-${cat.toLowerCase()}`}>{cat}</span></td><td style={{ fontSize: 11, color: "var(--tx2)" }}>{p.b ? `${p.a} + ${p.b}` : p.a}</td><td style={{ fontWeight: 700, fontFamily: "monospace", color: "var(--ok)" }}>{tp}</td><td style={{ fontWeight: 700, fontFamily: "monospace", color: "var(--hi)" }}>{rv}</td><td style={{ fontWeight: 700, fontFamily: "monospace", color: "var(--tx3)" }}>{fp}</td></tr>);
        })}</tbody>
      </table>
    </div>
  );
}

function StepDetail({ step }) {
  const rows = step.section?.rows || [];
  const pair = TOOL_PAIRS[step.category] || {};
  const sev = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  rows.forEach((r) => { if (sev[r.severity] !== undefined) sev[r.severity]++; });

  return (
    <div className="detail-panel">
      <div className="detail-head">
        <div><div className="detail-title">{step.name}</div><div className="detail-sub">{step.sub}</div></div>
        <div className={`detail-status ${getStatusClass(nodeToGate(step.node))}`}>{getBadgeLabel(nodeToGate(step.node))}</div>
      </div>
      <div className="stat-row">
        {Object.entries(sev).map(([k, v]) => (
          <div className="stat-card" key={k}><div className="stat-n" style={{ color: k === "CRITICAL" ? "var(--cr)" : k === "HIGH" ? "var(--hi)" : k === "MEDIUM" ? "var(--ac)" : "var(--tx2)" }}>{v}</div><div className="stat-l">{k}</div></div>
        ))}
      </div>

      {rows.length > 0 && (<>
        <div className="sec-label" style={{ marginTop: 0 }}>교차 검증 결과 — {pair.a || step.category}{pair.b ? ` ↔ ${pair.b}` : ""}</div>
        <div className="cross-head"><span>위치 / 대상</span><span>{pair.a || "Tool A"}</span><span>↔</span><span>{pair.b || "—"}</span><span>결과</span></div>
        {rows.map((r, i) => {
          const fa = r.finding_a || r.tool_a_finding;
          const fb = r.finding_b || r.tool_b_finding;
          const isBoth = fa && fb;
          const label = r.target_label || (fa || fb)?.file_path || r.correlation_key || "—";
          return (
            <div key={i} className={`cross-row-t ${r.severity === "CRITICAL" ? "row-cr" : r.severity === "HIGH" ? "row-hi" : ""}`}>
              <span className="cross-loc">{label}</span>
              <span style={{ fontSize: 11, color: "var(--tx2)" }}>{fa?.title || "— 미탐지"}</span>
              <span className="cross-arrow">↔</span>
              <span style={{ fontSize: 11, color: "var(--tx2)" }}>{fb?.title || "— 미탐지"}</span>
              <span className={`f-match ${isBoth ? "m-both" : "m-single"}`}>{isBoth ? "동시 탐지" : "단독 탐지"}</span>
            </div>
          );
        })}

        <div className={`ai-box ${rows.some((r) => r.severity === "CRITICAL" && r.judgement === "TRUE_POSITIVE") ? "ai-fail" : "ai-ok"}`}>
          <div className="ai-head">
            <span className="ai-chip">LLM 판정</span>
            <span className="ai-verdict">{rows.filter((r) => r.judgement === "TRUE_POSITIVE").length}건 실제 취약점 · {rows.filter((r) => r.judgement === "REVIEW_NEEDED").length}건 검토 필요</span>
          </div>
          {rows.map((r, i) => (
            <div key={i} style={{ display: "flex", alignItems: "flex-start", gap: 10, padding: "8px 0", borderBottom: "1px solid rgba(0,0,0,.06)" }}>
              <span className={`f-sev ${r.judgement === "TRUE_POSITIVE" ? "s-ok" : r.judgement === "FALSE_POSITIVE" ? "s-pu" : "s-ac"}`} style={{ flexShrink: 0, marginTop: 1, whiteSpace: "nowrap" }}>
                {r.judgement === "TRUE_POSITIVE" ? "실제 취약점" : r.judgement === "FALSE_POSITIVE" ? "오탐" : "검토 필요"}
              </span>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: 11, fontFamily: "monospace", color: "var(--tx2)", marginBottom: 2 }}>{r.target_label || (r.finding_a || r.finding_b)?.file_path || r.correlation_key || "—"} · {r.severity}</div>
                <div style={{ fontSize: 11, color: "var(--tx2)", lineHeight: 1.6 }}>{r.reason || r.action_text || (r.finding_b || r.finding_a)?.description || "—"}</div>
                {(r.action || r.action_text) && <div style={{ fontSize: 11, color: "var(--ac)", marginTop: 3, fontWeight: 500 }}>→ {r.action || r.action_text}</div>}
              </div>
            </div>
          ))}
        </div>
      </>)}

      {rows.length === 0 && <div style={{ padding: 20, textAlign: "center", color: "var(--tx3)", fontSize: 12, fontFamily: "monospace" }}>이 단계는 실행되지 않았거나 데이터가 없습니다</div>}
    </div>
  );
}

export default function PipelinePage() {
  const [pipeline, setPipeline] = useState(null);
  const [crossData, setCrossData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeId, setActiveId] = useState(null);

  useEffect(() => {
    Promise.all([
      api.get("/pipelines").catch(() => ({ data: { pipelines: [] } })),
      api.get("/cross").catch(() => ({ data: {} })),
    ]).then(([pRes, cRes]) => {
      const pData = pRes.data;
      const pipelines = Array.isArray(pData) ? pData : (pData.pipelines || []);
      const cross = cRes.data?.dashboard_report || cRes.data || {};
      // Use pipeline from DB, or construct from cross data
      const p = pipelines[0] || (cross.commit_hash ? {
        commit_hash: cross.commit_hash,
        project_name: cross.project_name || "secureflow",
        branch: "nayoung",
        gate_result: cross.gate_decision,
        gate_score: cross.total_score,
        status: cross.gate_decision === "BLOCK" ? "blocked" : "completed",
      } : null);
      setPipeline(p);
      setCrossData(cross);
    }).finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="loading-center">로딩 중...</div>;

  const gate = pipeline?.gate_result || crossData?.gate_decision || null;
  const steps = buildSteps(pipeline, crossData);
  const activeStep = steps.find((s) => s.id === activeId) || null;

  const sevCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0 };
  const normSections = normalizeSections(crossData?.sections);
  Object.values(normSections).forEach((sec) => {
    (sec.rows || []).forEach((r) => {
      if (sevCounts[r.severity] !== undefined) sevCounts[r.severity]++;
    });
  });

  return (
    <div className="pipeline-page" style={{ flex: 1 }}>
      <div className="left-col">
        <div style={{ fontSize: 10, color: "var(--tx3)", fontFamily: "monospace", marginBottom: 14 }}>
          {pipeline ? `${pipeline.branch || "main"} · commit ${(pipeline.commit_hash || "").slice(0, 7)}` : "파이프라인 데이터 없음"}
        </div>

        {gate && (
          <div className={`verdict ${gate === "BLOCK" ? "fail" : gate === "REVIEW" ? "review" : "ok"}`}>
            <div className="verdict-top">
              <div className="verdict-icon">{gate === "BLOCK" ? "✕" : gate === "REVIEW" ? "!" : "✓"}</div>
              <div>
                <div className="verdict-title">{gate === "BLOCK" ? "배포 차단" : gate === "REVIEW" ? "검토 필요" : "배포 완료"}</div>
                <div className="verdict-meta">{gate === "BLOCK" ? "보안 검사 실패" : gate === "REVIEW" ? "일부 항목 검토 필요" : "모든 보안 검사 통과"}</div>
              </div>
            </div>
            <div className="verdict-counts">
              <div className="vc"><span className="vc-n" style={{ color: "var(--cr)" }}>{sevCounts.CRITICAL}</span><span className="vc-l">Critical</span></div>
              <div className="vc"><span className="vc-n" style={{ color: "var(--hi)" }}>{sevCounts.HIGH}</span><span className="vc-l">High</span></div>
              <div className="vc"><span className="vc-n" style={{ color: "var(--ac)" }}>{sevCounts.MEDIUM}</span><span className="vc-l">Medium</span></div>
              <div className="vc"><span className="vc-n" style={{ color: gate === "BLOCK" ? "var(--cr)" : gate === "REVIEW" ? "var(--hi)" : "var(--ok)" }}>{getBadgeLabel(gate)}</span><span className="vc-l" style={{ visibility: "hidden" }}>-</span></div>
            </div>
          </div>
        )}

        <div className="tl-label">DevSecOps 파이프라인</div>
        <div className="timeline">
          {steps.map((s) => (
            <React.Fragment key={s.id}>
              {s.id === "dast" && <div className="phase-bridge">↓ Phase 1 게이트 → Phase 2</div>}
              <div className="tl-item">
                <div className={`tl-node ${s.node}`} onClick={() => setActiveId(s.id)}>{ICONS[s.node] || ICONS.skip}</div>
                <div className="tl-content">
                  <div className={`tl-row${s.id === activeId ? " active" : ""}`} onClick={() => setActiveId(s.id)}>
                    <div><div className="tl-name">{s.name}</div><div className="tl-sub">{s.sub}</div></div>
                    <span className={`tl-badge ${getBadgeClass(nodeToGate(s.node))}`}>{getBadgeLabel(nodeToGate(s.node))}</span>
                  </div>
                </div>
              </div>
            </React.Fragment>
          ))}
        </div>
      </div>

      <div className="right-col">
        {activeStep ? (activeStep.isSummary ? <SummaryDetail step={activeStep} /> : <StepDetail step={activeStep} />) : (
          <div className="detail-empty">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" width="28" height="28" style={{ opacity: 0.25 }}><circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" /></svg>
            <p>파이프라인 단계를 클릭하면<br />상세 정보가 표시됩니다</p>
          </div>
        )}
      </div>
    </div>
  );
}
