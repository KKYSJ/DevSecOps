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

  const gateColor = gate === "BLOCK" ? "var(--cr)" : gate === "REVIEW" ? "var(--hi)" : "var(--ok)";

  return (
    <div className="detail-panel">
      <div className="detail-head">
        <div><div className="detail-title">교차 검증</div><div className="detail-sub">LLM 기반 배포 게이트</div></div>
        <div className={`detail-status ${getStatusClass(gate)}`}>{getBadgeLabel(gate)}</div>
      </div>

      {/* 게이트 판정 + 점수 */}
      <div style={{ display: "flex", gap: 10, marginBottom: 14 }}>
        <div className="stat-card" style={{ flex: 1 }}>
          <div className="stat-n" style={{ color: gateColor }}>{getBadgeLabel(gate)}</div>
          <div className="stat-l">배포 판정</div>
        </div>
        <div className="stat-card" style={{ flex: 1 }}>
          <div className="stat-n" style={{ color: (totalScore || 0) >= 100 ? "var(--cr)" : (totalScore || 0) >= 10 ? "var(--hi)" : "var(--ok)", fontFamily: "monospace" }}>
            {typeof totalScore === "number" ? totalScore.toFixed(1) : "0"}
          </div>
          <div className="stat-l">위험도 점수</div>
        </div>
      </div>

      {/* ── LLM이 필요한 이유 ── */}
      <div style={{ background: "var(--bg)", border: "1px solid var(--bd)", borderRadius: 8, padding: "12px 14px", marginBottom: 14 }}>
        <div style={{ fontSize: 10, fontWeight: 700, fontFamily: "var(--mono)", color: "var(--ac)", textTransform: "uppercase", letterSpacing: ".06em", marginBottom: 8 }}>
          왜 LLM 교차검증인가?
        </div>
        <div style={{ display: "flex", gap: 8, marginBottom: 8 }}>
          <div style={{ flex: 1, background: "var(--cr-bg)", border: "1px solid var(--cr-bd)", borderRadius: 6, padding: "8px 10px" }}>
            <div style={{ fontSize: 10, fontWeight: 700, color: "var(--cr)", marginBottom: 3 }}>두 도구 동시 탐지</div>
            <div style={{ fontSize: 10, color: "var(--tx2)", lineHeight: 1.5 }}>실제 취약점 가능성 높음<br/>LLM → TRUE_POSITIVE 판정<br/>점수 전액 반영</div>
          </div>
          <div style={{ display: "flex", alignItems: "center", color: "var(--tx3)", fontSize: 13 }}>vs</div>
          <div style={{ flex: 1, background: "var(--hi-bg)", border: "1px solid var(--hi-bd)", borderRadius: 6, padding: "8px 10px" }}>
            <div style={{ fontSize: 10, fontWeight: 700, color: "var(--hi)", marginBottom: 3 }}>한 도구만 탐지</div>
            <div style={{ fontSize: 10, color: "var(--tx2)", lineHeight: 1.5 }}>오탐 가능성 있음<br/>LLM → REVIEW_NEEDED 판정<br/>점수 50% 반영</div>
          </div>
        </div>
        <div style={{ fontSize: 10, color: "var(--tx3)", lineHeight: 1.5 }}>
          도구 1개만 쓰면 오탐·미탐이 많아 신뢰하기 어렵습니다. 두 도구가 독립적으로 같은 취약점을 탐지했을 때 LLM이 최종 확인하여 보안 담당자가 봐야 할 항목을 크게 줄여줍니다.
        </div>
      </div>

      {/* ── 스코어링 기준 ── */}
      <div style={{ background: "var(--bg)", border: "1px solid var(--bd)", borderRadius: 8, padding: "12px 14px", marginBottom: 14 }}>
        <div style={{ fontSize: 10, fontWeight: 700, fontFamily: "var(--mono)", color: "var(--tx3)", textTransform: "uppercase", letterSpacing: ".06em", marginBottom: 8 }}>
          스코어링 기준
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 6, marginBottom: 10 }}>
          {[
            { label: "Critical × TRUE_POS", score: "100점", color: "var(--cr)", bg: "var(--cr-bg)", bd: "var(--cr-bd)" },
            { label: "High × TRUE_POS", score: "10점", color: "var(--hi)", bg: "var(--hi-bg)", bd: "var(--hi-bd)" },
            { label: "Medium × TRUE_POS", score: "1점", color: "var(--ac)", bg: "var(--ac-bg)", bd: "var(--ac-bd)" },
          ].map(({ label, score, color, bg, bd }) => (
            <div key={label} style={{ background: bg, border: `1px solid ${bd}`, borderRadius: 6, padding: "6px 8px", textAlign: "center" }}>
              <div style={{ fontSize: 14, fontWeight: 700, color, fontFamily: "var(--mono)" }}>{score}</div>
              <div style={{ fontSize: 9, color: "var(--tx3)", marginTop: 2 }}>{label}</div>
            </div>
          ))}
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 6 }}>
          {[
            { gate: "BLOCK", cond: "≥ 100점 또는 Critical 1건", color: "var(--cr)", bg: "var(--cr-bg)" },
            { gate: "REVIEW", cond: "≥ 10점 (High 1건)", color: "var(--hi)", bg: "var(--hi-bg)" },
            { gate: "ALLOW", cond: "< 10점", color: "var(--ok)", bg: "var(--ok-bg)" },
          ].map(({ gate: g, cond, color, bg }) => (
            <div key={g} style={{ background: bg, borderRadius: 6, padding: "5px 8px" }}>
              <div style={{ fontSize: 10, fontWeight: 700, color, fontFamily: "var(--mono)" }}>{g}</div>
              <div style={{ fontSize: 9, color: "var(--tx3)", marginTop: 1 }}>{cond}</div>
            </div>
          ))}
        </div>
      </div>

      {/* ── 단계별 LLM 판정 집계 ── */}
      <div className="sec-label" style={{ marginTop: 0 }}>단계별 LLM 판정 집계</div>
      <table className="vtbl">
        <thead><tr><th>단계</th><th>도구 쌍</th><th style={{ color: "var(--cr)" }}>실제 취약점</th><th style={{ color: "var(--hi)" }}>검토 필요</th><th style={{ color: "var(--tx3)" }}>오탐 제거</th></tr></thead>
        <tbody>{cats.map((cat) => {
          const rows = (sections[cat]?.rows) || [];
          const tp = rows.filter((r) => (r.judgement_code || r.judgement) === "TRUE_POSITIVE").length;
          const rv = rows.filter((r) => (r.judgement_code || r.judgement) === "REVIEW_NEEDED").length;
          const fp = rows.filter((r) => (r.judgement_code || r.judgement) === "FALSE_POSITIVE").length;
          const p = TOOL_PAIRS[cat];
          const bothDetect = rows.filter((r) => r.tool_a?.status === "detected" && r.tool_b?.status === "detected").length;
          return (
            <tr key={cat}>
              <td><span className={`sev-b cat-${cat.toLowerCase()}`}>{cat}</span></td>
              <td style={{ fontSize: 10, color: "var(--tx2)" }}>
                {p.b ? `${p.a} + ${p.b}` : p.a}
                {bothDetect > 0 && <span style={{ marginLeft: 4, fontSize: 9, color: "var(--cr)", fontWeight: 700 }}>동시{bothDetect}건</span>}
              </td>
              <td style={{ fontWeight: 700, fontFamily: "monospace", color: tp > 0 ? "var(--cr)" : "var(--tx3)" }}>{tp}</td>
              <td style={{ fontWeight: 700, fontFamily: "monospace", color: rv > 0 ? "var(--hi)" : "var(--tx3)" }}>{rv}</td>
              <td style={{ fontWeight: 700, fontFamily: "monospace", color: "var(--tx3)" }}>{fp}</td>
            </tr>
          );
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
        <CrossTableWithLlm rows={rows} pair={pair} />
      </>)}

      {rows.length === 0 && <div style={{ padding: 20, textAlign: "center", color: "var(--tx3)", fontSize: 12, fontFamily: "monospace" }}>이 단계는 실행되지 않았거나 데이터가 없습니다</div>}
    </div>
  );
}

function CrossTableWithLlm({ rows, pair }) {
  const [openIdx, setOpenIdx] = React.useState(null);

  return (
    <>
      <div className="cross-head"><span>위치 / 대상</span><span>{pair.a || "Tool A"}</span><span>↔</span><span>{pair.b || "—"}</span><span>결과</span></div>
      {rows.map((r, i) => {
        const fa = r.finding_a || r.tool_a_finding;
        const fb = r.finding_b || r.tool_b_finding;
        const isBoth = fa && fb;
        const label = r.target_label || (fa || fb)?.file_path || r.correlation_key || "—";
        const isOpen = openIdx === i;
        const jud = r.judgement_code || r.judgement || "REVIEW_NEEDED";
        const judColor = jud === "TRUE_POSITIVE" ? "var(--cr)" : jud === "FALSE_POSITIVE" ? "var(--ok)" : "var(--hi)";
        const judBg = jud === "TRUE_POSITIVE" ? "var(--cr-bg)" : jud === "FALSE_POSITIVE" ? "var(--ok-bg)" : "var(--hi-bg)";
        const judLabel = jud === "TRUE_POSITIVE" ? "실제 취약점" : jud === "FALSE_POSITIVE" ? "오탐" : "검토 필요";

        return (
          <React.Fragment key={i}>
            <div
              className={`cross-row-t ${r.severity === "CRITICAL" ? "row-cr" : r.severity === "HIGH" ? "row-hi" : ""}`}
              onClick={() => setOpenIdx(isOpen ? null : i)}
              style={{ cursor: "pointer" }}
            >
              <span className="cross-loc">{label}</span>
              <span style={{ fontSize: 11, color: "var(--tx2)" }}>{fa?.title ? (fa.title.length > 40 ? fa.title.slice(0, 40) + "..." : fa.title) : "— 미탐지"}</span>
              <span className="cross-arrow">↔</span>
              <span style={{ fontSize: 11, color: "var(--tx2)" }}>{fb?.title ? (fb.title.length > 40 ? fb.title.slice(0, 40) + "..." : fb.title) : "— 미탐지"}</span>
              <span className={`f-match ${isBoth ? "m-both" : "m-single"}`}>{isBoth ? "동시 탐지" : "단독 탐지"}</span>
            </div>

            {isOpen && (
              <div style={{ border: "1px solid var(--bd)", borderTop: "none", borderLeft: `3px solid ${judColor}`, background: judBg, padding: "14px 16px", animation: "fadeUp .15s ease" }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
                  <span style={{ fontSize: 10, fontWeight: 700, fontFamily: "var(--mono)", padding: "2px 8px", borderRadius: 4, background: judColor, color: "#fff" }}>{judLabel}</span>
                  <span className={`sev-b ${r.severity === "CRITICAL" ? "s-cr" : r.severity === "HIGH" ? "s-hi" : r.severity === "MEDIUM" ? "s-ac" : "s-ok"}`}>{r.severity}</span>
                  <span style={{ fontSize: 11, fontFamily: "var(--mono)", color: "var(--tx3)" }}>{r.confidence_level || r.confidence || ""}</span>
                  <span style={{ marginLeft: "auto", fontSize: 12, fontWeight: 700, fontFamily: "var(--mono)", color: (r.row_score || 0) >= 50 ? "var(--cr)" : "var(--tx2)" }}>
                    {typeof r.row_score === "number" ? r.row_score.toFixed(1) + "점" : ""}
                  </span>
                </div>
                {r.title_ko && <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 8 }}>{r.title_ko}</div>}
                {r.risk_summary && <div style={{ fontSize: 12, color: "var(--tx)", lineHeight: 1.7, marginBottom: 8 }}>{r.risk_summary}</div>}
                {r.reason && <div style={{ fontSize: 12, color: "var(--tx2)", lineHeight: 1.7, marginBottom: 8 }}>{r.reason}</div>}
                {(r.action || r.action_text) && (
                  <div style={{ fontSize: 12, color: "var(--ac)", fontWeight: 500, padding: "8px 12px", background: "rgba(255,255,255,.6)", borderRadius: 6, border: "1px solid var(--ac-bd)" }}>
                    → {r.action || r.action_text}
                  </div>
                )}
                {!r.risk_summary && !r.reason && !r.action_text && <div style={{ fontSize: 12, color: "var(--tx3)" }}>LLM 분석 결과가 없습니다.</div>}
              </div>
            )}
          </React.Fragment>
        );
      })}
    </>
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
