import React, { useState, useEffect } from "react";
import api from "../services/api";

const CAT_TOOLS = { SAST: ["SonarQube", "Semgrep"], SCA: ["Trivy", "Dep-Check"], IaC: ["tfsec", "Checkov"], DAST: ["OWASP ZAP"] };
const CAT_LABELS = { SAST: "SonarQube ↔ Semgrep", SCA: "Trivy ↔ Dep-Check", IaC: "tfsec ↔ Checkov", DAST: "OWASP ZAP" };

export default function CrossValidationPage() {
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState(null);
  const [expandedId, setExpandedId] = useState(null);

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
  const sections = {};
  Object.entries(rawSections).forEach(([cat, val]) => {
    sections[cat] = Array.isArray(val) ? val : (val?.rows || []);
  });
  const gate = (cards.gate_decision || dr.gate_decision || "—").toUpperCase();
  const totalScore = cards.total_score ?? dr.total_score ?? 0;
  const catKeys = Object.keys(sections);
  const rows = sections[activeTab] || [];
  const gateClass = gate === "BLOCK" ? "fail" : gate === "REVIEW" ? "review" : "ok";

  const allRows = Object.values(sections).flat();
  const truePos = allRows.filter(r => (r.judgement_code || r.judgement) === "TRUE_POSITIVE").length;
  const reviewNeeded = allRows.filter(r => (r.judgement_code || r.judgement) === "REVIEW_NEEDED").length;
  const falsePos = allRows.filter(r => (r.judgement_code || r.judgement) === "FALSE_POSITIVE").length;

  return (
    <div className="full-page">
      <div className="page-head">
        <h2>교차 검증 결과</h2>
        <p>다중 보안 도구 교차 검증 리포트 — Gemini LLM 분석</p>
      </div>

      {/* ── LLM 목적 설명 배너 ── */}
      <div style={{ background: "var(--bg)", border: "1px solid var(--bd)", borderRadius: 8, padding: "14px 16px", marginBottom: 16 }}>
        <div style={{ fontSize: 10, fontWeight: 700, fontFamily: "var(--mono)", color: "var(--ac)", textTransform: "uppercase", letterSpacing: ".08em", marginBottom: 10 }}>
          Gemini LLM 교차검증이란?
        </div>
        <div style={{ display: "flex", gap: 8, marginBottom: 10 }}>
          <div style={{ flex: 1, background: "var(--cr-bg)", border: "1px solid var(--cr-bd)", borderRadius: 6, padding: "10px 12px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 4 }}>
              <span style={{ fontSize: 11, fontWeight: 700, color: "var(--cr)", fontFamily: "var(--mono)" }}>동시 탐지</span>
              <span style={{ fontSize: 9, background: "var(--cr)", color: "#fff", borderRadius: 3, padding: "1px 5px" }}>TRUE_POSITIVE</span>
            </div>
            <div style={{ fontSize: 10, color: "var(--tx2)", lineHeight: 1.6 }}>
              두 도구가 독립적으로 같은 취약점을 발견했을 때.<br/>
              LLM이 최종 확인 → <strong>실제 취약점</strong>으로 판정.<br/>
              점수 100% 반영, 보안 담당자 즉시 조치 필요.
            </div>
          </div>
          <div style={{ flex: 1, background: "var(--hi-bg)", border: "1px solid var(--hi-bd)", borderRadius: 6, padding: "10px 12px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 4 }}>
              <span style={{ fontSize: 11, fontWeight: 700, color: "var(--hi)", fontFamily: "var(--mono)" }}>단독 탐지</span>
              <span style={{ fontSize: 9, background: "var(--hi)", color: "#fff", borderRadius: 3, padding: "1px 5px" }}>REVIEW_NEEDED</span>
            </div>
            <div style={{ fontSize: 10, color: "var(--tx2)", lineHeight: 1.6 }}>
              한 도구만 발견했을 때 — 오탐 가능성 있음.<br/>
              LLM이 맥락 분석 → 검토 필요로 분류.<br/>
              점수 50% 반영, 보안 담당자 확인 후 판단.
            </div>
          </div>
          <div style={{ flex: 1, background: "var(--ok-bg)", border: "1px solid var(--ok-bd)", borderRadius: 6, padding: "10px 12px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 4 }}>
              <span style={{ fontSize: 11, fontWeight: 700, color: "var(--ok)", fontFamily: "var(--mono)" }}>오탐 제거</span>
              <span style={{ fontSize: 9, background: "var(--ok)", color: "#fff", borderRadius: 3, padding: "1px 5px" }}>FALSE_POSITIVE</span>
            </div>
            <div style={{ fontSize: 10, color: "var(--tx2)", lineHeight: 1.6 }}>
              LLM이 분석 후 실제 위험이 없다고 판단.<br/>
              점수 0점. 보안 담당자가 볼 필요 없음.<br/>
              도구 단독으로는 걸러내지 못했던 노이즈.
            </div>
          </div>
        </div>
        <div style={{ display: "flex", gap: 12, padding: "8px 10px", background: "var(--sf)", borderRadius: 6, fontSize: 10, color: "var(--tx3)" }}>
          <span>스코어링:</span>
          <span style={{ color: "var(--cr)", fontWeight: 700 }}>Critical×100</span>
          <span style={{ color: "var(--hi)", fontWeight: 700 }}>High×10</span>
          <span style={{ color: "var(--ac)", fontWeight: 700 }}>Medium×1</span>
          <span style={{ margin: "0 4px", color: "var(--bd)" }}>|</span>
          <span style={{ color: "var(--cr)" }}>BLOCK ≥100점 또는 Critical 1건</span>
          <span style={{ color: "var(--hi)" }}>REVIEW ≥10점</span>
          <span style={{ color: "var(--ok)" }}>ALLOW &lt;10점</span>
        </div>
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
          <div className="vc"><span className="vc-n" style={{ color: "var(--cr)" }}>{cards.by_severity?.CRITICAL || 0}</span><span className="vc-l">Critical</span></div>
          <div className="vc"><span className="vc-n" style={{ color: "var(--hi)" }}>{cards.by_severity?.HIGH || 0}</span><span className="vc-l">High</span></div>
          <div className="vc"><span className="vc-n" style={{ color: "var(--ac)" }}>{cards.by_severity?.MEDIUM || 0}</span><span className="vc-l">Medium</span></div>
          <div className="vc"><span className="vc-n">{cards.by_severity?.LOW || 0}</span><span className="vc-l">Low</span></div>
        </div>
      </div>

      {/* 판정 요약 */}
      <div style={{ display: "flex", gap: 12, marginBottom: 20 }}>
        <SummaryCard color="cr" count={truePos} label="실제 취약점" />
        <SummaryCard color="hi" count={reviewNeeded} label="검토 필요" />
        <SummaryCard color="ok" count={falsePos} label="오탐 제거" />
        <SummaryCard color="tx" count={allRows.length} label="전체 항목" border />
      </div>

      {/* Category Tabs */}
      <div className="filter-row">
        {catKeys.map((cat) => (
          <span key={cat} className={`filter-chip${activeTab === cat ? " active" : ""}`} onClick={() => { setActiveTab(cat); setExpandedId(null); }}>
            {cat} ({(sections[cat] || []).length})
          </span>
        ))}
      </div>

      {catKeys.length === 0 && <Empty msg="교차 검증 데이터가 없습니다" />}

      {activeTab && rows.length > 0 && (
        <>
          <div className="sec-label" style={{ marginTop: 0 }}>{activeTab} — {CAT_LABELS[activeTab] || activeTab}</div>

          {/* 테이블 헤더 */}
          <div style={{ display: "grid", gridTemplateColumns: "40px 1fr 80px 90px 70px 60px", gap: 8, padding: "8px 16px", background: "var(--bg)", borderRadius: "8px 8px 0 0", border: "1px solid var(--bd)", borderBottom: "none", fontSize: 10, fontFamily: "var(--mono)", color: "var(--tx3)", textTransform: "uppercase", letterSpacing: ".06em" }}>
            <span>#</span><span>취약점</span><span>심각도</span><span>판정</span><span>점수</span><span></span>
          </div>

          {rows.map((r, i) => {
            const id = r.row_id || i;
            const isOpen = expandedId === id;
            const jud = r.judgement_code || r.judgement || "REVIEW_NEEDED";
            const judColor = jud === "TRUE_POSITIVE" ? "var(--cr)" : jud === "FALSE_POSITIVE" ? "var(--ok)" : "var(--hi)";
            const judBg = jud === "TRUE_POSITIVE" ? "var(--cr-bg)" : jud === "FALSE_POSITIVE" ? "var(--ok-bg)" : "var(--hi-bg)";
            const judLabel = jud === "TRUE_POSITIVE" ? "실제 취약점" : jud === "FALSE_POSITIVE" ? "오탐" : "검토 필요";
            const sevCls = r.severity === "CRITICAL" ? "s-cr" : r.severity === "HIGH" ? "s-hi" : r.severity === "MEDIUM" ? "s-ac" : "s-ok";

            const title = r.title_ko || (r.finding_a || r.finding_b)?.title || r.target_label || r.correlation_key || "—";
            const shortTitle = title.length > 70 ? title.slice(0, 70) + "..." : title;

            return (
              <div key={id}>
                {/* 요약 행 (클릭 가능) */}
                <div
                  onClick={() => setExpandedId(isOpen ? null : id)}
                  style={{
                    display: "grid", gridTemplateColumns: "40px 1fr 80px 90px 70px 60px", gap: 8,
                    padding: "12px 16px", background: "var(--sf)", border: "1px solid var(--bd)", borderTop: "none",
                    borderLeft: `3px solid ${judColor}`, cursor: "pointer", alignItems: "center",
                    transition: "background .1s",
                  }}
                  onMouseEnter={e => e.currentTarget.style.background = "var(--bg)"}
                  onMouseLeave={e => e.currentTarget.style.background = "var(--sf)"}
                >
                  <span style={{ fontSize: 12, fontWeight: 700, color: "var(--tx3)", fontFamily: "var(--mono)" }}>{i + 1}</span>
                  <span style={{ fontSize: 12, fontWeight: 500, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{shortTitle}</span>
                  <span><span className={`sev-b ${sevCls}`}>{r.severity}</span></span>
                  <span style={{ fontSize: 10, fontWeight: 700, fontFamily: "var(--mono)", padding: "3px 8px", borderRadius: 4, background: judBg, color: judColor, textAlign: "center" }}>{judLabel}</span>
                  <span style={{ fontSize: 12, fontWeight: 700, fontFamily: "var(--mono)", color: (r.row_score || 0) >= 50 ? "var(--cr)" : "var(--tx2)" }}>{typeof r.row_score === "number" ? r.row_score.toFixed(1) : "—"}</span>
                  <span style={{ fontSize: 11, color: "var(--tx3)" }}>{isOpen ? "▲" : "▼"}</span>
                </div>

                {/* 펼쳐지는 상세 패널 */}
                {isOpen && <DetailPanel r={r} activeTab={activeTab} />}
              </div>
            );
          })}
        </>
      )}

      {activeTab && rows.length === 0 && <Empty msg="이 카테고리에 데이터가 없습니다" />}
    </div>
  );
}

function SummaryCard({ color, count, label, border }) {
  const bg = border ? "var(--bg)" : `var(--${color}-bg)`;
  const bd = border ? "var(--bd)" : `var(--${color}-bd)`;
  const cl = border ? "var(--tx)" : `var(--${color})`;
  return (
    <div style={{ flex: 1, background: bg, border: `1px solid ${bd}`, borderRadius: 8, padding: "14px 18px", textAlign: "center" }}>
      <div style={{ fontSize: 24, fontWeight: 700, color: cl, fontFamily: "var(--mono)" }}>{count}</div>
      <div style={{ fontSize: 11, color: "var(--tx2)" }}>{label}</div>
    </div>
  );
}

function DetailPanel({ r, activeTab }) {
  const tools = CAT_TOOLS[activeTab] || ["도구A", "도구B"];
  const risk = r.risk_summary || "";
  const reason = r.reason || "";
  const action = r.action_text || r.action || "";
  const jud = r.judgement_code || r.judgement || "REVIEW_NEEDED";
  const judColor = jud === "TRUE_POSITIVE" ? "var(--cr)" : jud === "FALSE_POSITIVE" ? "var(--ok)" : "var(--hi)";
  const judBg = jud === "TRUE_POSITIVE" ? "var(--cr-bg)" : jud === "FALSE_POSITIVE" ? "var(--ok-bg)" : "var(--hi-bg)";

  const hasA = r.finding_a != null;
  const hasB = r.finding_b != null;
  const isBoth = hasA && hasB;
  const isDAST = activeTab === "DAST";

  // 단독 탐지 시 어느 도구가 잡았는지
  const detectedTool = hasA ? tools[0] : tools[1];
  const missedTool = hasA ? tools[1] : tools[0];
  const detectedFinding = hasA ? r.finding_a : r.finding_b;

  return (
    <div style={{ border: "1px solid var(--bd)", borderTop: "none", background: "var(--sf)", padding: "16px 20px 20px", animation: "fadeUp .15s ease" }}>

      {/* ── 교차검증 상태 헤더 ── */}
      {!isDAST && (
        <div style={{
          display: "flex", alignItems: "center", gap: 8, marginBottom: 14,
          padding: "8px 12px", borderRadius: 6,
          background: isBoth ? "var(--cr-bg)" : "var(--hi-bg)",
          border: `1px solid ${isBoth ? "var(--cr-bd)" : "var(--hi-bd)"}`,
        }}>
          <span style={{ fontSize: 16 }}>{isBoth ? "⚠" : "?"}</span>
          <div>
            <div style={{ fontSize: 11, fontWeight: 700, color: isBoth ? "var(--cr)" : "var(--hi)" }}>
              {isBoth
                ? `두 도구 동시 탐지 — ${tools[0]} + ${tools[1]}`
                : `단독 탐지 — ${detectedTool}만 발견, ${missedTool}는 미탐지`}
            </div>
            <div style={{ fontSize: 10, color: "var(--tx3)", marginTop: 2 }}>
              {isBoth
                ? "독립된 두 도구가 같은 취약점을 발견 → LLM이 실제 취약점으로 판정"
                : `${missedTool}가 이 항목을 탐지하지 못했습니다 → LLM이 오탐 가능성을 판단해 검토 필요로 분류`}
            </div>
          </div>
        </div>
      )}

      {/* ── 도구 비교 ── */}
      <div style={{ fontSize: 10, fontFamily: "var(--mono)", color: "var(--tx3)", textTransform: "uppercase", letterSpacing: ".06em", marginBottom: 8 }}>도구 탐지 결과</div>
      <div style={{ display: "flex", gap: 8, marginBottom: 14 }}>
        <ToolBox name={tools[0]} finding={r.finding_a} />
        {!isDAST && (
          <>
            <div style={{ display: "flex", alignItems: "center", color: "var(--tx3)", fontSize: 13 }}>↔</div>
            <ToolBox name={tools[1]} finding={r.finding_b} />
          </>
        )}
      </div>

      {/* ── LLM 판정 결과 ── */}
      <div style={{ fontSize: 10, fontFamily: "var(--mono)", color: "var(--tx3)", textTransform: "uppercase", letterSpacing: ".06em", marginBottom: 8 }}>
        Gemini LLM 판정
        {!isBoth && !isDAST && (
          <span style={{ marginLeft: 6, fontSize: 9, fontWeight: 700, color: "var(--hi)", textTransform: "none" }}>
            — 단독 탐지이므로 교차 검증 불가, 오탐 여부 분석
          </span>
        )}
      </div>
      <div style={{ background: judBg, border: `1px solid ${judColor}30`, borderRadius: 8, padding: "14px 16px" }}>
        {/* 단독 탐지일 때: 원문 타이틀이 아니라 LLM이 뭘 봤는지 명시 */}
        {!isBoth && !isDAST && detectedFinding && (
          <div style={{ marginBottom: 10, padding: "6px 10px", background: "rgba(0,0,0,.03)", borderRadius: 6, border: "1px solid var(--bd)" }}>
            <div style={{ fontSize: 9, fontFamily: "var(--mono)", color: "var(--tx3)", marginBottom: 3 }}>{detectedTool} 원문 탐지 내용</div>
            <div style={{ fontSize: 11, color: "var(--tx2)" }}>{detectedFinding.title || detectedFinding.rule_id || "—"}</div>
            {detectedFinding.file_path && (
              <div style={{ fontSize: 10, color: "var(--tx3)", marginTop: 2, fontFamily: "var(--mono)" }}>
                {detectedFinding.file_path}{detectedFinding.line_number ? `:${detectedFinding.line_number}` : ""}
              </div>
            )}
            <div style={{ marginTop: 4, fontSize: 9, color: "var(--hi)", fontWeight: 700 }}>
              ↑ {missedTool}에서 같은 취약점을 확인하지 못해 교차검증 불가 → LLM 단독 분석
            </div>
          </div>
        )}

        {risk && (
          <div style={{ fontSize: 13, fontWeight: 600, color: judColor, marginBottom: 8, lineHeight: 1.6 }}>
            {risk}
          </div>
        )}
        {reason && (
          <div style={{ fontSize: 12, color: "var(--tx2)", lineHeight: 1.7, marginBottom: 8 }}>
            {reason}
          </div>
        )}
        {action && (
          <div style={{ fontSize: 12, color: "var(--ac)", fontWeight: 500, lineHeight: 1.6, padding: "8px 12px", background: "var(--ac-bg)", borderRadius: 6, border: "1px solid var(--ac-bd)" }}>
            → {action}
          </div>
        )}
        {!risk && !reason && !action && (
          <div style={{ fontSize: 12, color: "var(--tx3)" }}>LLM 분석 결과가 없습니다.</div>
        )}
      </div>
    </div>
  );
}

function ToolBox({ name, finding }) {
  const detected = finding != null;
  const sev = finding?.severity || "";
  const title = finding?.title || finding?.rule_id || "";
  const shortTitle = title.length > 55 ? title.slice(0, 55) + "..." : title;
  const cwe = finding?.cwe_id || "";
  const cve = finding?.cve_id || "";

  return (
    <div style={{
      flex: 1, padding: "10px 14px", background: "var(--bg)", borderRadius: 8,
      borderLeft: detected ? "3px solid var(--cr)" : "3px solid var(--bd)",
      opacity: detected ? 1 : 0.55,
    }}>
      <div style={{ fontSize: 11, fontWeight: 700, marginBottom: 5 }}>{name}</div>
      {detected ? (
        <>
          <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 4 }}>
            {sev && <span className={`sev-b ${sev === "CRITICAL" ? "s-cr" : sev === "HIGH" ? "s-hi" : sev === "MEDIUM" ? "s-ac" : "s-ok"}`}>{sev}</span>}
            <span style={{ fontSize: 10, fontWeight: 700, color: "var(--cr)" }}>탐지됨</span>
          </div>
          {shortTitle && <div style={{ fontSize: 10, color: "var(--tx2)", lineHeight: 1.5 }}>{shortTitle}</div>}
          {(cwe || cve) && (
            <div style={{ marginTop: 4, fontSize: 9, fontFamily: "var(--mono)", color: "var(--tx3)" }}>
              {cwe && <span style={{ marginRight: 6 }}>{cwe}</span>}
              {cve && <span>{cve}</span>}
            </div>
          )}
        </>
      ) : (
        <>
          <div style={{ fontSize: 10, fontWeight: 700, color: "var(--tx3)" }}>미탐지</div>
          <div style={{ fontSize: 9, color: "var(--tx3)", marginTop: 3, lineHeight: 1.4 }}>이 도구는 해당 위치에서<br/>취약점을 발견하지 못함</div>
        </>
      )}
    </div>
  );
}

function Empty({ msg }) {
  return <div style={{ padding: 40, textAlign: "center", color: "var(--tx3)", fontFamily: "monospace" }}>{msg}</div>;
}