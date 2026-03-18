import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import api from "../services/api";

function gateBadge(g) {
  if (g === "BLOCK") return { cls: "b-fail", label: "차단" };
  if (g === "REVIEW") return { cls: "b-warn", label: "검토" };
  return { cls: "b-ok", label: "배포 승인" };
}

function phaseSteps(p) {
  const status = p?.status || "";
  const gate = p?.gate_result || "";
  const isBlocked = status === "blocked";
  const phase1Done = status !== "scanning_phase1";
  const phase2Done = status === "completed" || (isBlocked && phase1Done);

  const cats = ["IaC", "SAST", "SCA"];
  const steps = cats.map((c) => ({
    label: c,
    status: phase1Done ? (gate === "BLOCK" && c === "SAST" ? "fail" : "ok") : "pending",
  }));
  steps.push({ label: "교차검증", status: phase1Done ? (gate === "BLOCK" ? "fail" : "ok") : "pending" });
  steps.push({ label: "DAST", status: isBlocked && !phase2Done ? "skip" : phase2Done ? "ok" : "pending" });
  return steps;
}

function stepBadge(s) {
  if (s === "ok") return { cls: "b-ok", icon: "✓" };
  if (s === "fail") return { cls: "b-fail", icon: "✕" };
  if (s === "skip") return { cls: "b-skip", icon: "—" };
  return { cls: "b-skip", icon: "…" };
}

function formatTime(ts) {
  if (!ts) return "—";
  const d = new Date(ts);
  const now = new Date();
  const diff = now - d;
  if (diff < 3600000) return `${Math.floor(diff / 60000)}분 전`;
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}시간 전`;
  return d.toLocaleDateString("ko-KR", { month: "short", day: "numeric" });
}

export default function HistoryPage() {
  const [pipelines, setPipelines] = useState([]);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    api.get("/pipelines")
      .then((res) => setPipelines(Array.isArray(res.data) ? res.data : []))
      .catch(() => setPipelines([]))
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="loading-center">로딩 중...</div>;

  return (
    <div className="full-page">
      <div className="page-head">
        <h2>실행 이력</h2>
        <p>최근 파이프라인 실행 결과 · SecureFlow</p>
      </div>

      {pipelines.length === 0 && (
        <div style={{ padding: 40, textAlign: "center", color: "var(--tx3)", fontFamily: "monospace" }}>
          실행된 파이프라인이 없습니다
        </div>
      )}

      {pipelines.map((p, i) => {
        const g = gateBadge(p.gate_result);
        const steps = phaseSteps(p);
        const sevCritical = 0; // would come from cross data
        return (
          <div className="hist-row" key={p.id || i} onClick={() => navigate("/")}>
            <div className="hist-num">#{p.id || i + 1}</div>
            <div className="hist-info">
              <div className="hist-title">{p.branch || p.commit_hash?.slice(0, 7) || `Pipeline #${p.id}`}</div>
              <div className="hist-meta">
                {p.project_name || "secureflow"} · {formatTime(p.created_at)} · {p.status}
              </div>
              <div className="hist-steps">
                {steps.map((s, si) => {
                  const b = stepBadge(s.status);
                  return <span className={`hist-step ${b.cls}`} key={si}>{s.label} {b.icon}</span>;
                })}
              </div>
            </div>
            <div className="hist-score">
              <div className="hist-score-n" style={{ color: p.gate_score >= 100 ? "var(--cr)" : p.gate_score >= 40 ? "var(--hi)" : "var(--ok)" }}>
                {p.gate_score?.toFixed(0) || "0"}
              </div>
              <div className="hist-score-l">Score</div>
            </div>
            <span className={`hist-badge ${g.cls}`}>{g.label}</span>
          </div>
        );
      })}
    </div>
  );
}
