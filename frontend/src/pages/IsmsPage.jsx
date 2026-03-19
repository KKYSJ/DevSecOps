import React, { useState, useEffect } from "react";
import api from "../services/api";

export default function IsmsPage() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState("ALL");

  useEffect(() => {
    api.get("/isms")
      .then((res) => setData(res.data))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

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
    </div>
  );
}