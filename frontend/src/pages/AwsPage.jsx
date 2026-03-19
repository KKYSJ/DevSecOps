import React, { useState, useEffect } from "react";
import api from "../services/api";

export default function AwsPage() {
  const [ismsData, setIsmsData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState(null);

  useEffect(() => {
    api.get("/isms")
      .then((res) => setIsmsData(res.data))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="loading-center">로딩 중...</div>;

  const awsChecks = ismsData?.aws_checks || {};
  const catItems = (ismsData?.categories || []).flatMap((c) => c.items || []);
  const checks = Array.isArray(awsChecks) ? awsChecks : catItems;
  const passCount = awsChecks.passed || checks.filter((c) => c.status === "PASS").length;
  const failCount = awsChecks.failed || checks.filter((c) => c.status === "FAIL").length;
  const total = awsChecks.total || checks.length || 1;
  const passRate = total > 0 ? Math.round((passCount / total) * 100) : 0;

  // Group by resource type (simulate from ISMS check items)
  const resources = [];
  const grouped = {};
  checks.forEach((c) => {
    const key = c.resource || c.name || "기타";
    if (!grouped[key]) {
      grouped[key] = { name: key, type: c.type || "AWS Resource", region: c.region || "ap-northeast-2", items: [], critical: 0, high: 0, medium: 0 };
      resources.push(grouped[key]);
    }
    grouped[key].items.push(c);
    if (c.status === "FAIL") {
      const sev = (c.severity || "MEDIUM").toUpperCase();
      if (sev === "CRITICAL") grouped[key].critical++;
      else if (sev === "HIGH") grouped[key].high++;
      else grouped[key].medium++;
    }
  });

  const selectedResource = selected !== null ? resources[selected] : null;

  return (
    <div style={{ display: "flex", flex: 1, minHeight: 0 }}>
      <div style={{ flex: 1, padding: "28px 24px", overflowY: "auto" }}>
        <div className="page-head">
          <h2>AWS 리소스 현황</h2>
          <p>계정 내 보안 점검 결과 · boto3 API 수집</p>
        </div>

        <div style={{ display: "flex", gap: 12, marginBottom: 20 }}>
          <div className="stat-card" style={{ flex: 1 }}>
            <div className="stat-n" style={{ color: "var(--ok)" }}>{passCount}</div>
            <div className="stat-l">충족</div>
          </div>
          <div className="stat-card" style={{ flex: 1 }}>
            <div className="stat-n" style={{ color: "var(--cr)" }}>{failCount}</div>
            <div className="stat-l">미충족</div>
          </div>
          <div className="stat-card" style={{ flex: 1 }}>
            <div className="stat-n" style={{ color: "var(--pu)" }}>{passRate}%</div>
            <div className="stat-l">준수율</div>
          </div>
        </div>

        {resources.length === 0 ? (
          <div style={{ padding: 40, textAlign: "center", color: "var(--tx3)", fontFamily: "monospace" }}>
            AWS 리소스 점검 데이터가 없습니다.<br />POST /api/v1/isms/run 으로 점검을 실행하세요.
          </div>
        ) : (
          <>
            <div className="sec-label" style={{ marginTop: 0 }}>감지된 리소스 · {resources.length}개</div>
            <div className="resource-grid">
              {resources.map((r, i) => {
                const cls = r.critical > 0 ? "rc-cr" : r.high > 0 ? "rc-hi" : "rc-ok";
                return (
                  <div key={i} className={`rc ${cls}${selected === i ? " selected" : ""}`} onClick={() => setSelected(i)}>
                    <div className="rc-head">
                      <div>
                        <div className="rc-type">{r.type}</div>
                        <div className="rc-name">{r.name}</div>
                        <div className="rc-region">{r.region}</div>
                      </div>
                      <span className={`sev-b ${r.critical > 0 ? "s-cr" : r.high > 0 ? "s-hi" : "s-ok"}`}>
                        {r.critical > 0 ? "위험" : r.high > 0 ? "경고" : "정상"}
                      </span>
                    </div>
                    <div style={{ display: "flex", gap: 10, marginTop: 10, paddingTop: 10, borderTop: "1px solid var(--bd)" }}>
                      <div><div style={{ fontWeight: 700, fontFamily: "monospace", color: "var(--cr)" }}>{r.critical}</div><div style={{ fontSize: 9, color: "var(--tx3)" }}>CRITICAL</div></div>
                      <div><div style={{ fontWeight: 700, fontFamily: "monospace", color: "var(--hi)" }}>{r.high}</div><div style={{ fontSize: 9, color: "var(--tx3)" }}>HIGH</div></div>
                      <div><div style={{ fontWeight: 700, fontFamily: "monospace", color: "var(--ac)" }}>{r.medium}</div><div style={{ fontSize: 9, color: "var(--tx3)" }}>MEDIUM</div></div>
                    </div>
                  </div>
                );
              })}
            </div>
          </>
        )}
      </div>

      {/* Right detail panel */}
      <div style={{ width: 340, flexShrink: 0, borderLeft: "1px solid var(--bd)", padding: "24px 20px", overflowY: "auto", background: "var(--sf)" }}>
        {!selectedResource ? (
          <div className="detail-empty">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" width="24" height="24" style={{ opacity: 0.2 }}>
              <rect x="2" y="3" width="20" height="14" rx="2" /><path d="M8 21h8M12 17v4" />
            </svg>
            <p>리소스 카드를 클릭하면<br />상세 정보가 표시됩니다</p>
          </div>
        ) : (
          <div className="detail-panel">
            <div style={{ marginBottom: 16, paddingBottom: 14, borderBottom: "1px solid var(--bd)" }}>
              <div style={{ fontSize: 10, fontFamily: "monospace", color: "var(--tx3)", textTransform: "uppercase" }}>{selectedResource.type}</div>
              <div style={{ fontSize: 16, fontWeight: 700, marginTop: 4 }}>{selectedResource.name}</div>
              <div style={{ fontSize: 11, color: "var(--tx3)", fontFamily: "monospace", marginTop: 2 }}>{selectedResource.region}</div>
            </div>
            <div className="sec-label" style={{ marginTop: 0 }}>점검 항목</div>
            {selectedResource.items.map((item, i) => {
              const ok = item.status === "PASS";
              return (
                <div key={i} className={`finding ${ok ? "f-ok" : "f-cr"}`} style={{ marginBottom: 6 }}>
                  <span className={`f-sev ${ok ? "s-ok" : "s-cr"}`}>{ok ? "충족" : "미충족"}</span>
                  <div className="f-body">
                    <div className="f-title">{item.name || item.id}</div>
                    {item.description && <div className="f-meta">{item.description}</div>}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
