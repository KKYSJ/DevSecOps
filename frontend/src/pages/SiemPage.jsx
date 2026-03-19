import React, { useState, useEffect } from "react";
import api from "../services/api";

export default function SiemPage() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.get("/siem")
      .then((res) => setData(res.data))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="loading-center">로딩 중...</div>;

  const d = data || {};
  const services = d.services || {};
  const events = d.recentEvents || d.recent_critical_events || [];

  const serviceCards = [
    { name: "CloudWatch", key: "cloudwatch", color: "var(--hi)", metrics: [
      { label: "CPU 사용률", value: services.cloudwatch?.cpu || "—" },
      { label: "메모리", value: services.cloudwatch?.memory || "—" },
      { label: "에러율", value: services.cloudwatch?.errorRate || "—" },
    ]},
    { name: "GuardDuty", key: "guardduty", color: "var(--pu)", metrics: [
      { label: "위협 탐지", value: services.guardduty?.findings || "0건" },
      { label: "최고 심각도", value: services.guardduty?.severity || "—" },
      { label: "마지막 점검", value: services.guardduty?.lastCheck || "—" },
    ]},
    { name: "Security Hub", key: "securityhub", color: "var(--cr)", metrics: [
      { label: "보안 점수", value: services.securityhub?.score || "—" },
      { label: "Critical", value: services.securityhub?.critical || "0건" },
      { label: "CIS", value: services.securityhub?.cis || "—" },
    ]},
    { name: "CloudTrail", key: "cloudtrail", color: "var(--run)", metrics: [
      { label: "API 호출", value: services.cloudtrail?.events?.toLocaleString() || "—" },
      { label: "Trail 수", value: services.cloudtrail?.trails || "—" },
      { label: "S3 로그", value: services.cloudtrail?.active ? "정상" : "—" },
    ]},
  ];

  return (
    <div className="full-page">
      <div className="page-head">
        <h2>SIEM 모니터링</h2>
        <p>CloudWatch · GuardDuty · CloudTrail · Security Hub</p>
      </div>

      <div className="siem-grid">
        {serviceCards.map((svc) => {
          const svcData = services[svc.key];
          const isActive = svcData?.active !== false;
          return (
            <div className="siem-card" key={svc.key}>
              <div className="siem-card-head">
                <div className="siem-card-title">{svc.name}</div>
                <span className={`sev-b ${isActive ? "s-ok" : "s-ac"}`}>{isActive ? "정상" : "비활성"}</span>
              </div>
              {svc.metrics.map((m, i) => (
                <div className="siem-row" key={i}>
                  <div className="siem-dot" style={{ background: svc.color }} />
                  <div className="siem-info"><div className="siem-title">{m.label}</div></div>
                  <span className="siem-badge b-ok">{m.value}</span>
                </div>
              ))}
            </div>
          );
        })}
      </div>

      {/* Recent Events */}
      <div className="siem-card">
        <div className="siem-card-head">
          <div className="siem-card-title">최근 보안 이벤트</div>
          <span style={{ fontSize: 11, color: "var(--tx3)", fontFamily: "monospace" }}>최근 24시간</span>
        </div>
        {events.length === 0 ? (
          <div style={{ padding: 20, textAlign: "center", color: "var(--tx3)", fontSize: 12 }}>보안 이벤트가 없습니다</div>
        ) : (
          events.map((evt, i) => (
            <div className="ev-item" key={evt.id || i}>
              <span className="ev-time">{evt.time || "—"}</span>
              <div className="ev-body">
                <div className="ev-title">{evt.description || evt.type || "이벤트"}</div>
                <div className="ev-meta">{evt.source || "—"} · {evt.resource || "—"}</div>
              </div>
              <span className={`siem-badge ${evt.severity === "CRITICAL" || evt.severity === "HIGH" ? "b-fail" : evt.severity === "MEDIUM" ? "b-warn" : "b-ok"}`}>
                {evt.severity || evt.status || "—"}
              </span>
            </div>
          ))
        )}
      </div>
    </div>
  );
}