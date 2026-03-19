import React from "react";
import { NavLink, Route, Routes } from "react-router-dom";
import PipelinePage from "./pages/PipelinePage";
import HistoryPage from "./pages/HistoryPage";
import VulnsPage from "./pages/VulnsPage";
import CrossValidationPage from "./pages/CrossValidationPage";
import AwsPage from "./pages/AwsPage";
import IsmsPage from "./pages/IsmsPage";
import SiemPage from "./pages/SiemPage";

const NAV = [
  {
    label: "파이프라인",
    items: [
      { to: "/", icon: "ac", text: "Pipeline 현황" },
      { to: "/history", icon: "tx3", text: "실행 이력" },
      { to: "/vulns", icon: "cr", text: "취약점 목록" },
      { to: "/cross", icon: "ac", text: "교차 검증" },
    ],
  },
  {
    label: "보안 분석",
    items: [
      { to: "/aws", icon: "hi", text: "AWS 리소스 현황" },
      { to: "/isms", icon: "pu", text: "ISMS-P 컴플라이언스" },
    ],
  },
  {
    label: "모니터링",
    items: [
      { to: "/siem", icon: "ok", text: "SIEM" },
    ],
  },
];

export default function App() {
  return (
    <div className="shell">
      <nav className="sidebar">
        <div className="logo">
          <div className="logo-sq">
            <svg viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="2.5" width="14" height="14">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
          </div>
          <div className="logo-name">SecureFlow</div>
        </div>

        {NAV.map((group) => (
          <div className="nav-group" key={group.label}>
            <div className="nav-label">{group.label}</div>
            {group.items.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.to === "/"}
                className={({ isActive }) => `nav-item${isActive ? " on" : ""}`}
              >
                <div className="nav-dot" style={{ background: `var(--${item.icon})` }} />
                {item.text}
              </NavLink>
            ))}
          </div>
        ))}

        <div className="nav-footer">
          <div className="env-line">
            <span className="live-dot" />
            Production · ap-ne-2
          </div>
        </div>
      </nav>

      <main className="main-content">
        <Routes>
          <Route path="/" element={<PipelinePage />} />
          <Route path="/history" element={<HistoryPage />} />
          <Route path="/vulns" element={<VulnsPage />} />
          <Route path="/cross" element={<CrossValidationPage />} />
          <Route path="/aws" element={<AwsPage />} />
          <Route path="/isms" element={<IsmsPage />} />
          <Route path="/siem" element={<SiemPage />} />
        </Routes>
      </main>
    </div>
  );
}
