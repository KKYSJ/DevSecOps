import React from "react";
import { Link, Route, Routes } from "react-router-dom";
import OverviewPage from "./pages/OverviewPage";
import VulnsPage from "./pages/VulnsPage";
import CrossValidationPage from "./pages/CrossValidationPage";
import ToolsPage from "./pages/ToolsPage";
import IsmsPage from "./pages/IsmsPage";
import SiemPage from "./pages/SiemPage";
import PipelinePage from "./pages/PipelinePage";
import DownloadPage from "./pages/DownloadPage";

export default function App() {
  const links = [
    ["/", "overview"], ["/vulns", "vulns"], ["/cross", "cross"], ["/tools", "tools"],
    ["/isms", "isms"], ["/siem", "siem"], ["/pipelines", "pipelines"], ["/download", "download"],
  ];
  return (
    <div>
      <nav style={{ display: "flex", gap: 12, padding: 16, background: "#111827" }}>
        {links.map(([path, label]) => <Link key={path} to={path} style={{ color: "white", textDecoration: "none" }}>{label}</Link>)}
      </nav>
      <div style={{ padding: 20 }}>
        <Routes>
          <Route path="/" element={<OverviewPage />} />
          <Route path="/vulns" element={<VulnsPage />} />
          <Route path="/cross" element={<CrossValidationPage />} />
          <Route path="/tools" element={<ToolsPage />} />
          <Route path="/isms" element={<IsmsPage />} />
          <Route path="/siem" element={<SiemPage />} />
          <Route path="/pipelines" element={<PipelinePage />} />
          <Route path="/download" element={<DownloadPage />} />
        </Routes>
      </div>
    </div>
  );
}
