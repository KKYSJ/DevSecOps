import React, { useState, useEffect } from 'react';
import axios from 'axios';

const API_BASE = process.env.REACT_APP_API_BASE_URL || '/api/v1';


const TYPE_COLORS = {
  CROSS_VALIDATION: { bg: '#1e3a5f', color: '#60a5fa', border: '#1d4ed8' },
  ISMS_P: { bg: '#14532d', color: '#4ade80', border: '#15803d' },
  FULL_REPORT: { bg: '#451a03', color: '#fbbf24', border: '#d97706' },
};

const FORMAT_ICONS = {
  JSON: '{ }',
  PDF: '📄',
  CSV: '📊',
  HTML: '🌐',
};

const GATE_STYLES = {
  ALLOW: { bg: '#14532d', color: '#4ade80' },
  REVIEW: { bg: '#451a03', color: '#fbbf24' },
  BLOCK: { bg: '#450a0a', color: '#f87171' },
};

export default function DownloadPage() {
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(true);
  const [typeFilter, setTypeFilter] = useState('ALL');
  const [downloadingId, setDownloadingId] = useState(null);
  const [notification, setNotification] = useState(null);

  useEffect(() => {
    axios.get(`${API_BASE}/reports`)
      .then(res => {
        const data = Array.isArray(res.data) ? res.data : (res.data.reports || res.data.items || []);
        setReports(data);
      })
      .catch(() => setReports([]))
      .finally(() => setLoading(false));
  }, []);

  const handleDownload = async (report) => {
    setDownloadingId(report.id);

    // Attempt to fetch real report from API
    const endpoints = {
      CROSS_VALIDATION: `${API_BASE}/cross`,
      ISMS_P: `${API_BASE}/isms`,
      FULL_REPORT: `${API_BASE}/cross`,
    };

    try {
      const endpoint = endpoints[report.type] || `${API_BASE}/cross`;
      const res = await axios.get(endpoint);
      const content = JSON.stringify(res.data, null, 2);
      const blob = new Blob([content], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${report.id}.json`;
      a.click();
      URL.revokeObjectURL(url);
      setNotification({ type: 'success', message: `"${report.name}" 다운로드 완료 (실제 데이터)` });
    } catch {
      // Demo download - create demo JSON/text
      const demoContent = JSON.stringify({
        report_id: report.id,
        name: report.name,
        type: report.type,
        created_at: report.created_at,
        pipeline_run: report.pipeline_run,
        branch: report.branch,
        gate: report.gate,
        score: report.score,
        note: '데모 데이터 — API 연결 시 실제 데이터로 대체됩니다.',
      }, null, 2);
      const blob = new Blob([demoContent], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${report.id}_demo.json`;
      a.click();
      URL.revokeObjectURL(url);
      setNotification({ type: 'info', message: `"${report.name}" 데모 파일 다운로드 (API 미연결)` });
    }

    setDownloadingId(null);
    setTimeout(() => setNotification(null), 4000);
  };

  if (loading) {
    return (
      <div style={{ color: 'white', padding: 60, textAlign: 'center', fontSize: 16, fontFamily: 'monospace' }}>
        <div style={{ fontSize: 24, marginBottom: 12 }}>📥</div>
        리포트 목록 로딩 중...
      </div>
    );
  }

  const filteredReports = typeFilter === 'ALL'
    ? reports
    : reports.filter(r => r.type === typeFilter);

  const containerStyle = {
    background: '#111827',
    minHeight: '100vh',
    color: '#fff',
    fontFamily: "'Segoe UI', system-ui, sans-serif",
    paddingBottom: 40,
    position: 'relative',
  };

  const thStyle = {
    padding: '10px 14px',
    textAlign: 'left',
    color: '#9ca3af',
    fontSize: 11,
    fontWeight: 700,
    borderBottom: '1px solid #374151',
    whiteSpace: 'nowrap',
    background: '#111827',
  };

  const tdStyle = {
    padding: '14px',
    borderBottom: '1px solid #1f2937',
    verticalAlign: 'middle',
  };

  return (
    <div style={containerStyle}>
      {/* Notification Toast */}
      {notification && (
        <div style={{
          position: 'fixed',
          top: 20,
          right: 20,
          background: notification.type === 'success' ? '#14532d' : '#1e3a5f',
          border: `1px solid ${notification.type === 'success' ? '#16a34a' : '#1d4ed8'}`,
          color: notification.type === 'success' ? '#4ade80' : '#60a5fa',
          padding: '12px 18px',
          borderRadius: 8,
          fontSize: 13,
          fontWeight: 600,
          zIndex: 9999,
          boxShadow: '0 4px 12px rgba(0,0,0,0.5)',
          maxWidth: 360,
        }}>
          {notification.type === 'success' ? '✅ ' : 'ℹ️ '}{notification.message}
        </div>
      )}

      {/* Header */}
      <div style={{ marginBottom: 20 }}>
        <h1 style={{ fontSize: 24, fontWeight: 800, color: '#fff', margin: 0, marginBottom: 6 }}>
          리포트 다운로드
        </h1>
        <div style={{ color: '#6b7280', fontSize: 13 }}>
          보안 스캔 및 교차 검증 리포트 다운로드
        </div>
      </div>

      {/* Summary Stats */}
      <div style={{ display: 'flex', gap: 14, marginBottom: 20, flexWrap: 'wrap' }}>
        {[
          { label: '전체 리포트', value: reports.length, color: '#60a5fa' },
          { label: '교차검증', value: reports.filter(r => r.type === 'CROSS_VALIDATION').length, color: '#93c5fd' },
          { label: 'ISMS-P', value: reports.filter(r => r.type === 'ISMS_P').length, color: '#4ade80' },
          { label: '전체 리포트', value: reports.filter(r => r.type === 'FULL_REPORT').length, color: '#fbbf24' },
        ].map(s => (
          <div key={s.label} style={{
            background: '#1f2937',
            border: '1px solid #374151',
            borderRadius: 8,
            padding: '12px 20px',
            flex: 1,
            minWidth: 120,
          }}>
            <div style={{ color: '#9ca3af', fontSize: 12, marginBottom: 4 }}>{s.label}</div>
            <div style={{ color: s.color, fontSize: 24, fontWeight: 800 }}>{s.value}</div>
          </div>
        ))}
      </div>

      {/* Quick Download Buttons */}
      <div style={{
        background: '#1f2937',
        border: '1px solid #374151',
        borderRadius: 10,
        padding: '16px 20px',
        marginBottom: 20,
      }}>
        <div style={{ color: '#9ca3af', fontSize: 12, fontWeight: 600, marginBottom: 12 }}>
          최신 리포트 빠른 다운로드
        </div>
        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
          {reports.slice(0, 3).map(report => {
            const typeStyle = TYPE_COLORS[report.type] || TYPE_COLORS.FULL_REPORT;
            const isDownloading = downloadingId === report.id;
            return (
              <button
                key={report.id}
                onClick={() => !isDownloading && handleDownload(report)}
                disabled={isDownloading}
                style={{
                  background: typeStyle.bg,
                  color: typeStyle.color,
                  border: `1px solid ${typeStyle.border}`,
                  borderRadius: 6,
                  padding: '8px 16px',
                  fontSize: 12,
                  fontWeight: 600,
                  cursor: isDownloading ? 'not-allowed' : 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 6,
                  opacity: isDownloading ? 0.7 : 1,
                }}
              >
                <span>{isDownloading ? '⏳' : '⬇️'}</span>
                <span>{isDownloading ? '다운로드 중...' : report.type_label}</span>
                <span style={{ color: '#6b7280', fontSize: 11 }}>#{report.run_number}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Type Filter */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 20, flexWrap: 'wrap' }}>
        {[
          { value: 'ALL', label: '전체', color: '#9ca3af', bg: '#374151' },
          { value: 'CROSS_VALIDATION', label: '교차검증 JSON', color: '#60a5fa', bg: '#1e3a5f' },
          { value: 'ISMS_P', label: 'ISMS-P JSON', color: '#4ade80', bg: '#14532d' },
          { value: 'FULL_REPORT', label: '전체 보안 리포트', color: '#fbbf24', bg: '#451a03' },
        ].map(btn => (
          <button
            key={btn.value}
            onClick={() => setTypeFilter(btn.value)}
            style={{
              background: typeFilter === btn.value ? btn.bg : '#1f2937',
              color: typeFilter === btn.value ? btn.color : '#9ca3af',
              border: `1px solid ${typeFilter === btn.value ? btn.color + '40' : '#374151'}`,
              borderRadius: 6,
              padding: '6px 14px',
              fontSize: 12,
              fontWeight: 600,
              cursor: 'pointer',
            }}
          >
            {btn.label}
            <span style={{
              marginLeft: 6,
              background: 'rgba(255,255,255,0.1)',
              borderRadius: 8,
              padding: '1px 5px',
              fontSize: 11,
            }}>
              {btn.value === 'ALL' ? reports.length : reports.filter(r => r.type === btn.value).length}
            </span>
          </button>
        ))}
      </div>

      {/* Reports Table */}
      <div style={{
        background: '#1f2937',
        border: '1px solid #374151',
        borderRadius: 10,
        overflow: 'hidden',
      }}>
        <div style={{
          padding: '12px 20px',
          background: '#161e2e',
          borderBottom: '1px solid #374151',
          display: 'flex',
          alignItems: 'center',
          gap: 8,
        }}>
          <span style={{ color: '#e5e7eb', fontWeight: 700, fontSize: 14 }}>📋 리포트 목록</span>
          <span style={{
            background: '#374151',
            color: '#9ca3af',
            padding: '2px 8px',
            borderRadius: 10,
            fontSize: 12,
            marginLeft: 'auto',
          }}>
            {filteredReports.length}개
          </span>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr>
                <th style={thStyle}>이름</th>
                <th style={thStyle}>유형</th>
                <th style={thStyle}>파이프라인</th>
                <th style={thStyle}>게이트 / 점수</th>
                <th style={thStyle}>형식</th>
                <th style={thStyle}>크기</th>
                <th style={thStyle}>생성일시</th>
                <th style={{ ...thStyle, textAlign: 'center' }}>다운로드</th>
              </tr>
            </thead>
            <tbody>
              {filteredReports.map((report, idx) => {
                const typeStyle = TYPE_COLORS[report.type] || TYPE_COLORS.FULL_REPORT;
                const gateStyle = GATE_STYLES[report.gate] || GATE_STYLES.REVIEW;
                const rowBg = idx % 2 === 0 ? '#1f2937' : '#1a2332';
                const isDownloading = downloadingId === report.id;

                return (
                  <tr key={report.id} style={{ background: rowBg }}>
                    {/* Name */}
                    <td style={{ ...tdStyle, maxWidth: 220 }}>
                      <div style={{ color: '#fff', fontWeight: 600, fontSize: 13 }}>
                        {report.name}
                      </div>
                      <div style={{ color: '#6b7280', fontSize: 11, marginTop: 2 }}>
                        {report.description}
                      </div>
                    </td>

                    {/* Type */}
                    <td style={tdStyle}>
                      <span style={{
                        background: typeStyle.bg,
                        color: typeStyle.color,
                        border: `1px solid ${typeStyle.border}`,
                        padding: '3px 10px',
                        borderRadius: 4,
                        fontSize: 11,
                        fontWeight: 700,
                        whiteSpace: 'nowrap',
                      }}>
                        {report.type_label}
                      </span>
                    </td>

                    {/* Pipeline */}
                    <td style={tdStyle}>
                      <div style={{ color: '#60a5fa', fontSize: 12, fontFamily: 'monospace' }}>
                        Run #{report.run_number}
                      </div>
                      <div style={{ color: '#6b7280', fontSize: 11, fontFamily: 'monospace', marginTop: 2 }}>
                        🌿 {report.branch}
                      </div>
                    </td>

                    {/* Gate / Score */}
                    <td style={tdStyle}>
                      <span style={{
                        background: gateStyle.bg,
                        color: gateStyle.color,
                        padding: '2px 8px',
                        borderRadius: 4,
                        fontSize: 11,
                        fontWeight: 700,
                        display: 'inline-block',
                        marginBottom: 2,
                      }}>
                        {report.gate}
                      </span>
                      <div style={{
                        color: report.score >= 80 ? '#4ade80' : report.score >= 60 ? '#fbbf24' : '#f87171',
                        fontSize: 11,
                        fontFamily: 'monospace',
                        fontWeight: 600,
                      }}>
                        {typeof report.score === 'number' ? report.score.toFixed(1) : '-'}
                      </div>
                    </td>

                    {/* Format */}
                    <td style={tdStyle}>
                      <span style={{
                        background: '#374151',
                        color: '#e5e7eb',
                        padding: '2px 8px',
                        borderRadius: 4,
                        fontSize: 11,
                        fontWeight: 700,
                        fontFamily: 'monospace',
                      }}>
                        {FORMAT_ICONS[report.format] || ''} {report.format}
                      </span>
                    </td>

                    {/* Size */}
                    <td style={{ ...tdStyle, color: '#9ca3af', fontSize: 12, fontFamily: 'monospace', whiteSpace: 'nowrap' }}>
                      {report.size}
                    </td>

                    {/* Created At */}
                    <td style={{ ...tdStyle, color: '#6b7280', fontSize: 12, whiteSpace: 'nowrap' }}>
                      {report.created_at}
                    </td>

                    {/* Download Button */}
                    <td style={{ ...tdStyle, textAlign: 'center' }}>
                      <button
                        onClick={() => !isDownloading && handleDownload(report)}
                        disabled={!report.available || isDownloading}
                        style={{
                          background: !report.available ? '#374151' : isDownloading ? '#1e3a5f' : '#1d4ed8',
                          color: !report.available ? '#6b7280' : isDownloading ? '#60a5fa' : '#fff',
                          border: 'none',
                          borderRadius: 6,
                          padding: '7px 14px',
                          fontSize: 12,
                          fontWeight: 600,
                          cursor: !report.available || isDownloading ? 'not-allowed' : 'pointer',
                          whiteSpace: 'nowrap',
                          display: 'flex',
                          alignItems: 'center',
                          gap: 4,
                          margin: '0 auto',
                          minWidth: 90,
                          justifyContent: 'center',
                        }}
                      >
                        {isDownloading ? (
                          <>⏳ 처리 중</>
                        ) : !report.available ? (
                          <>🔒 준비 중</>
                        ) : (
                          <>⬇️ 다운로드</>
                        )}
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        {filteredReports.length === 0 && (
          <div style={{ padding: 40, textAlign: 'center', color: '#6b7280', fontSize: 14 }}>
            리포트가 없습니다.
          </div>
        )}
      </div>

      {/* Info Notice */}
      <div style={{
        background: '#1f2937',
        border: '1px solid #374151',
        borderRadius: 8,
        padding: '12px 18px',
        marginTop: 16,
        color: '#6b7280',
        fontSize: 12,
        lineHeight: 1.6,
      }}>
        <span style={{ color: '#9ca3af', fontWeight: 600 }}>ℹ️ 안내:</span>
        {' '}API 연결 시 실제 리포트 파일이 다운로드됩니다. API가 비활성화된 경우 데모 데이터가 JSON 형식으로 저장됩니다.
        리포트는 파이프라인 완료 후 자동 생성되며, 최대 90일간 보관됩니다.
      </div>
    </div>
  );
}
