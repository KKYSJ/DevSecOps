// DevSecOps Dashboard - IsmpSection Component
// Design: Clean Governance Dashboard | ISMS-P compliance tracking

import { CheckCircle, XCircle, MinusCircle, AlertCircle } from 'lucide-react';
import type { IsmpItem } from '@/lib/types';

interface IsmpSectionProps {
  items: IsmpItem[];
  compliance: number;
}

const statusConfig = {
  PASS: {
    label: 'PASS',
    icon: CheckCircle,
    className: 'text-emerald-600',
    badgeClass: 'bg-emerald-50 text-emerald-700 border-emerald-200',
  },
  FAIL: {
    label: 'FAIL',
    icon: XCircle,
    className: 'text-red-600',
    badgeClass: 'bg-red-50 text-red-700 border-red-200',
  },
  PARTIAL: {
    label: 'PARTIAL',
    icon: MinusCircle,
    className: 'text-amber-600',
    badgeClass: 'bg-amber-50 text-amber-700 border-amber-200',
  },
  'N/A': {
    label: 'N/A',
    icon: AlertCircle,
    className: 'text-slate-400',
    badgeClass: 'bg-slate-50 text-slate-500 border-slate-200',
  },
};

export default function IsmpSection({ items, compliance }: IsmpSectionProps) {
  const passCount = items.filter(i => i.status === 'PASS').length;
  const failCount = items.filter(i => i.status === 'FAIL').length;
  const partialCount = items.filter(i => i.status === 'PARTIAL').length;
  const naCount = items.filter(i => i.status === 'N/A').length;

  // Group by domain
  const domains = Array.from(new Set(items.map(i => i.domain)));

  const handleDownload = () => {
    const headers = [
      'Control ID',
      'Domain',
      'Requirement',
      'Status',
      'Evidence',
      'Last Checked',
    ];

    const rows = items.map((item) => [
      item.controlId,
      item.domain,
      item.requirement,
      item.status,
      item.evidence,
      new Date(item.lastChecked).toLocaleString('ko-KR'),
    ]);

    const csvContent = [headers, ...rows]
      .map((row) =>
        row
          .map((cell) => `"${String(cell).replace(/"/g, '""')}"`)
          .join(',')
      )
      .join('\n');

    const blob = new Blob([csvContent], {
      type: 'text/csv;charset=utf-8;',
    });

    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `isms-report-${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };


  return (
    <div className="bg-card rounded-lg border border-border shadow-sm animate-fade-in-up"
      style={{ animationDelay: '700ms', opacity: 0, animationFillMode: 'forwards' }}>
      {/* Header */}
      <div className="p-4 border-b border-border">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h3 className="text-sm font-semibold text-foreground">ISMS-P 점검 현황</h3>
            <p className="text-xs text-muted-foreground mt-0.5">
              정보보호 관리체계 인증 통제 항목 점검
            </p>
          </div>

          <div className="flex items-center gap-3">
            {/* 다운로드 버튼 */}
            <button
              onClick={handleDownload}
              className="text-xs px-3 py-1.5 rounded-md border border-border bg-background hover:bg-muted transition"
            >
              📄 보고서 다운로드
            </button>

            {/* 기존 compliance */}
            <div className="text-right">
              <div className="text-2xl font-bold font-mono text-emerald-600">
                {compliance.toFixed(1)}%
              </div>
              <div className="text-xs text-muted-foreground">충족률</div>
            </div>
          </div>
        </div>

        {/* Progress bar */}
        <div className="mt-3">
          <div className="flex h-2.5 rounded-full overflow-hidden bg-slate-100">
            <div
              className="bg-emerald-500 transition-all duration-1000"
              style={{ width: `${(passCount / items.length) * 100}%` }}
              title={`PASS: ${passCount}`}
            />
            <div
              className="bg-amber-400 transition-all duration-1000"
              style={{ width: `${(partialCount / items.length) * 100}%` }}
              title={`PARTIAL: ${partialCount}`}
            />
            <div
              className="bg-red-400 transition-all duration-1000"
              style={{ width: `${(failCount / items.length) * 100}%` }}
              title={`FAIL: ${failCount}`}
            />
          </div>
          <div className="flex items-center gap-4 mt-2 text-xs">
            <div className="flex items-center gap-1.5">
              <div className="w-2 h-2 rounded-sm bg-emerald-500" />
              <span className="text-muted-foreground">PASS</span>
              <span className="font-mono font-semibold text-foreground">{passCount}</span>
            </div>
            <div className="flex items-center gap-1.5">
              <div className="w-2 h-2 rounded-sm bg-amber-400" />
              <span className="text-muted-foreground">PARTIAL</span>
              <span className="font-mono font-semibold text-foreground">{partialCount}</span>
            </div>
            <div className="flex items-center gap-1.5">
              <div className="w-2 h-2 rounded-sm bg-red-400" />
              <span className="text-muted-foreground">FAIL</span>
              <span className="font-mono font-semibold text-foreground">{failCount}</span>
            </div>
            {naCount > 0 && (
              <div className="flex items-center gap-1.5">
                <div className="w-2 h-2 rounded-sm bg-slate-300" />
                <span className="text-muted-foreground">N/A</span>
                <span className="font-mono font-semibold text-foreground">{naCount}</span>
              </div>
            )}
            <div className="ml-auto text-muted-foreground">
              총 <span className="font-mono font-semibold text-foreground">{items.length}</span>개 항목
            </div>
          </div>
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-border bg-muted/30">
              <th className="text-left px-4 py-2.5 font-semibold text-muted-foreground uppercase tracking-wider w-20">통제 ID</th>
              <th className="text-left px-4 py-2.5 font-semibold text-muted-foreground uppercase tracking-wider w-24">도메인</th>
              <th className="text-left px-4 py-2.5 font-semibold text-muted-foreground uppercase tracking-wider">요구사항</th>
              <th className="text-left px-4 py-2.5 font-semibold text-muted-foreground uppercase tracking-wider w-20">상태</th>
              <th className="text-left px-4 py-2.5 font-semibold text-muted-foreground uppercase tracking-wider">증적/비고</th>
              <th className="text-left px-4 py-2.5 font-semibold text-muted-foreground uppercase tracking-wider w-28">점검 일시</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {items.map((item) => {
              const config = statusConfig[item.status];
              const Icon = config.icon;
              const rowBg =
                item.status === 'FAIL' ? 'bg-red-50/30' :
                  item.status === 'PARTIAL' ? 'bg-amber-50/20' : '';

              return (
                <tr key={item.id} className={`hover:bg-muted/20 transition-colors ${rowBg}`}>
                  <td className="px-4 py-2.5 font-mono font-semibold text-foreground">{item.controlId}</td>
                  <td className="px-4 py-2.5">
                    <span className="px-1.5 py-0.5 bg-slate-100 text-slate-600 rounded text-[10px] font-medium">
                      {item.domain}
                    </span>
                  </td>
                  <td className="px-4 py-2.5 text-foreground font-medium">{item.requirement}</td>
                  <td className="px-4 py-2.5">
                    <div className="flex items-center gap-1.5">
                      <Icon size={13} className={config.className} />
                      <span className={`px-1.5 py-0.5 rounded border text-[10px] font-semibold font-mono ${config.badgeClass}`}>
                        {config.label}
                      </span>
                    </div>
                  </td>
                  <td className="px-4 py-2.5 text-muted-foreground max-w-[250px] truncate" title={item.evidence}>
                    {item.evidence}
                  </td>
                  <td className="px-4 py-2.5 text-muted-foreground font-mono text-[10px]">
                    {new Date(item.lastChecked).toLocaleString('ko-KR', {
                      month: '2-digit',
                      day: '2-digit',
                      hour: '2-digit',
                      minute: '2-digit',
                      hour12: false,
                    })}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Footer summary */}
      <div className="px-4 py-3 border-t border-border bg-muted/20">
        <div className="flex items-center gap-4 text-xs text-muted-foreground flex-wrap">
          <span>도메인: {domains.join(' · ')}</span>
          <span className="ml-auto">
            {failCount > 0 && (
              <span className="text-red-600 font-semibold">
                ⚠ FAIL {failCount}건 즉시 조치 필요
              </span>
            )}
          </span>
        </div>
      </div>
    </div>
  );
}
