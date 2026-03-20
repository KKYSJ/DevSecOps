// DevSecOps Dashboard - Header Component
// Design: Clean Governance Dashboard | Top status bar with pipeline status

import { Clock, Wifi, Bell } from 'lucide-react';
import type { PipelineStatus } from '@/lib/types';

interface HeaderProps {
  lastScanTime: string;
  pipelineStatus: PipelineStatus;
  pipelineStage?: string;
}

const pipelineStatusConfig = {
  idle: { label: 'IDLE', color: 'text-slate-500', dot: 'bg-slate-400' },
  running: { label: 'RUNNING', color: 'text-amber-600', dot: 'bg-amber-500 status-running' },
  success: { label: 'SUCCESS', color: 'text-emerald-600', dot: 'bg-emerald-500' },
  failed: { label: 'FAILED', color: 'text-red-600', dot: 'bg-red-500' },
};

function formatDateTime(isoString: string): string {
  const date = new Date(isoString);
  return date.toLocaleString('ko-KR', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  });
}

export default function Header({ lastScanTime, pipelineStatus, pipelineStage }: HeaderProps) {
  const statusConfig = pipelineStatusConfig[pipelineStatus];
  const now = new Date().toLocaleString('ko-KR', {
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', hour12: false,
  });

  return (
    <header className="fixed top-14 left-0 right-0 z-20 h-14 flex items-center justify-between px-6"
      style={{
        backgroundColor: 'var(--card)',
        borderBottom: '1px solid var(--border)',
        boxShadow: '0 1px 3px oklch(0 0 0 / 0.06)',
      }}>
      {/* Left: Page title */}
      <div className="flex items-center gap-4">
        <div>
          <h1 className="text-base font-semibold text-foreground tracking-tight">
            보안 대시보드
          </h1>
        </div>
      </div>

      {/* Right: Status indicators */}
      <div className="flex items-center gap-5">
        {/* Last scan time */}
        <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
          <Clock size={13} />
          <span className="font-mono">최근 스캔: {formatDateTime(lastScanTime)}</span>
        </div>

        {/* Divider */}
        <div className="w-px h-5 bg-border" />

        {/* Pipeline status */}
        <div className="flex items-center gap-2">
          <div className={`w-2 h-2 rounded-full ${statusConfig.dot}`} />
          <div className="text-xs">
            <span className={`font-semibold font-mono ${statusConfig.color}`}>
              {statusConfig.label}
            </span>
            {pipelineStage && pipelineStatus !== 'idle' && (
              <span className="text-muted-foreground ml-1.5">— {pipelineStage}</span>
            )}
          </div>
        </div>

        {/* Divider */}
        <div className="w-px h-5 bg-border" />

        {/* Current time */}
        <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
          <Wifi size={13} />
          <span className="font-mono">{now}</span>
        </div>

        {/* Notification bell */}
        <button className="relative p-1.5 rounded-md hover:bg-accent transition-colors">
          <Bell size={16} className="text-muted-foreground" />
          <span className="absolute top-0.5 right-0.5 w-2 h-2 bg-red-500 rounded-full border border-white" />
        </button>
      </div>
    </header>
  );
}
