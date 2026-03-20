// DevSecOps Dashboard - SeverityBadge Component
// Design: Clean Governance Dashboard | Color-coded severity indicators

import type { Severity } from '@/lib/types';

interface SeverityBadgeProps {
  severity: Severity;
  size?: 'sm' | 'md';
}

const config: Record<Severity, { label: string; className: string }> = {
  CRITICAL: {
    label: 'CRITICAL',
    className: 'bg-red-900 text-red-100 border border-red-800',
  },
  HIGH: {
    label: 'HIGH',
    className: 'bg-red-50 text-red-700 border border-red-200',
  },
  MEDIUM: {
    label: 'MED',
    className: 'bg-amber-50 text-amber-700 border border-amber-200',
  },
  LOW: {
    label: 'LOW',
    className: 'bg-blue-50 text-blue-700 border border-blue-200',
  },
  INFO: {
    label: 'INFO',
    className: 'bg-slate-50 text-slate-600 border border-slate-200',
  },
};

export default function SeverityBadge({ severity, size = 'sm' }: SeverityBadgeProps) {
  const { label, className } = config[severity];
  const sizeClass = size === 'sm'
    ? 'text-[10px] px-1.5 py-0.5'
    : 'text-xs px-2 py-1';

  return (
    <span className={`inline-flex items-center rounded font-semibold font-mono tracking-wider ${className} ${sizeClass}`}>
      {label}
    </span>
  );
}
