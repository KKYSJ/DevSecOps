// DevSecOps Dashboard - ActionButtons Component
// Design: Clean Governance Dashboard | Action buttons with loading states

import { RefreshCw, Shield, GitMerge, CheckSquare, Loader2 } from 'lucide-react';
import type { ScanState } from '@/lib/types';

interface ActionButtonsProps {
  scanState: ScanState;
  onRefresh: () => void;
  onSecurityScan: () => void;
  onCrossAnalysis: () => void;
  onIsmpCheck: () => void;
}

interface ActionButtonProps {
  label: string;
  description: string;
  icon: React.ReactNode;
  loadingIcon: React.ReactNode;
  isLoading: boolean;
  isDisabled: boolean;
  onClick: () => void;
  variant: 'primary' | 'danger' | 'warning' | 'success';
}

const variantStyles = {
  primary: {
    base: 'bg-slate-800 text-white hover:bg-slate-700 border-slate-700',
    loading: 'bg-slate-600 text-white border-slate-600',
  },
  danger: {
    base: 'bg-red-600 text-white hover:bg-red-700 border-red-600',
    loading: 'bg-red-400 text-white border-red-400',
  },
  warning: {
    base: 'bg-amber-500 text-white hover:bg-amber-600 border-amber-500',
    loading: 'bg-amber-300 text-white border-amber-300',
  },
  success: {
    base: 'bg-emerald-600 text-white hover:bg-emerald-700 border-emerald-600',
    loading: 'bg-emerald-400 text-white border-emerald-400',
  },
};

function ActionButton({
  label,
  description,
  icon,
  loadingIcon,
  isLoading,
  isDisabled,
  onClick,
  variant,
}: ActionButtonProps) {
  const styles = variantStyles[variant];
  const className = `
    flex items-center gap-3 px-4 py-3 rounded-lg border text-sm font-medium
    transition-all duration-200 shadow-sm
    disabled:opacity-60 disabled:cursor-not-allowed
    ${isLoading ? styles.loading : styles.base}
  `;

  return (
    <button
      className={className}
      onClick={onClick}
      disabled={isDisabled}
    >
      <div className="flex-shrink-0">
        {isLoading ? loadingIcon : icon}
      </div>
      <div className="text-left min-w-0">
        <div className="font-semibold leading-tight">{label}</div>
        <div className="text-[11px] opacity-80 mt-0.5 leading-tight">{description}</div>
      </div>
    </button>
  );
}

export default function ActionButtons({
  scanState,
  onRefresh,
  onSecurityScan,
  onCrossAnalysis,
  onIsmpCheck,
}: ActionButtonsProps) {
  const isAnyRunning =
    scanState.isRefreshing ||
    scanState.isSecurityScanning ||
    scanState.isCrossAnalyzing ||
    scanState.isIsmpChecking;

  const spinner = <Loader2 size={16} className="animate-spin" />;

  return (
    // <div className="bg-card rounded-lg border border-border p-4 shadow-sm animate-fade-in-up"
    <div className="animate-fade-in-up"
      style={{ animationDelay: '400ms', opacity: 0, animationFillMode: 'forwards' }}>
      <div className="flex items-center gap-2 mb-3">
        {/* <div className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
          스캔 제어
        </div> */}
        {isAnyRunning && (
          <div className="flex items-center gap-1.5 text-xs text-amber-600 font-medium">
            <div className="w-1.5 h-1.5 rounded-full bg-amber-500 status-running" />
            {scanState.stage}
          </div>
        )}
      </div>

      {/* Progress bar when running */}
      {isAnyRunning && (
        <div className="mb-3">
          <div className="flex justify-between text-xs text-muted-foreground mb-1">
            <span className="font-mono">{scanState.stage}</span>
            <span className="font-mono">{scanState.progress}%</span>
          </div>
          <div className="h-1.5 bg-slate-100 rounded-full overflow-hidden">
            <div
              className="h-full bg-amber-500 rounded-full transition-all duration-300"
              style={{ width: `${scanState.progress}%` }}
            />
          </div>
        </div>
      )}

      {/* <div className="flex flex-wrap gap-2"> */}
      <div className="flex justify-end">
        {/* <ActionButton
          label="결과 새로고침"
          description="현재 스캔 결과 갱신"
          icon={<RefreshCw size={16} />}
          loadingIcon={spinner}
          isLoading={scanState.isRefreshing}
          isDisabled={isAnyRunning}
          onClick={onRefresh}
          variant="primary"
        />
        <ActionButton
          label="보안 스캔 실행"
          description="SAST + 시크릿 + 의존성"
          icon={<Shield size={16} />}
          loadingIcon={spinner}
          isLoading={scanState.isSecurityScanning}
          isDisabled={isAnyRunning}
          onClick={onSecurityScan}
          variant="danger"
        />
        <ActionButton
          label="교차 분석 실행"
          description="복수 도구 결과 비교"
          icon={<GitMerge size={16} />}
          loadingIcon={spinner}
          isLoading={scanState.isCrossAnalyzing}
          isDisabled={isAnyRunning}
          onClick={onCrossAnalysis}
          variant="warning"
        /> */}
        <ActionButton
          label="ISMS-P 점검 실행"
          description="통제 항목 자동 점검"
          icon={<CheckSquare size={16} />}
          loadingIcon={spinner}
          isLoading={scanState.isIsmpChecking}
          isDisabled={isAnyRunning}
          onClick={onIsmpCheck}
          variant="success"
        />
      </div>
    </div>
  );
}
