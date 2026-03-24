// DevSecOps Dashboard - useScanState Hook
// Design: Clean Governance Dashboard | Scan execution state management

import { useState, useCallback, useRef } from 'react';
import type { ScanState, ScanSummary, PipelineStatus } from '@/lib/types';
import { PIPELINE_STAGES } from '@/lib/mockData';

const initialScanState: ScanState = {
  isRefreshing: false,
  isSecurityScanning: false,
  isCrossAnalyzing: false,
  isIsmpChecking: false,
  currentScanType: null,
  progress: 0,
  stage: '',
};

interface UseScanStateReturn {
  scanState: ScanState;
  pipelineStatus: PipelineStatus;
  pipelineStage: string;
  pipelineProgress: number;
  handleRefresh: () => void;
  handleSecurityScan: () => void;
  handleCrossAnalysis: () => void;
  handleIsmpCheck: () => void;
}

function sleep(ms: number) {
  return new Promise<void>((resolve) => setTimeout(resolve, ms));
}

export function useScanState(
  onScanComplete?: (type: 'security' | 'cross' | 'isms' | 'refresh') => void
): UseScanStateReturn {
  const [scanState, setScanState] = useState<ScanState>(initialScanState);
  const [pipelineStatus, setPipelineStatus] = useState<PipelineStatus>('success');
  const [pipelineStage, setPipelineStage] = useState('SAST 완료');
  const [pipelineProgress, setPipelineProgress] = useState(100);
  const abortRef = useRef(false);

  const runWithProgress = useCallback(
    async (
      stateKey: keyof ScanState,
      stages: string[],
      durationPerStage: number,
      onDone: () => void
    ) => {
      abortRef.current = false;
      setPipelineStatus('running');
      setScanState((prev) => ({
        ...prev,
        [stateKey]: true,
        progress: 0,
        stage: stages[0],
      }));
      setPipelineStage(stages[0]);
      setPipelineProgress(0);

      for (let i = 0; i < stages.length; i++) {
        if (abortRef.current) break;
        const progress = Math.round(((i + 1) / stages.length) * 100);
        setScanState((prev) => ({
          ...prev,
          progress,
          stage: stages[i],
        }));
        setPipelineStage(stages[i]);
        setPipelineProgress(progress);
        await sleep(durationPerStage);
      }

      setScanState((prev) => ({
        ...prev,
        [stateKey]: false,
        currentScanType: null,
        progress: 100,
        stage: '완료',
      }));
      setPipelineStatus('success');
      setPipelineProgress(100);
      onDone();
    },
    []
  );

  const handleRefresh = useCallback(() => {
    runWithProgress(
      'isRefreshing',
      ['데이터 로드 중...', '결과 파싱 중...', '갱신 완료'],
      600,
      () => onScanComplete?.('refresh')
    );
  }, [runWithProgress, onScanComplete]);

  const handleSecurityScan = useCallback(() => {
    runWithProgress(
      'isSecurityScanning',
      PIPELINE_STAGES,
      800,
      () => onScanComplete?.('security')
    );
  }, [runWithProgress, onScanComplete]);

  const handleCrossAnalysis = useCallback(() => {
    runWithProgress(
      'isCrossAnalyzing',
      ['Semgrep 결과 로드', 'Bandit 결과 로드', 'Gitleaks 결과 로드', 'ESLint 결과 로드', '교차 비교 분석', '중복 제거', '결과 집계'],
      700,
      () => onScanComplete?.('cross')
    );
  }, [runWithProgress, onScanComplete]);

  const handleIsmpCheck = useCallback(() => {
    runWithProgress(
      'isIsmpChecking',
      ['정책 항목 로드', '접근 통제 점검', '암호화 점검', '로그 관리 점검', '취약점 매핑', '충족률 계산', '보고서 생성'],
      700,
      () => onScanComplete?.('isms')
    );
  }, [runWithProgress, onScanComplete]);

  return {
    scanState,
    pipelineStatus,
    pipelineStage,
    pipelineProgress,
    handleRefresh,
    handleSecurityScan,
    handleCrossAnalysis,
    handleIsmpCheck,
  };
}
