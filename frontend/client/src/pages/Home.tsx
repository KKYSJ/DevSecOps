// DevSecOps Dashboard - Home Page
// Design: Clean Governance Dashboard | IBM Plex Sans + IBM Plex Mono
// Layout: Fixed top nav + Scrollable main content

import { useState, useCallback, useMemo, useEffect } from 'react';
import { toast } from 'sonner';
import { Cloud, Code2, ShieldCheck, GitBranch, Image, Server, Bug, Monitor, ArrowLeft, ChevronDown } from 'lucide-react';
import { useLocation } from 'wouter';
import Sidebar from '@/components/Sidebar';
import SummaryCards from '@/components/SummaryCards';
import ActionButtons from '@/components/ActionButtons';
import VulnerabilityCharts from '@/components/VulnerabilityCharts';
import VulnerabilityTable from '@/components/VulnerabilityTable';
import CrossAnalysis from '@/components/CrossAnalysis';
import IsmpSection from '@/components/IsmpSection';
import SecurityMonitoring from '@/components/SecurityMonitoring';
import { useScanState } from '@/hooks/useScanState';
import {
  mockScanSummary,
  mockVulnerabilities,
  mockCrossAnalysis,
  mockIsmpItems,
  mockToolChartData,
  mockCategoryChartData,
  mockSecurityMonitoringSummary,
  mockServiceStatuses,
  mockEventItems,
  mockTrendChartData,
  mockDeployments,
} from '@/lib/mockData';
import type { ScanSummary, Vulnerability, CrossAnalysisItem } from '@/lib/types';
import StageCrossAnalysis from '@/components/StageCrossAnalysis';
import AwsResources from '@/components/AwsResources';
import { fetchJson } from '@/lib/api';

const SCAN_STAGES = [
  { id: 'iac', label: 'IaC 스캔', subtitle: 'tfsec + Checkov', icon: Cloud },
  { id: 'sast', label: 'SAST', subtitle: 'SonarQube + Semgrep', icon: Code2 },
  { id: 'sca', label: 'SCA', subtitle: 'Trivy + Dep-Check', icon: ShieldCheck },
  { id: 'image', label: '이미지 스캔', subtitle: 'Trivy + Grype', icon: Image },
  { id: 'dast', label: 'DAST', subtitle: 'ZAP + Nuclei', icon: Bug },
];
const CROSS_STAGE = { id: 'cross', label: '교차 검증', subtitle: 'LLM 종합 분석', icon: GitBranch };

// gate 결과 기반으로 BLOCK된 위치를 찾아 교차검증을 동적 삽입
function buildDynamicPipeline(gates: Record<string, any>) {
  const getDecision = (g: any) => {
    const d = (g?.decision || g?.gate_result || g?.llm_analysis?.recommended_decision || '').toLowerCase();
    if (d === 'fail' || d === 'block') return 'block';
    return d;
  };

  // BLOCK된 stage 찾기
  const scanOrder = ['iac', 'sast', 'sca', 'image', 'dast'];
  let blockIdx = -1;
  for (let i = 0; i < scanOrder.length; i++) {
    if (getDecision(gates[scanOrder[i]]) === 'block') {
      blockIdx = i;
      break;
    }
  }

  const stages = [...SCAN_STAGES];
  if (blockIdx >= 0) {
    // BLOCK된 stage의 SCAN_STAGES 내 인덱스 찾기
    const blockStageId = scanOrder[blockIdx];
    const insertAfter = stages.findIndex(s => s.id === blockStageId);
    if (insertAfter >= 0) {
      stages.splice(insertAfter + 1, 0, CROSS_STAGE);
    }
  } else {
    // BLOCK 없으면 맨 뒤에
    stages.push(CROSS_STAGE);
  }
  return stages;
}

// 하위 호환용
const PIPELINE_STAGES = SCAN_STAGES;

type PipelineStepState = 'pending' | 'running' | 'success' | 'failed';

function stageIdFromPipelineText(text: string | undefined): string | null {
  if (!text) return null;
  if (text.includes('IaC')) return 'iac';
  if (text.includes('SAST')) return 'sast';
  if (text.includes('SCA') || text.includes('의존성')) return 'sca';
  if (text.includes('교차')) return 'cross';
  //if (text.includes('정규화') || text.includes('스코어')) return 'normalize';
  if (text.includes('이미지') || text.includes('컨테이너')) return 'image';
  if (text.includes('배포')) return 'deploy';
  if (text.includes('DAST')) return 'dast';
  return null;
}

// gate 결과 기반 단계별 상태 계산
function getStepStateFromGates(
  stageId: string,
  gates: Record<string, any>
): PipelineStepState {
  const getGateDecision = (g: any) => {
    const d = (g?.decision || g?.gate_result || g?.llm_analysis?.recommended_decision || '').toLowerCase();
    // fail = block
    if (d === 'fail' || d === 'block') return 'block';
    return d;
  };

  const stageGateMap: Record<string, string[]> = {
    'iac': ['iac'],
    'sast': ['sast'],
    'sca': ['sca'],
    'cross': ['sast', 'sca', 'iac'],
    'image': ['image'],
    'deploy': [],
    'dast': ['dast'],
  };

  const relevantGates = stageGateMap[stageId] || [];

  if (stageId === 'cross') {
    // 교차검증은 BLOCK/REVIEW와 무관하게 분석 완료 표시
    const allGateKeys = ['sast', 'sca', 'iac', 'image', 'dast'];
    const hasAny = allGateKeys.some(g => gates[g]);
    if (!hasAny) return 'pending';
    return 'success'; // 분석 완료
  }

  // BLOCK된 단계 이후는 전부 회색 (교차검증 제외)
  const scanOrder = ['iac', 'sast', 'sca', 'image', 'dast'];
  const currentStageIdx = scanOrder.indexOf(stageId);
  if (currentStageIdx >= 0) {
    for (let i = 0; i < currentStageIdx; i++) {
      const prevId = scanOrder[i];
      const prevGates2 = stageGateMap[prevId] || [];
      const prevDecision = prevGates2.length > 0 ? getGateDecision(gates[prevGates2[0]]) : '';
      if (prevDecision === 'block') return 'pending';
    }
  }
  // 교차검증: BLOCK된 stage가 있으면 그 이전 stage 기준으로 판단
  if (stageId === 'cross') {
    // BLOCK 이후에 위치하므로 항상 표시 (pending 아님)
  }

  if (stageId === 'deploy') {
    return 'success';
  }

  const gate = gates[relevantGates[0]];
  if (!gate) return 'pending';
  const decision = getGateDecision(gate);
  if (decision === 'block') return 'failed';
  if (decision === 'review') return 'running';
  return 'success';
}

function getStepState(
  idx: number,
  currentIdx: number,
  pipelineStatus: 'idle' | 'running' | 'success' | 'failed',
  isFailure: boolean,
  progress: number
): PipelineStepState {
  if (pipelineStatus === 'idle') return 'pending';

  if (pipelineStatus === 'failed' || isFailure) {
    if (idx < currentIdx) return 'success';
    if (idx === currentIdx) return 'failed';
    return 'pending';
  }

  if (pipelineStatus === 'running') {
    if (idx < currentIdx) return 'success';
    if (idx === currentIdx) return 'running';
    return 'pending';
  }

  // success
  if (progress >= 100) return 'success';
  if (idx <= currentIdx) return 'success';
  return 'pending';
}

// CI LLM Gate 분석 결과 표시 컴포넌트
// 아코디언 컴포넌트
function Accordion({ title, badge, defaultOpen = false, children }: { title: React.ReactNode; badge?: React.ReactNode; defaultOpen?: boolean; children: React.ReactNode }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="bg-card rounded-lg border border-border shadow-sm overflow-hidden">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between p-5 hover:bg-muted/30 transition-colors text-left"
      >
        <div className="flex items-center gap-2 flex-wrap">
          {title}
          {badge}
        </div>
        <ChevronDown size={18} className={`text-muted-foreground transition-transform flex-shrink-0 ${open ? 'rotate-180' : ''}`} />
      </button>
      {open && <div className="px-5 pb-5">{children}</div>}
    </div>
  );
}

function LlmGateSummary({ gate, judgments, mode = 'cross' }: { gate: any; judgments?: any[]; mode?: 'cross' | 'combined' }) {
  if (!gate) return null;

  const llm = gate.llm_analysis || {};
  const matching = gate.matching || {};
  const confirmed = gate.confirmed_summary || {};
  const combined = gate.combined_summary || {};
  const reasons = llm.reasons || [];
  const decision = gate.decision || 'unknown';

  const decisionColor = decision === 'pass' ? 'text-green-600 bg-green-50 border-green-200'
    : decision === 'fail' ? 'text-red-600 bg-red-50 border-red-200'
    : 'text-amber-600 bg-amber-50 border-amber-200';

  const decisionLabel = decision === 'pass' ? '통과' : decision === 'fail' ? '차단' : '검토 필요';

  return (
    <div className="bg-card rounded-lg border border-border shadow-sm p-5 mb-4">
      <div className="flex items-center gap-2 mb-4">
        <span className="text-sm font-bold bg-blue-600 text-white px-3 py-1 rounded">Gemini LLM</span>
        <span className="text-base font-semibold text-foreground">{mode === 'combined' ? '합산 검증 분석 결과' : 'CI 교차검증 분석 결과'}</span>
        <span className={`text-sm font-bold px-2 py-1 rounded border ${decisionColor}`}>{decisionLabel}</span>
      </div>

      {/* 매칭 통계 — judgments 기반 */}
      {mode === 'cross' && judgments && judgments.length > 0 && (() => {
        const jConfirmed = judgments.filter((j: any) => j.judgement_code === 'TRUE_POSITIVE' && j.finding_b).length;
        const jReview = judgments.filter((j: any) => j.judgement_code !== 'TRUE_POSITIVE' || !j.finding_b).length;
        return (
          <div className="grid grid-cols-2 gap-3 mb-3">
            <div className="bg-muted rounded-md p-3 text-center">
              <div className="text-xl font-bold text-green-600">{jConfirmed}</div>
              <div className="text-sm text-muted-foreground">동시 탐지</div>
            </div>
            <div className="bg-muted rounded-md p-3 text-center">
              <div className="text-xl font-bold text-amber-600">{jReview}</div>
              <div className="text-sm text-muted-foreground">단독 탐지</div>
            </div>
          </div>
        );
      })()}

      {/* LLM 분석 요약 */}
      {llm.summary && (
        <div className="bg-muted rounded-lg p-4 mb-3">
          <div className="text-sm font-semibold text-foreground mb-2">LLM 분석 요약</div>
          <div className="text-sm text-foreground leading-relaxed">{llm.summary}</div>
        </div>
      )}

      {/* LLM 판정 근거 */}
      {reasons.length > 0 && (
        <div className="space-y-2 mb-3">
          <div className="text-sm font-semibold text-foreground">판정 근거</div>
          {reasons.map((r: string, i: number) => (
            <div key={i} className="text-sm text-muted-foreground flex gap-2">
              <span className="text-foreground font-bold">•</span> {r}
            </div>
          ))}
        </div>
      )}

      {/* Provider notes */}
      {llm.provider_notes && (
        <div className="mt-2 text-sm text-blue-700 bg-blue-50 rounded-lg p-3">
          {llm.provider_notes}
        </div>
      )}

      {/* 개별 취약점 LLM 판정은 동시탐지/단독탐지 카드에 통합됨 */}
    </div>
  );
}

// 배포 상태 섹션 — cross/history 기반
function DeploySection() {
  const [deployData, setDeployData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    Promise.all([
      fetchJson<any>('/cross/history').catch(() => ({ history: [] })),
      fetchJson<any>('/cross/gates').catch(() => ({ gates: {}, judgments: {} })),
    ]).then(([hRes, gatesData]) => {
      const latest = (hRes.history || []).find((h: any) => h.commit_hash);
      // judgments에서 통계
      const jAll = gatesData.judgments || {};
      const allJ = [...(jAll.sast || []), ...(jAll.sca || []), ...(jAll.iac || []),
        ...((jAll.gate_result?.judgments?.sast) || []),
        ...((jAll.gate_result?.judgments?.sca) || []),
        ...((jAll.gate_result?.judgments?.iac) || [])];
      const tp = allJ.filter((j: any) => j.judgement_code === 'TRUE_POSITIVE' && j.finding_b).length;
      const total = allJ.length;

      setDeployData({
        commit: latest?.commit_hash?.slice(0, 8) || '—',
        gate: latest?.gate_decision || '—',
        score: latest?.total_score || 0,
        time: latest?.generated_at || '',
        findings: total,
        tp,
        phase: 1,
      });
    }).finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="text-center py-10 text-muted-foreground">로딩 중...</div>;
  if (!deployData) return <div className="text-center py-10 text-muted-foreground">배포 데이터 없음</div>;

  const isBlocked = deployData.gate === 'BLOCK';
  const timeStr = deployData.time ? new Date(deployData.time).toLocaleString('ko-KR') : '—';

  return (
    <>
      {/* 배포 판정 배너 */}
      <div className={`rounded-lg border-2 p-5 ${isBlocked ? 'bg-red-50 border-red-300' : 'bg-green-50 border-green-300'}`}>
        <div className="flex items-center gap-3 mb-2">
          <span className={`text-lg font-bold ${isBlocked ? 'text-red-700' : 'text-green-700'}`}>
            {isBlocked ? '🔴 배포 차단' : '🟢 배포 완료'}
          </span>
        </div>
        <div className={`text-sm ${isBlocked ? 'text-red-600' : 'text-green-600'}`}>
          {isBlocked
            ? `보안 게이트에서 차단됨 — 동시탐지 ${deployData.tp}건 포함 총 ${deployData.findings}건의 취약점 발견`
            : '모든 보안 검사를 통과하여 배포가 완료되었습니다'}
        </div>
      </div>

      {/* 파이프라인 상태 */}
      <div className="bg-card rounded-lg border border-border shadow-sm p-5">
        <h3 className="text-sm font-bold text-foreground mb-4">파이프라인 실행 상태</h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-muted rounded-lg p-4">
            <div className="text-xs text-muted-foreground mb-1">최근 커밋</div>
            <div className="text-sm font-mono font-bold text-foreground">{deployData.commit}</div>
          </div>
          <div className="bg-muted rounded-lg p-4">
            <div className="text-xs text-muted-foreground mb-1">게이트 판정</div>
            <div className={`text-sm font-bold ${isBlocked ? 'text-red-600' : 'text-green-600'}`}>{deployData.gate}</div>
          </div>
          <div className="bg-muted rounded-lg p-4">
            <div className="text-xs text-muted-foreground mb-1">Phase</div>
            <div className="text-sm font-bold text-foreground">Phase {deployData.phase} 완료</div>
          </div>
          <div className="bg-muted rounded-lg p-4">
            <div className="text-xs text-muted-foreground mb-1">실행 시각</div>
            <div className="text-xs font-mono text-foreground">{timeStr}</div>
          </div>
        </div>
      </div>

      {/* Phase 단계별 상태 */}
      <div className="bg-card rounded-lg border border-border shadow-sm p-5">
        <h3 className="text-sm font-bold text-foreground mb-4">보안 검사 단계</h3>
        <div className="space-y-3">
          {[
            { label: 'Phase 1 — SAST + SCA + IaC', status: '완료', ok: true },
            { label: '교차검증 + LLM 판정', status: '완료', ok: true },
            { label: '게이트 판정', status: deployData.gate, ok: !isBlocked },
            { label: 'Docker 이미지 빌드', status: isBlocked ? '차단됨' : '완료', ok: !isBlocked },
            { label: 'Phase 2 — DAST (ZAP + Nuclei)', status: isBlocked ? '미실행' : '완료', ok: !isBlocked },
            { label: '배포 (ECS Fargate)', status: isBlocked ? '차단됨' : '완료', ok: !isBlocked },
          ].map((step, i) => (
            <div key={i} className="flex items-center gap-3">
              <span className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold text-white ${step.ok ? 'bg-green-500' : 'bg-red-500'}`}>
                {step.ok ? '✓' : '✕'}
              </span>
              <span className="text-sm text-foreground flex-1">{step.label}</span>
              <span className={`text-xs font-semibold ${step.ok ? 'text-green-600' : 'text-red-600'}`}>{step.status}</span>
            </div>
          ))}
        </div>
      </div>
    </>
  );
}

// 이미지 스캔 섹션
function ImageScanSection({ judgments, summaries, gates }: { judgments?: any[]; summaries?: Record<string, any>; gates?: Record<string, any> }) {
  const [apiVulns, setApiVulns] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    // trivy-image + grype 둘 다 가져오기
    Promise.all([
      fetchJson<any>('/vulns?tool=trivy-image&limit=200').catch(() => ({ vulnerabilities: [] })),
      fetchJson<any>('/vulns?tool=grype&limit=200').catch(() => ({ vulnerabilities: [] })),
    ]).then(([trivyRes, grypeRes]) => {
      const _s: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
      const allVulns = [...(trivyRes.vulnerabilities || []), ...(grypeRes.vulnerabilities || [])]
        .sort((a: any, b: any) => (_s[(a.severity || 'LOW').toUpperCase()] ?? 9) - (_s[(b.severity || 'LOW').toUpperCase()] ?? 9))
        .map((v: any, i: number) => ({
          id: `img-api-${i}`,
          severity: (v.severity || 'MEDIUM').toUpperCase(),
          category: 'IMAGE',
          tool: v.tool || 'trivy-image',
          file: v.package_name || v.file_path || '',
          line: 0,
          cwe: v.cve_id || v.cwe_id || '',
          description: (v.title || '').slice(0, 100),
          confidence: 'MED',
          detectedAt: v.created_at || new Date().toISOString(),
          _originalDesc: ((v.description || v.title || '') as string).slice(0, 300),
        }));
      setApiVulns(allVulns);
    }).finally(() => setLoading(false));
  }, []);

  const imgJ = judgments || [];
  const _s: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

  // judgments 기반 vulns (있으면 우선)
  const jVulns: any[] = [];
  imgJ.forEach((j: any, i: number) => {
    const fa = j.finding_a || {};
    const fb = j.finding_b || {};
    const cleanTitle = (s: string) => (s || '').replace(/^\[(?:확인됨|미확인|검토필요|검토 필요)\]\s*/g, '');
    // finding_a (trivy)
    jVulns.push({
      id: `img-j-${i}-a`,
      severity: (j.reassessed_severity || j.severity || fa.severity || 'MEDIUM').toUpperCase(),
      category: 'IMAGE',
      tool: fa.tool === 'trivy' ? 'trivy-image' : (fa.tool || 'trivy-image'),
      file: fa.package_name || fa.file_path || '',
      line: 0,
      cwe: fa.cve_id || fa.cwe_id || '',
      description: cleanTitle(j.title_ko || (fa.title || '').slice(0, 100)),
      confidence: fb.tool ? 'HIGH' : (j.confidence || 'MED'),
      detectedAt: new Date().toISOString(),
      _originalDesc: ((fa.description || fa.title || '') as string).slice(0, 300),
      _judgment: j,
    });
    // finding_b (grype) — 동시 탐지일 때만
    if (fb.tool) {
      jVulns.push({
        id: `img-j-${i}-b`,
        severity: (j.reassessed_severity || j.severity || fb.severity || 'MEDIUM').toUpperCase(),
        category: 'IMAGE',
        tool: fb.tool === 'trivy' ? 'trivy-image' : (fb.tool || 'grype'),
        file: fb.package_name || fb.file_path || fa.package_name || fa.file_path || '',
        line: 0,
        cwe: fb.cve_id || fa.cve_id || fb.cwe_id || fa.cwe_id || '',
        description: cleanTitle(j.title_ko || (fb.title || '').slice(0, 100)),
        confidence: 'HIGH',
        detectedAt: new Date().toISOString(),
        _originalDesc: ((fb.description || fb.title || '') as string).slice(0, 300),
        _judgment: j,
      });
    }
  });

  // API vulns에서 CVE→패키지명 맵 생성
  const cvePkgMap = new Map<string, string>();
  apiVulns.forEach(v => { if (v.cwe && v.file) cvePkgMap.set(v.cwe, v.file); });
  // judgments에 패키지명 보강
  jVulns.forEach((v: any) => { if (!v.file && v.cwe && cvePkgMap.has(v.cwe)) v.file = cvePkgMap.get(v.cwe); });
  // 합치기 (judgments 우선, 중복 제거)
  const jKeys = new Set(jVulns.map((v: any) => v.cwe).filter(Boolean));
  const extra = apiVulns.filter(v => !v.cwe || !jKeys.has(v.cwe));
  // judgments 전부 포함 + extra는 상위만
  const extraLimit = Math.max(0, 30 - jVulns.length);
  const imgVulns = [...jVulns, ...extra.slice(0, extraLimit)].sort((a: any, b: any) => (_s[a.severity] ?? 9) - (_s[b.severity] ?? 9));

  if (loading && imgJ.length === 0) return <div className="text-center py-10 text-muted-foreground">이미지 스캔 데이터 로딩 중...</div>;

  if (imgVulns.length === 0) {
    return (
      <div className="bg-card rounded-lg border border-border p-8 text-center">
        <div className="text-lg font-semibold text-foreground mb-2">이미지 스캔</div>
        <p className="text-sm text-muted-foreground mb-1">Docker 빌드 후 컨테이너 이미지 내부의 취약점을 Trivy + Grype로 스캔합니다.</p>
        <div className="mt-4 text-xs text-muted-foreground bg-muted rounded p-3">다음 CD 파이프라인 실행 시 이미지 스캔 결과가 여기에 표시됩니다.</div>
      </div>
    );
  }

  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  imgVulns.forEach(v => { if (counts[v.severity as keyof typeof counts] !== undefined) counts[v.severity as keyof typeof counts]++; });
  const confirmed = imgJ.filter((j: any) => j.judgement_code === 'TRUE_POSITIVE' && j.finding_b);
  const review = imgJ.filter((j: any) => !(j.judgement_code === 'TRUE_POSITIVE' && j.finding_b));
  const sm = summaries?.['image'];
  const gate = gates?.['image'];

  return (
    <>
      {/* Severity 카드 */}
      <div className="grid grid-cols-4 gap-3">
        {Object.entries(counts).map(([sev, count]) => {
          const colors: Record<string, string> = { CRITICAL: 'text-red-600 bg-red-50 border-red-200', HIGH: 'text-orange-600 bg-orange-50 border-orange-200', MEDIUM: 'text-yellow-600 bg-yellow-50 border-yellow-200', LOW: 'text-blue-600 bg-blue-50 border-blue-200' };
          const labels: Record<string, string> = { CRITICAL: '긴급 조치 필요', HIGH: '즉시 조치 필요', MEDIUM: '우선 검토 필요', LOW: '모니터링 권장' };
          return <div key={sev} className={`rounded-lg border p-4 ${colors[sev]}`}><div className="text-xs font-semibold uppercase">{sev}</div><div className="text-2xl font-bold mt-1">{count}</div><div className="text-xs mt-1">{labels[sev]}</div></div>;
        })}
      </div>

      {/* CI 교차검증 분석 결과 */}
      <Accordion title={<><span className="text-sm font-bold bg-blue-600 text-white px-3 py-1 rounded">Gemini LLM</span><span className="text-base font-semibold text-foreground">이미지 스캔 교차검증 분석 결과</span></>}>
        {(() => {
          const fallbackSummary = sm?.summary || gate?.llm_analysis?.summary;
          const fallbackReasons = sm?.reasons?.length > 0 ? sm.reasons : (gate?.llm_analysis?.reasons || []);
          return (<div className="space-y-3 pt-3">
            {imgJ.length > 0 && <div className="grid grid-cols-2 gap-3"><div className="bg-muted rounded-md p-3 text-center"><div className="text-xl font-bold text-green-600">{confirmed.length}</div><div className="text-sm text-muted-foreground">동시 탐지</div></div><div className="bg-muted rounded-md p-3 text-center"><div className="text-xl font-bold text-amber-600">{review.length}</div><div className="text-sm text-muted-foreground">단독 탐지</div></div></div>}
            {fallbackSummary && <div className="bg-muted rounded-lg p-4"><div className="text-sm font-semibold text-foreground mb-2">LLM 분석 요약</div><div className="text-sm text-foreground leading-relaxed">{fallbackSummary}</div></div>}
            {fallbackReasons.length > 0 && <div className="space-y-2"><div className="text-sm font-semibold text-foreground">판정 근거</div>{fallbackReasons.map((r: string, i: number) => <div key={i} className="text-sm text-muted-foreground flex gap-2"><span className="text-foreground font-bold">•</span> {r}</div>)}</div>}
            {!fallbackSummary && imgVulns.length > 0 && <div className="bg-muted rounded-lg p-4"><div className="text-sm text-muted-foreground">이미지 스캔 {imgVulns.length}건이 확인되었습니다. 다음 CI/CD 실행 후 LLM 분석이 표시됩니다.</div></div>}
          </div>);
        })()}
      </Accordion>

      {/* 동시 탐지 */}
      {confirmed.length > 0 && (
        <Accordion title={<><span className="text-sm font-bold bg-red-600 text-white px-3 py-1 rounded">동시 탐지</span><span className="text-base font-semibold text-foreground">두 도구가 동시에 발견한 취약점</span></>}>
          <div className="space-y-4 pt-3">{confirmed.sort((a: any, b: any) => (_s[(a.reassessed_severity||a.severity||'LOW').toUpperCase()]??9)-(_s[(b.reassessed_severity||b.severity||'LOW').toUpperCase()]??9)).map((j: any, i: number) => {
            const sev = (j.reassessed_severity||j.severity||'HIGH').toUpperCase(); const sc = sev==='CRITICAL'?'bg-red-600':sev==='HIGH'?'bg-orange-600':'bg-yellow-600'; const fa=j.finding_a||{}; const fb=j.finding_b||{};
            return <div key={i} className="bg-red-50 border border-red-200 rounded-lg p-4"><div className="flex items-center gap-2 mb-1"><span className={`text-sm font-bold text-white px-2 py-0.5 rounded ${sc}`}>{sev}</span>{fa.cve_id && <span className="text-sm font-bold text-blue-700">{fa.cve_id}</span>}</div><div className="text-base font-semibold text-foreground mb-1">{j.title_ko || fa.title}</div><div className="grid grid-cols-2 gap-3 mb-3"><div className="bg-white rounded-lg border border-red-100 p-3"><div className="text-sm font-bold text-red-700">✓ {fa.tool} 탐지</div></div><div className="bg-white rounded-lg border border-red-100 p-3"><div className="text-sm font-bold text-red-700">✓ {fb.tool} 탐지</div></div></div>{j.risk_summary && <div className="bg-red-100 rounded-lg p-3 space-y-1"><div className="text-sm text-red-800"><strong>위험:</strong> {j.risk_summary}</div>{j.action_text && <div className="text-sm text-blue-800"><strong>수정 방법:</strong> {j.action_text}</div>}</div>}</div>;
          })}</div>
        </Accordion>
      )}

      {/* 단독 탐지 */}
      {review.length > 0 && (
        <Accordion title={<><span className="text-sm font-bold bg-amber-600 text-white px-3 py-1 rounded">단독 탐지</span><span className="text-base font-semibold text-foreground">한 도구에서만 발견 — 오탐 가능성</span></>} defaultOpen={false}>
          {(() => {
            const dedup = (items: any[]) => { const seen = new Set<string>(); return items.filter(j => { const k = j.title_ko || j.finding_a?.title || ''; if (seen.has(k)) return false; seen.add(k); return true; }); };
            const rA = dedup(review.filter((j: any) => (j.finding_a?.tool||'').includes('trivy')));
            const rB = dedup(review.filter((j: any) => (j.finding_a?.tool||'') === 'grype'));
            const renderItem = (j: any, i: number) => { const sev = (j.reassessed_severity||j.severity||'MEDIUM').toUpperCase(); const sc = sev==='CRITICAL'?'bg-red-600':sev==='HIGH'?'bg-orange-600':sev==='MEDIUM'?'bg-yellow-600':'bg-gray-500'; return <div key={i} className="bg-amber-50 border border-amber-100 rounded p-3"><div className="flex items-center gap-2 mb-1"><span className={`text-xs font-bold text-white px-1.5 py-0.5 rounded ${sc}`}>{sev}</span></div><div className="text-sm font-medium">{j.title_ko||j.finding_a?.title}</div></div>; };
            return <div className="grid grid-cols-2 gap-4 pt-3"><div><div className="text-sm font-bold mb-2 bg-muted rounded p-2">Trivy ({rA.length}건)</div><div className="space-y-2">{rA.length>0?rA.map(renderItem):<div className="text-sm text-muted-foreground p-3">단독 탐지 없음</div>}</div></div><div><div className="text-sm font-bold mb-2 bg-muted rounded p-2">Grype ({rB.length}건)</div><div className="space-y-2">{rB.length>0?rB.map(renderItem):<div className="text-sm text-muted-foreground p-3">단독 탐지 없음</div>}</div></div></div>;
          })()}
        </Accordion>
      )}

      {/* 도구별 탐지 현황 */}
      {(() => {
        const toolStats = (toolFilter: (v: any) => boolean, label: string) => {
          const tv = imgVulns.filter(toolFilter);
          const c = tv.filter(v => v.severity === 'CRITICAL').length;
          const h = tv.filter(v => v.severity === 'HIGH').length;
          const m = tv.filter(v => v.severity === 'MEDIUM').length;
          const l = tv.filter(v => v.severity === 'LOW').length;
          return <div className="bg-muted rounded-md p-3"><div className="flex items-center justify-between mb-1"><span className="text-xs font-bold">{label}</span><span className="text-xs text-muted-foreground">총 {tv.length}건</span></div><div className="flex gap-2 mt-1">{c > 0 && <span className="text-xs font-bold text-red-600">C:{c}</span>}{h > 0 && <span className="text-xs font-bold text-orange-600">H:{h}</span>}{m > 0 && <span className="text-xs font-bold text-yellow-600">M:{m}</span>}{l > 0 && <span className="text-xs font-bold text-blue-600">L:{l}</span>}</div></div>;
        };
        return <div className="bg-card rounded-lg border border-border shadow-sm p-4"><h3 className="text-sm font-semibold text-foreground mb-3">도구별 탐지 현황</h3><div className="grid grid-cols-2 gap-3">{toolStats(v => v.tool?.includes('trivy'), 'Trivy')}{toolStats(v => v.tool === 'grype', 'Grype')}</div></div>;
      })()}

      {/* 취약점 목록 */}
      <VulnerabilityTable vulnerabilities={imgVulns} judgments={imgJ} category="IMAGE" />
    </>
  );
}

// DAST 전체 섹션 — SAST/SCA와 동일 구조
function DastFullSection({ gates, judgments, summaries }: { gates: Record<string, any>; judgments: Record<string, any[]>; summaries?: Record<string, any> }) {
  const [dastVulnsApi, setDastVulnsApi] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    fetchJson<any>('/vulns?category=DAST&limit=50').then(res => {
      const _s: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
      const vulns = (res?.vulnerabilities || [])
        .filter((v: any) => (v.severity || '').toUpperCase() !== 'INFO')
        .sort((a: any, b: any) => (_s[(a.severity || 'LOW').toUpperCase()] ?? 9) - (_s[(b.severity || 'LOW').toUpperCase()] ?? 9))
        .map((v: any, i: number) => ({
          id: `dast-api-${i}`,
          severity: (v.severity || 'MEDIUM').toUpperCase(),
          category: 'DAST',
          tool: v.tool || 'zap',
          file: v.url || v.file_path || '',
          line: 0,
          cwe: v.cwe_id || '',
          description: v.title || v.description || '',
          confidence: 'MED',
          detectedAt: v.created_at || new Date().toISOString(),
          _originalDesc: ((v.description || v.title || '') as string).replace(/<[^>]*>/g, ''),
        }));
      setDastVulnsApi(vulns);
    }).catch(() => {}).finally(() => setLoading(false));
  }, []);

  const gate = gates['dast'];
  const dastJ = judgments['dast'] || [];

  // judgments + vulns API 합치기
  const _s: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  const jVulns = dastJ.map((j: any, i: number) => {
        const fa = j.finding_a || {};
        return {
          id: `dast-j-${i}`,
          severity: (j.reassessed_severity || j.severity || fa.severity || 'MEDIUM').toUpperCase(),
          category: 'DAST',
          tool: fa.tool || 'zap',
          file: fa.url || fa.file_path || '',
          line: 0,
          cwe: fa.cwe_id || '',
          description: j.title_ko || fa.title || '',
          confidence: j.confidence || 'MED',
          detectedAt: new Date().toISOString(),
          _originalDesc: ((fa.description || fa.title || '') as string).replace(/<[^>]*>/g, ''),
          _judgment: j,
        };
      }).sort((a: any, b: any) => (_s[a.severity] ?? 9) - (_s[b.severity] ?? 9));

  // judgments에 없는 vulns API 데이터 추가 (nuclei 등)
  // judgment의 영어 title 기준으로 매칭
  const jTitles = new Set(jVulns.map((v: any) => `${v.tool}|${v._originalDesc}`));
  const extraVulns = dastVulnsApi.filter(v => !jTitles.has(`${v.tool}|${v._originalDesc}`));
  // extraVulns에도 CWE 기반 judgment 매칭 시도
  const extraWithJ = extraVulns.map(v => {
    if (v._judgment) return v;
    const j = (dastJ || []).find((j: any) => {
      const fa = j.finding_a || {};
      return fa.tool === v.tool && (fa.title || '') === (v._originalDesc || v.description);
    });
    return j ? { ...v, _judgment: j, description: j.title_ko || v.description } : v;
  });
  const dastVulns = [...jVulns, ...extraWithJ].sort((a: any, b: any) => (_s[a.severity] ?? 9) - (_s[b.severity] ?? 9));

  if (loading && dastJ.length === 0) return <div className="text-center py-10 text-muted-foreground">DAST 데이터 로딩 중...</div>;
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  dastVulns.forEach(v => { if (counts[v.severity as keyof typeof counts] !== undefined) counts[v.severity as keyof typeof counts]++; });

  if (dastVulns.length === 0 && !gate) {
    return <div className="bg-card rounded-lg border border-border p-8 text-center text-muted-foreground"><p className="text-sm">DAST 스캔 결과가 없습니다</p><p className="text-xs mt-1">CD 파이프라인에서 ZAP + Nuclei 스캔 후 표시됩니다</p></div>;
  }

  return (
    <>
      {/* Severity 카드 */}
      <div className="grid grid-cols-4 gap-3">
        {Object.entries(counts).map(([sev, count]) => {
          const colors: Record<string, string> = { CRITICAL: 'text-red-600 bg-red-50 border-red-200', HIGH: 'text-orange-600 bg-orange-50 border-orange-200', MEDIUM: 'text-yellow-600 bg-yellow-50 border-yellow-200', LOW: 'text-blue-600 bg-blue-50 border-blue-200' };
          const labels: Record<string, string> = { CRITICAL: '긴급 조치 필요', HIGH: '즉시 조치 필요', MEDIUM: '우선 검토 필요', LOW: '모니터링 권장' };
          return <div key={sev} className={`rounded-lg border p-4 ${colors[sev]}`}><div className="text-xs font-semibold uppercase">{sev}</div><div className="text-2xl font-bold mt-1">{count}</div><div className="text-xs mt-1">{labels[sev]}</div></div>;
        })}
      </div>

      {/* CI 교차검증 분석 결과 */}
      {gate && (
        <Accordion title={<><span className="text-sm font-bold bg-blue-600 text-white px-3 py-1 rounded">Gemini LLM</span><span className="text-base font-semibold text-foreground">DAST 교차검증 분석 결과</span></>}>
          {(() => {
            const sm = summaries?.['dast'] || {};
            const llm = gate?.llm_analysis || {};
            const fallbackSummary = sm?.summary || llm.summary;
            const fallbackReasons = sm?.reasons?.length > 0 ? sm.reasons : (llm.reasons || []);
            const zapCount = dastVulns.filter((v: any) => v.tool === 'zap').length;
            const nucleiCount = dastVulns.filter((v: any) => v.tool === 'nuclei').length;
            return (<div className="space-y-3 pt-3">
              <div className="grid grid-cols-2 gap-3"><div className="bg-muted rounded-md p-3 text-center"><div className="text-xl font-bold text-foreground">{zapCount}</div><div className="text-sm text-muted-foreground">ZAP 탐지</div></div><div className="bg-muted rounded-md p-3 text-center"><div className="text-xl font-bold text-foreground">{nucleiCount}</div><div className="text-sm text-muted-foreground">Nuclei 탐지</div></div></div>
              {fallbackSummary && <div className="bg-muted rounded-lg p-4"><div className="text-sm font-semibold text-foreground mb-2">LLM 분석 요약</div><div className="text-sm text-foreground leading-relaxed">{fallbackSummary}</div></div>}
              {fallbackReasons.length > 0 && <div className="space-y-2"><div className="text-sm font-semibold text-foreground">판정 근거</div>{fallbackReasons.map((r: string, i: number) => <div key={i} className="text-sm text-muted-foreground flex gap-2"><span className="text-foreground font-bold">•</span> {r}</div>)}</div>}
            </div>);
          })()}
        </Accordion>
      )}

      {/* 동시 탐지 */}
      {dastJ.length > 0 && (() => {
        const confirmed = dastJ.filter((j: any) => j.judgement_code === 'TRUE_POSITIVE' && j.finding_b);
        return confirmed.length > 0 ? (
          <Accordion title={<><span className="text-sm font-bold bg-red-600 text-white px-3 py-1 rounded">동시 탐지</span><span className="text-base font-semibold text-foreground">두 도구가 동시에 발견한 취약점</span></>}>
            <div className="space-y-4 pt-3">{confirmed.map((j: any, i: number) => {
              const sev = (j.reassessed_severity || j.severity || 'MEDIUM').toUpperCase();
              const sc = sev === 'CRITICAL' ? 'bg-red-600' : sev === 'HIGH' ? 'bg-orange-600' : 'bg-yellow-600';
              const fa = j.finding_a || {}; const fb = j.finding_b || {};
              return <div key={i} className="bg-red-50 border border-red-200 rounded-lg p-4"><div className="flex items-center gap-2 mb-1"><span className={`text-sm font-bold text-white px-2 py-0.5 rounded ${sc}`}>{sev}</span></div><div className="text-base font-semibold text-foreground mb-1">{j.title_ko || fa.title}</div><div className="grid grid-cols-2 gap-3 mb-3"><div className="bg-white rounded-lg border border-red-100 p-3"><div className="text-sm font-bold text-red-700">✓ {fa.tool}</div></div><div className="bg-white rounded-lg border border-red-100 p-3"><div className="text-sm font-bold text-red-700">✓ {fb.tool}</div></div></div>{j.risk_summary && <div className="bg-red-100 rounded-lg p-3 space-y-1"><div className="text-sm text-red-800"><strong>위험:</strong> {j.risk_summary}</div>{j.action_text && <div className="text-sm text-blue-800"><strong>수정 방법:</strong> {j.action_text}</div>}</div>}</div>;
            })}</div>
          </Accordion>
        ) : null;
      })()}

      {/* 단독 탐지 */}
      {dastJ.length > 0 && (() => {
        const review = dastJ.filter((j: any) => !(j.judgement_code === 'TRUE_POSITIVE' && j.finding_b));
        const tools = gate?.tool_summaries || [];
        const tA = tools[0]?.tool || 'zap'; const tB = tools[1]?.tool || 'nuclei';
        const rA = review.filter((j: any) => (j.finding_a?.tool || '').toLowerCase() === tA.toLowerCase());
        const rB = review.filter((j: any) => (j.finding_a?.tool || '').toLowerCase() === tB.toLowerCase());
        return (rA.length > 0 || rB.length > 0) ? (
          <Accordion title={<><span className="text-sm font-bold bg-amber-600 text-white px-3 py-1 rounded">단독 탐지</span><span className="text-base font-semibold text-foreground">한 도구에서만 발견 — 오탐 가능성</span></>}>
            <div className="grid grid-cols-2 gap-4 pt-3">
              <div><div className="text-sm font-bold mb-2 bg-muted rounded p-2">{tA} ({rA.length}건)</div><div className="space-y-2">{rA.length > 0 ? rA.map((j: any, i: number) => <div key={i} className="bg-amber-50 border border-amber-100 rounded p-3"><div className="flex items-center gap-2 mb-1"><span className={`text-xs font-bold text-white px-1.5 py-0.5 rounded ${(j.reassessed_severity || j.severity || '') === 'CRITICAL' ? 'bg-red-600' : (j.reassessed_severity || j.severity || '') === 'HIGH' ? 'bg-orange-600' : 'bg-yellow-600'}`}>{(j.reassessed_severity || j.severity || 'MEDIUM').toUpperCase()}</span></div><div className="text-sm font-medium">{j.title_ko || j.finding_a?.title}</div></div>) : <div className="text-sm text-muted-foreground p-3">탐지 없음</div>}</div></div>
              <div><div className="text-sm font-bold mb-2 bg-muted rounded p-2">{tB} ({rB.length}건)</div><div className="space-y-2">{rB.length > 0 ? rB.map((j: any, i: number) => <div key={i} className="bg-amber-50 border border-amber-100 rounded p-3"><div className="flex items-center gap-2 mb-1"><span className={`text-xs font-bold text-white px-1.5 py-0.5 rounded ${(j.reassessed_severity || j.severity || '') === 'CRITICAL' ? 'bg-red-600' : (j.reassessed_severity || j.severity || '') === 'HIGH' ? 'bg-orange-600' : 'bg-yellow-600'}`}>{(j.reassessed_severity || j.severity || 'MEDIUM').toUpperCase()}</span></div><div className="text-sm font-medium">{j.title_ko || j.finding_a?.title}</div></div>) : <div className="text-sm text-muted-foreground p-3">탐지 없음</div>}</div></div>
            </div>
          </Accordion>
        ) : null;
      })()}

      {/* 도구별 탐지 현황 */}
      {(() => {
        const toolStats = (toolFilter: (v: any) => boolean, label: string) => {
          const tv = dastVulns.filter(toolFilter);
          const c = tv.filter(v => v.severity === 'CRITICAL').length;
          const h = tv.filter(v => v.severity === 'HIGH').length;
          const m = tv.filter(v => v.severity === 'MEDIUM').length;
          const l = tv.filter(v => v.severity === 'LOW').length;
          return <div className="bg-muted rounded-md p-3"><div className="flex items-center justify-between mb-1"><span className="text-xs font-bold">{label}</span><span className="text-xs text-muted-foreground">총 {tv.length}건</span></div><div className="flex gap-2 mt-1">{c > 0 && <span className="text-xs font-bold text-red-600">C:{c}</span>}{h > 0 && <span className="text-xs font-bold text-orange-600">H:{h}</span>}{m > 0 && <span className="text-xs font-bold text-yellow-600">M:{m}</span>}{l > 0 && <span className="text-xs font-bold text-blue-600">L:{l}</span>}</div></div>;
        };
        return <div className="bg-card rounded-lg border border-border shadow-sm p-4"><h3 className="text-sm font-semibold text-foreground mb-3">도구별 탐지 현황</h3><div className="grid grid-cols-2 gap-3">{toolStats(v => v.tool === 'zap', 'ZAP')}{toolStats(v => v.tool === 'nuclei', 'Nuclei')}</div></div>;
      })()}

      {/* 취약점 목록 */}
      <VulnerabilityTable vulnerabilities={dastVulns} judgments={dastJ} category="DAST" />
    </>
  );
}

// (레거시) DAST 섹션
function DastSection() {
  const [dastVulns, setDastVulns] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    fetchJson<any>('/vulns?category=DAST&limit=50').then(res => {
      const vulns = (res?.vulnerabilities || []).filter((v: any) => (v.severity || '').toUpperCase() !== 'INFO').map((v: any, i: number) => ({
        id: `dast-${i}`,
        severity: (v.severity || 'MEDIUM').toUpperCase(),
        category: 'DAST',
        tool: v.tool || 'zap',
        file: v.file_path || v.cwe_id || '',
        line: v.line_number || 0,
        cwe: v.cwe_id || '',
        description: v.title || v.description || '',
        confidence: 'MED',
        detectedAt: v.created_at || new Date().toISOString(),
      }));
      setDastVulns(vulns);
    }).catch(() => {}).finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="text-center py-10 text-muted-foreground">DAST 데이터 로딩 중...</div>;

  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  dastVulns.forEach(v => { if (counts[v.severity as keyof typeof counts] !== undefined) counts[v.severity as keyof typeof counts]++; });

  const zapCount = dastVulns.filter(v => v.tool === 'zap').length;
  const nucleiCount = dastVulns.filter(v => v.tool === 'nuclei').length;

  return (
    <>
      {dastVulns.length === 0 ? (
        <div className="bg-card rounded-lg border border-border p-8 text-center text-muted-foreground">
          <p className="text-sm">DAST 스캔 결과가 없습니다</p>
          <p className="text-xs mt-1">CD 파이프라인에서 ZAP + Nuclei 스캔 후 표시됩니다</p>
        </div>
      ) : (
        <>
          {/* Severity 카드 */}
          <div className="grid grid-cols-5 gap-3">
            {Object.entries(counts).filter(([k]) => k !== 'INFO').map(([sev, count]) => {
              const colors: Record<string, string> = { CRITICAL: 'text-red-600 bg-red-50 border-red-200', HIGH: 'text-orange-600 bg-orange-50 border-orange-200', MEDIUM: 'text-yellow-600 bg-yellow-50 border-yellow-200', LOW: 'text-blue-600 bg-blue-50 border-blue-200' };
              return (
                <div key={sev} className={`rounded-lg border p-4 ${colors[sev] || ''}`}>
                  <div className="text-xs font-semibold uppercase">{sev}</div>
                  <div className="text-2xl font-bold mt-1">{count}</div>
                </div>
              );
            })}
            <div className="rounded-lg border p-4 text-muted-foreground bg-muted/50 border-border">
              <div className="text-xs font-semibold uppercase">INFO</div>
              <div className="text-2xl font-bold mt-1">{counts.INFO}</div>
            </div>
          </div>

          {/* 도구별 현황 */}
          <div className="bg-card rounded-lg border border-border shadow-sm p-4">
            <h3 className="text-sm font-semibold text-foreground mb-3">도구별 탐지 현황</h3>
            <div className="grid grid-cols-2 gap-3">
              <div className="bg-muted rounded-md p-3">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-bold">ZAP</span>
                  <span className="text-xs text-muted-foreground">총 {zapCount}건</span>
                </div>
              </div>
              <div className="bg-muted rounded-md p-3">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-bold">Nuclei</span>
                  <span className="text-xs text-muted-foreground">총 {nucleiCount}건</span>
                </div>
              </div>
            </div>
          </div>

          {/* 취약점 목록 */}
          <VulnerabilityTable vulnerabilities={dastVulns} category="DAST" />
        </>
      )}
    </>
  );
}

// 파이프라인 실행 이력 타임라인
function PipelineTimeline() {
  const [history, setHistory] = useState<Array<{ time: string; gate: string; commit: string }>>([]);
  useEffect(() => {
    fetchJson<{ history: any[] }>('/cross/history').then(res => {
      const data = (res?.history || [])
        .filter((h: any) => h.commit_hash)
        .slice(0, 10)
        .map((h: any) => ({
          time: new Date(h.generated_at).toLocaleString('ko-KR', { month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit' }),
          gate: h.gate_decision || 'ALLOW',
          commit: h.commit_hash?.slice(0, 7) || '',
        }));
      setHistory(data);
    }).catch(() => {});
  }, []);

  if (history.length === 0) return null;

  return (
    <div className="bg-card rounded-lg border border-border shadow-sm p-5">
      <h3 className="text-sm font-bold text-foreground mb-1">파이프라인 실행 이력</h3>
      <p className="text-xs text-muted-foreground mb-4">최근 게이트 판정 변화</p>
      <div className="space-y-2">
        {history.map((h, i) => {
          const icon = h.gate === 'BLOCK' ? '🔴' : h.gate === 'REVIEW' ? '🟡' : '🟢';
          const color = h.gate === 'BLOCK' ? 'text-red-600' : h.gate === 'REVIEW' ? 'text-amber-600' : 'text-green-600';
          return (
            <div key={i} className="flex items-center gap-3 py-1.5 border-b border-border last:border-0">
              <span className="text-base">{icon}</span>
              <span className={`text-sm font-bold w-16 ${color}`}>{h.gate}</span>
              <span className="text-xs text-muted-foreground flex-1">{h.time}</span>
              <code className="text-xs bg-muted px-2 py-0.5 rounded font-mono text-foreground">{h.commit}</code>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// Gate 기반 교차검증 비교 카드
function GateCrossValidation({ gate, judgments }: { gate: any; judgments?: any[] }) {
  if (!gate && (!judgments || judgments.length === 0)) return null;

  // judgments 기반 동시탐지 / 단독탐지 분리
  // 동시탐지 = TRUE_POSITIVE + finding_b 있음 (두 도구 모두 탐지), 최대 3건
  const _sevOrder: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  const confirmed = (judgments || [])
    .filter((j: any) => j.judgement_code === 'TRUE_POSITIVE' && j.finding_b)
    .sort((a: any, b: any) => (_sevOrder[(a.reassessed_severity || a.severity || 'LOW').toUpperCase()] ?? 9) - (_sevOrder[(b.reassessed_severity || b.severity || 'LOW').toUpperCase()] ?? 9));
  const reviewNeeded = (judgments || []).filter((j: any) => {
    return j.judgement_code === 'REVIEW_NEEDED' || (j.judgement_code === 'TRUE_POSITIVE' && !j.finding_b);
  });
  const tools = gate?.tool_summaries || [];
  const toolAName = tools[0]?.tool || '도구A';
  const toolBName = tools[1]?.tool || '도구B';
  const toolAReview = reviewNeeded.filter((j: any) => (j.finding_a?.tool || '').toLowerCase() === toolAName.toLowerCase()).slice(0, 5);
  const toolBReview = reviewNeeded.filter((j: any) => (j.finding_a?.tool || '').toLowerCase() !== toolAName.toLowerCase()).slice(0, 5);

  return (
    <div className="space-y-4">
      {/* 동시 탐지 — judgments의 TRUE_POSITIVE */}
      {confirmed.length > 0 && (
        <div className="bg-card rounded-lg border-2 border-red-200 shadow-sm p-5">
          <div className="flex items-center gap-2 mb-4">
            <span className="text-sm font-bold bg-red-600 text-white px-3 py-1 rounded">동시 탐지</span>
            <span className="text-base font-semibold text-foreground">두 도구가 동시에 발견 — 실제 취약점</span>
            <span className="text-sm text-red-600 font-bold">({confirmed.length}건)</span>
          </div>
          <div className="space-y-4">
            {confirmed.map((j: any, i: number) => {
              const sev = (j.reassessed_severity || j.severity || 'HIGH').toUpperCase();
              const sevColor = sev === 'CRITICAL' ? 'bg-red-600' : sev === 'HIGH' ? 'bg-orange-600' : 'bg-yellow-600';
              const fa = j.finding_a || {};
              const fb = j.finding_b || {};
              return (
                <div key={i} className="bg-red-50 border border-red-200 rounded-lg p-4">
                  <div className="flex items-center gap-2 mb-1">
                    <span className={`text-sm font-bold text-white px-2 py-0.5 rounded ${sevColor}`}>{sev}</span>
                    {fa.cwe_id && <span className="text-sm font-bold text-blue-700">{fa.cwe_id}</span>}
                  </div>
                  <div className="text-base font-semibold text-foreground mb-1">{j.title_ko}</div>
                  {fa.file_path && <div className="text-sm text-muted-foreground mb-3">📁 {fa.file_path}{fa.line_number ? `:${fa.line_number}` : ''}</div>}
                  <div className="grid grid-cols-2 gap-3 mb-3">
                    <div className="bg-white rounded-lg border border-red-100 p-3">
                      <div className="text-sm font-bold text-red-700 mb-1">✓ {fa.tool} 탐지</div>
                      <div className="text-xs text-muted-foreground">{fa.rule_id || fa.cwe_id || ''}</div>
                    </div>
                    <div className="bg-white rounded-lg border border-red-100 p-3">
                      <div className="text-sm font-bold text-red-700 mb-1">✓ {fb.tool || toolBName} 탐지</div>
                      <div className="text-xs text-muted-foreground">{fb.rule_id || fb.cwe_id || ''}</div>
                    </div>
                  </div>
                  <div className="bg-red-100 rounded-lg p-3 space-y-1">
                    {j.risk_summary && <div className="text-sm text-red-800"><strong>위험:</strong> {j.risk_summary}</div>}
                    {j.action_text && <div className="text-sm text-blue-800"><strong>수정 방법:</strong> {j.action_text}</div>}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* 단독 탐지 — judgments의 REVIEW_NEEDED */}
      {(toolAReview.length > 0 || toolBReview.length > 0) && (
        <div className="bg-card rounded-lg border border-border shadow-sm p-5">
          <div className="flex items-center gap-2 mb-4">
            <span className="text-sm font-bold bg-amber-600 text-white px-3 py-1 rounded">단독 탐지</span>
            <span className="text-base font-semibold text-foreground">한 도구에서만 발견 — 오탐 가능성</span>
            <span className="text-sm text-amber-600"></span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <div className="text-sm font-bold text-foreground mb-2 bg-muted rounded p-2">{toolAName} ({toolAReview.length}건)</div>
              <div className="space-y-2">
                {toolAReview.length > 0 ? toolAReview.map((j: any, i: number) => (
                  <div key={i} className="bg-amber-50 border border-amber-100 rounded p-3">
                    <div className="flex items-center gap-2 mb-1">
                      <span className={`text-xs font-bold text-white px-1.5 py-0.5 rounded ${j.severity === 'CRITICAL' ? 'bg-red-600' : 'bg-orange-600'}`}>{j.severity}</span>
                    </div>
                    <div className="text-sm font-medium text-foreground">{j.title_ko || j.finding_a?.title}</div>
                    {j.finding_a?.file_path && <div className="text-xs text-muted-foreground mt-1">📁 {j.finding_a.file_path}</div>}
                  </div>
                )) : <div className="text-sm text-muted-foreground p-3">Critical/High 없음</div>}
              </div>
            </div>
            <div>
              <div className="text-sm font-bold text-foreground mb-2 bg-muted rounded p-2">{toolBName} ({toolBReview.length}건)</div>
              <div className="space-y-2">
                {toolBReview.length > 0 ? toolBReview.map((j: any, i: number) => (
                  <div key={i} className="bg-amber-50 border border-amber-100 rounded p-3">
                    <div className="flex items-center gap-2 mb-1">
                      <span className={`text-xs font-bold text-white px-1.5 py-0.5 rounded ${j.severity === 'CRITICAL' ? 'bg-red-600' : 'bg-orange-600'}`}>{j.severity}</span>
                    </div>
                    <div className="text-sm font-medium text-foreground">{j.title_ko || j.finding_a?.title}</div>
                    {j.finding_a?.file_path && <div className="text-xs text-muted-foreground mt-1">📁 {j.finding_a.file_path}</div>}
                  </div>
                )) : <div className="text-sm text-muted-foreground p-3">Critical/High 없음</div>}
              </div>
            </div>
          </div>
        </div>
      )}

      {confirmed.length === 0 && toolAReview.length === 0 && toolBReview.length === 0 && (
        <div className="bg-card rounded-lg border border-border p-6 text-center text-muted-foreground text-sm">
          LLM 개별 판정 데이터가 없습니다. 다음 CI 실행 후 표시됩니다.
        </div>
      )}
    </div>
  );
}

// 실제 취약점 데이터 기반 Severity 카드
function VulnSeverityCards({ vulns }: { vulns: Vulnerability[] }) {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  vulns.forEach(v => { if (counts[v.severity as keyof typeof counts] !== undefined) counts[v.severity as keyof typeof counts]++; });
  const colors: Record<string, string> = { CRITICAL: 'text-red-600 bg-red-50 border-red-200', HIGH: 'text-orange-600 bg-orange-50 border-orange-200', MEDIUM: 'text-yellow-600 bg-yellow-50 border-yellow-200', LOW: 'text-blue-600 bg-blue-50 border-blue-200' };
  const labels: Record<string, string> = { CRITICAL: '긴급 조치 필요', HIGH: '즉시 조치 필요', MEDIUM: '우선 검토 필요', LOW: '모니터링 권장' };
  return (
    <div className="grid grid-cols-4 gap-3">
      {Object.entries(counts).map(([sev, count]) => (
        <div key={sev} className={`rounded-lg border p-4 ${colors[sev]}`}>
          <div className="text-xs font-semibold uppercase">{sev}</div>
          <div className="text-2xl font-bold mt-1">{count}</div>
          <div className="text-xs mt-1">{labels[sev]}</div>
        </div>
      ))}
    </div>
  );
}

// Gate 기반 Severity 카드
function GateSeverityCards({ gate }: { gate: any }) {
  if (!gate) return null;
  const combined = gate.combined_summary || {};
  const confirmed = gate.confirmed_summary || {};

  const cards = [
    { label: 'CRITICAL', count: combined.critical || 0, confirmed: confirmed.critical || 0, color: 'text-red-600', bg: 'bg-red-50', desc: '긴급 조치 필요' },
    { label: 'HIGH', count: combined.high || 0, confirmed: confirmed.high || 0, color: 'text-orange-600', bg: 'bg-orange-50', desc: '즉시 조치 필요' },
    { label: 'MEDIUM', count: combined.medium || 0, confirmed: confirmed.medium || 0, color: 'text-amber-600', bg: 'bg-amber-50', desc: '우선 검토 필요' },
    { label: 'LOW', count: combined.low || 0, confirmed: confirmed.low || 0, color: 'text-blue-600', bg: 'bg-blue-50', desc: '모니터링 권장' },
  ];

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
      {cards.map((c) => (
        <div key={c.label} className={`${c.bg} rounded-lg border border-border p-4`}>
          <div className="flex items-center justify-between mb-1">
            <span className="text-xs font-bold text-muted-foreground">{c.label}</span>
            {c.confirmed > 0 && <span className="text-xs bg-red-600 text-white px-1.5 py-0.5 rounded">동시탐지 {c.confirmed}</span>}
          </div>
          <div className={`text-2xl font-bold ${c.color}`}>{c.count}</div>
          <div className="text-xs text-muted-foreground">{c.desc}</div>
        </div>
      ))}
    </div>
  );
}

// Gate 기반 도구별 요약
function GateToolSummary({ gate, judgments }: { gate: any; judgments?: any[] }) {
  // judgments 기반으로 도구별 집계
  const toolStats = useMemo(() => {
    if (!judgments || judgments.length === 0) {
      // 폴백: gate 데이터
      return (gate?.tool_summaries || []).map((t: any) => ({
        tool: t.tool,
        total: t.summary?.total || 0,
        critical: t.summary?.critical || 0,
        high: t.summary?.high || 0,
        medium: t.summary?.medium || 0,
        low: t.summary?.low || 0,
      }));
    }
    const map = new Map<string, { tool: string; critical: number; high: number; medium: number; low: number; total: number }>();
    judgments.forEach((j: any) => {
      const tool = j.finding_a?.tool || 'unknown';
      if (!map.has(tool)) map.set(tool, { tool, critical: 0, high: 0, medium: 0, low: 0, total: 0 });
      const s = map.get(tool)!;
      const sev = (j.reassessed_severity || j.severity || 'MEDIUM').toUpperCase();
      if (sev === 'CRITICAL') s.critical++;
      else if (sev === 'HIGH') s.high++;
      else if (sev === 'MEDIUM') s.medium++;
      else s.low++;
      s.total++;
      // finding_b도 있으면 (동시탐지) 그 도구도 집계
      if (j.finding_b?.tool && j.finding_b.tool !== tool) {
        const toolB = j.finding_b.tool;
        if (!map.has(toolB)) map.set(toolB, { tool: toolB, critical: 0, high: 0, medium: 0, low: 0, total: 0 });
        const sb = map.get(toolB)!;
        if (sev === 'CRITICAL') sb.critical++;
        else if (sev === 'HIGH') sb.high++;
        else if (sev === 'MEDIUM') sb.medium++;
        else sb.low++;
        sb.total++;
      }
    });
    return Array.from(map.values());
  }, [judgments, gate]);

  if (toolStats.length === 0) return null;

  return (
    <div className="bg-card rounded-lg border border-border shadow-sm p-4">
      <h3 className="text-sm font-semibold text-foreground mb-3">도구별 탐지 현황</h3>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {toolStats.map((s: any, i: number) => (
          <div key={i} className="bg-muted rounded-md p-3">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-bold text-foreground">{s.tool}</span>
              <span className="text-xs text-muted-foreground">총 {s.total}건</span>
            </div>
            <div className="flex gap-2">
              {s.critical > 0 && <span className="text-xs bg-red-100 text-red-700 px-1.5 py-0.5 rounded font-bold">C:{s.critical}</span>}
              {s.high > 0 && <span className="text-xs bg-orange-100 text-orange-700 px-1.5 py-0.5 rounded font-bold">H:{s.high}</span>}
              {s.medium > 0 && <span className="text-xs bg-yellow-100 text-yellow-700 px-1.5 py-0.5 rounded font-bold">M:{s.medium}</span>}
              {s.low > 0 && <span className="text-xs bg-blue-100 text-blue-700 px-1.5 py-0.5 rounded font-bold">L:{s.low}</span>}
              {s.total === 0 && <span className="text-xs text-muted-foreground">탐지 없음</span>}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

interface HomeProps {
  params: {
    id?: string;
  };
}

export default function Home({ params }: HomeProps) {
  const [, setLocation] = useLocation();
  const [activeSection, setActiveSection] = useState(PIPELINE_STAGES[0].id);

  // 배포 ID에 해당하는 데이터 찾기
  const deployment = useMemo(() => {
    if (params?.id) {
      return mockDeployments.find((d) => d.id === params.id);
    }
    return mockDeployments[0]; // 기본값: 첫 번째 배포
  }, [params?.id]);

  const [summary, setSummary] = useState<ScanSummary>(deployment?.scanSummary || mockScanSummary);
  const [apiVulns, setApiVulns] = useState<Vulnerability[]>([]);
  const [apiCross, setApiCross] = useState<CrossAnalysisItem[]>([]);
  const [apiLoaded, setApiLoaded] = useState(false);
  const [apiIsmsData, setApiIsmsData] = useState<any>(null);
  const [ismsFilter, setIsmsFilter] = useState<string>('all');
  const [ismsOpenSections, setIsmsOpenSections] = useState<Record<string, boolean>>({});
  const [apiSiemData, setApiSiemData] = useState<any>(null);
  const [llmGates, setLlmGates] = useState<Record<string, any>>({});
  const [llmJudgments, setLlmJudgments] = useState<Record<string, any[]>>({});
  const [llmSummaries, setLlmSummaries] = useState<Record<string, any>>({});

  // judgments 기반 데이터 로드 (매칭 불필요 — judgment에 한국어+원본 모두 포함)
  useEffect(() => {
    const cleanCwe = (cwe: string) => {
      if (!cwe) return '';
      const m = cwe.match(/^(CWE-\d+)/i);
      return m ? m[1] : cwe;
    };

    fetchJson<any>('/cross/gates').then((gatesData) => {
      if (!gatesData) return;
      console.log('gatesData keys:', Object.keys(gatesData));
      console.log('gatesData.gates keys:', Object.keys(gatesData.gates || {}));
      console.log('gatesData.judgments keys:', Object.keys(gatesData.judgments || {}));
      console.log('gatesData.gates.judgments?', !!gatesData.gates?.judgments);
      const rawGates = gatesData.gates || {};

      // judgments 찾기 — top-level을 우선 (merge된 데이터)
      let jByStage: Record<string, any[]> = {};
      const paths = [
        gatesData.judgments,                  // top.judgments (merge된 전체)
        gatesData.judgments?.judgments,       // top.judgments.judgments
        gatesData.judgments?.gate_result?.judgments,
        rawGates.judgments?.judgments,        // gates.judgments.judgments (최신 1건만)
        rawGates.judgments?.gate_result?.judgments,
      ];
      for (const p of paths) {
        if (p && typeof p === 'object' && (p.sast || p.sca || p.iac || p.dast)) {
          jByStage = p;
          break;
        }
      }

      // gates에서 judgments 키 제거 (gate 데이터만)
      const cleanGates = { ...rawGates };
      delete cleanGates.judgments;
      setLlmGates(cleanGates);

      // summaries 추출 — top-level 우선 (merge된 데이터)
      const sm = gatesData.summaries
        || rawGates.judgments?.summaries
        || rawGates.judgments?.gate_result?.summaries
        || {};
      setLlmSummaries(sm);
      setLlmJudgments(jByStage);

      // judgments → Vulnerability + CrossAnalysisItem 변환
      const vulns: Vulnerability[] = [];
      const crossItems: CrossAnalysisItem[] = [];
      const now = new Date().toISOString();

      Object.entries(jByStage).forEach(([stage, items]) => {
        if (!Array.isArray(items)) return;
        items.forEach((j: any, i: number) => {
          const fa = j.finding_a || {};
          const fb = j.finding_b || {};
          const hasBoth = !!fb.tool && fb.tool !== fa.tool;
          const cat = (fa.category || stage).toUpperCase();
          const isSCA = cat === 'SCA';
          const isIMAGE = cat === 'IMAGE' || stage === 'image';
          // IMAGE 카테고리에서 tool명 정규화
          if (isIMAGE) {
            if (fa.tool === 'trivy') fa.tool = 'trivy-image';
            if (fb.tool === 'trivy') fb.tool = 'trivy-image';
          }

          // finding_a 행
          if (fa.tool) {
            vulns.push({
              id: `j-${stage}-${i}-a`,
              severity: (j.reassessed_severity || j.severity || fa.severity || 'MEDIUM').toUpperCase() as any,
              category: cat,
              tool: fa.tool,
              file: fa.file_path || '',
              line: fa.line_number || 0,
              cwe: isSCA ? (fa.cve_id || cleanCwe(fa.cwe_id || '')) : cleanCwe(fa.cwe_id || ''),
              description: j.title_ko || fa.title || '',
              confidence: hasBoth ? 'HIGH' : (j.confidence || 'MED'),
              detectedAt: now,
              _judgment: j,
              _originalDesc: fa.title || fa.description || '',
            } as any);
          }

          // finding_b 행 (다른 도구)
          if (hasBoth) {
            vulns.push({
              id: `j-${stage}-${i}-b`,
              severity: (j.reassessed_severity || j.severity || fb.severity || 'MEDIUM').toUpperCase() as any,
              category: cat,
              tool: fb.tool,
              file: fb.file_path || '',
              line: fb.line_number || 0,
              cwe: isSCA ? (fb.cve_id || cleanCwe(fb.cwe_id || '')) : cleanCwe(fb.cwe_id || ''),
              description: j.title_ko || fb.title || '',
              _originalDesc: fb.title || fb.description || '',
              confidence: 'HIGH',
              detectedAt: now,
              _judgment: j,
            } as any);
          }

          // CrossAnalysisItem
          crossItems.push({
            id: `jc-${stage}-${i}`,
            severity: (j.severity || 'MEDIUM').toUpperCase() as any,
            category: cat,
            tools: [fa.tool, fb.tool].filter(Boolean),
            file: fa.file_path || fb.file_path || '',
            line: fa.line_number || fb.line_number || 0,
            cwe: cleanCwe(fa.cwe_id || fb.cwe_id || ''),
            description: j.title_ko || fa.title || '',
            confidence: (j.confidence || 'MED') as any,
            detectionCount: hasBoth ? 2 : 1,
          });
        });
      });

      if (vulns.length > 0) {
        setApiVulns(vulns);
        setApiCross(crossItems);
        setApiLoaded(true);
      }
    }).catch(() => {});

    // ISMS-P 데이터 로드
    fetchJson<any>('/isms').then((data) => {
      if (!data || data.message) return;
      // CD에서 보낸 데이터는 checker_result 안에 있음
      const ismsData = data.checker_result || data;
      setApiIsmsData(ismsData);
    }).catch(() => {});

    // SIEM 데이터 로드
    fetchJson<any>('/siem').then((data) => {
      if (!data || data.message) return;
      setApiSiemData(data);
    }).catch(() => {});
  }, []);

  // judgments 기반 데이터 사용, 없으면 mock fallback
  const vulnerabilities = apiLoaded ? apiVulns : mockVulnerabilities;
  const crossAnalysisItems = apiLoaded ? apiCross : mockCrossAnalysis;

  const handleScanComplete = useCallback((type: 'security' | 'cross' | 'isms' | 'refresh') => {
    const messages = {
      security: '보안 스캔이 완료되었습니다.',
      cross: '교차 분석이 완료되었습니다.',
      isms: 'ISMS-P 점검이 완료되었습니다.',
      refresh: '결과가 갱신되었습니다.',
    };
    toast.success(messages[type], {
      description: new Date().toLocaleString('ko-KR'),
      duration: 3000,
    });
    setSummary((prev) => ({
      ...prev,
      lastScanTime: new Date().toISOString(),
    }));
  }, []);

  const {
    scanState,
    pipelineStatus,
    pipelineStage,
    pipelineProgress,
    handleRefresh,
    handleSecurityScan,
    handleCrossAnalysis,
    handleIsmpCheck,
  } = useScanState(handleScanComplete);

  const currentSummary: ScanSummary = {
    ...summary,
    pipelineStatus,
    pipelineStage,
    pipelineProgress,
  };

  //const activeStageLabel = PIPELINE_STAGES.find((s) => s.id === activeSection)?.label ?? '';
  const activeStageLabel =
    PIPELINE_STAGES.find((s) => s.id === activeSection)?.label ??
    (activeSection === 'isms' ? 'ISMS-P' :
      activeSection === 'siem' ? '모니터링' :
        activeSection === 'aws' ? 'AWS 리소스 현황' : '');

  const isPipelineStage = [...SCAN_STAGES, CROSS_STAGE].some(stage => stage.id === activeSection);



  return (
    <div className="min-h-screen bg-background">
      {/* Deployment Header */}
      {deployment && (
        <div
          className="border-b border-border bg-card cursor-pointer hover:bg-muted/50 transition-colors"
          onClick={() => setLocation('/')}
        >
          <div className="max-w-[1400px] mx-auto px-4 sm:px-6 py-2 flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div>
                <ArrowLeft size={18} className="text-foreground" />
              </div>
              <div>
                <h1 className="text-base font-semibold text-foreground">{deployment.name}</h1>
                <p className="text-sm text-muted-foreground">
                  v{deployment.version} • {deployment.environment === 'prod' ? '프로덕션' : deployment.environment === 'staging' ? 'Staging' : 'Development'} •{' '}
                  {new Date(deployment.deployedAt).toLocaleDateString('ko-KR')}
                </p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Top navigation */}
      <Sidebar activeSection={activeSection} onSectionChange={setActiveSection} />

      {/* Content */}
      <main className="flex-1 overflow-y-auto">
        <div className="mx-auto w-full max-w-6xl px-6 sm:px-10 lg:px-16 py-6 space-y-5">
          {/* Section breadcrumb */}
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <span>대시보드</span>
            <span>/</span>
            <span className="text-foreground font-medium">{activeStageLabel}</span>
          </div>

          {/* Pipeline stages bar - only show for pipeline stages */}
          {isPipelineStage && (
            <div className="bg-card rounded-lg border border-border shadow-sm p-4">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-3">
                  <h2 className="text-sm font-semibold text-foreground">DevSecOps 파이프라인</h2>
                  <div className="flex items-center gap-2">
                    <div
                      className={`w-2 h-2 rounded-full`}
                      style={{ backgroundColor: (() => {
                        if (Object.keys(llmGates).length > 0) {
                          const hasBlock = Object.values(llmGates).some((g: any) => ['block', 'fail'].includes((g?.decision || g?.gate_result || g?.llm_analysis?.recommended_decision || '').toLowerCase()));
                          return hasBlock ? '#ef4444' : '#10b981';
                        }
                        return pipelineStatus === 'success' ? '#10b981' : pipelineStatus === 'failed' ? '#ef4444' : pipelineStatus === 'running' ? '#f59e0b' : '#94a3b8';
                      })() }}
                    />
                    <span className="text-xs font-medium" style={{ color: (() => {
                      if (Object.keys(llmGates).length > 0) {
                        const hasBlock = Object.values(llmGates).some((g: any) => ['block', 'fail'].includes((g?.decision || g?.gate_result || g?.llm_analysis?.recommended_decision || '').toLowerCase()));
                        return hasBlock ? '#ef4444' : '#10b981';
                      }
                      return pipelineStatus === 'success' ? '#10b981' : pipelineStatus === 'failed' ? '#ef4444' : pipelineStatus === 'running' ? '#f59e0b' : '#94a3b8';
                    })() }}>
                      {(() => {
                        if (Object.keys(llmGates).length > 0) {
                          const hasBlock = Object.values(llmGates).some((g: any) => ['block', 'fail'].includes((g?.decision || g?.gate_result || g?.llm_analysis?.recommended_decision || '').toLowerCase()));
                          return hasBlock ? 'BLOCK' : 'ALLOW';
                        }
                        return pipelineStatus === 'success' ? 'SUCCESS' : pipelineStatus === 'failed' ? 'FAILED' : pipelineStatus === 'running' ? 'RUNNING' : 'IDLE';
                      })()}
                    </span>
                  </div>
                </div>
                <div className="text-xs text-muted-foreground">
                  {PIPELINE_STAGES.length} 단계 진행 중
                </div>
              </div>
              {(() => {
                const stageId = stageIdFromPipelineText(pipelineStage || deployment?.scanSummary?.pipelineStage);
                const isFailure = (pipelineStage || deployment?.scanSummary?.pipelineStage || '').includes('실패');
                const currentId = stageId ?? PIPELINE_STAGES[0].id;
                const currentIdx = Math.max(0, PIPELINE_STAGES.findIndex((s) => s.id === currentId));
                const progress = typeof pipelineProgress === 'number'
                  ? pipelineProgress
                  : (deployment?.scanSummary?.pipelineProgress ?? 0);

                return (
                  <div className="pb-2">
                    {(() => {
                      const renderStep = (
                        stage: (typeof PIPELINE_STAGES)[number],
                        index: number,
                        opts: { showConnector: boolean; fullWidth?: boolean }
                      ) => {
                        const Icon = stage.icon;
                        const stepState = Object.keys(llmGates).length > 0
                          ? getStepStateFromGates(stage.id, llmGates)
                          : getStepState(index, currentIdx, pipelineStatus, isFailure, progress);
                        const isSelected = activeSection === stage.id;

                        const colors = {
                          pending: {
                            ring: 'border-border',
                            bg: 'bg-background',
                            text: 'text-muted-foreground',
                            line: 'bg-border',
                          },
                          running: {
                            ring: 'border-amber-500',
                            bg: 'bg-amber-50',
                            text: 'text-amber-700',
                            line: 'bg-amber-300',
                          },
                          success: {
                            ring: 'border-emerald-500',
                            bg: 'bg-emerald-50',
                            text: 'text-emerald-700',
                            line: 'bg-emerald-300',
                          },
                          failed: {
                            ring: 'border-red-500',
                            bg: 'bg-red-50',
                            text: 'text-red-700',
                            line: 'bg-red-300',
                          },
                        } as const;

                        const c = colors[stepState];

                        const badge = stepState === 'success'
                          ? { label: 'OK', className: 'border-emerald-200 bg-emerald-50 text-emerald-700' }
                          : stepState === 'failed'
                            ? { label: 'BLOCK', className: 'border-red-200 bg-red-50 text-red-700' }
                            : stepState === 'running'
                              ? { label: 'REVIEW', className: 'border-amber-200 bg-amber-50 text-amber-700' }
                              : null;

                        return (
                          <div key={stage.id} className="flex items-center">
                            <button
                              onClick={() => setActiveSection(stage.id)}
                              className={[
                                'group flex items-center gap-2 px-3 py-2.5 rounded-xl border transition-all',
                                opts.fullWidth
                                  ? 'w-full'
                                  : [
                                    // Small/medium desktop widths may still overflow → allow horizontal scroll.
                                    // Only very large screens should fit all steps in one row → flex and shrink.
                                    'w-[230px] h-[65px] flex-shrink-0',
                                    'lg:px-2.5 lg:py-2',
                                  ].join(' '),
                                isSelected ? 'bg-primary/10 border-primary' : 'bg-background hover:bg-muted/40',
                                c.ring,
                                isSelected ? 'ring-2 ring-primary shadow-md' : 'hover:shadow-sm',
                              ].join(' ')}
                            >
                              <div className="relative flex-shrink-0">
                                <div className={['w-10 h-10 rounded-lg border flex items-center justify-center transition-colors', c.bg].join(' ')}>
                                  <Icon size={16} className={c.text} />
                                </div>
                                {stepState === 'running' && (
                                  <div className="absolute inset-0 rounded-lg border-2 border-amber-400/35 animate-pulse pointer-events-none" />
                                )}
                              </div>
                              <div className="min-w-0 text-left flex-1">
                                <div className="text-xs font-semibold text-foreground leading-tight whitespace-nowrap">
                                  {stage.label}
                                </div>
                                <div className="text-[10px] text-muted-foreground leading-snug whitespace-nowrap">
                                  {stage.subtitle}
                                </div>
                              </div>
                              {badge && (
                                <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border flex-shrink-0 ${badge.className}`}>
                                  {badge.label}
                                </span>
                              )}
                            </button>

                            {opts.showConnector && index < buildDynamicPipeline(llmGates).length - 1 && (
                              <div className="hidden sm:block mx-2">
                                {(() => {
                                  const dynamicStages = buildDynamicPipeline(llmGates);
                                  const nextStage = dynamicStages[index + 1];
                                  const nextState = nextStage && Object.keys(llmGates).length > 0
                                    ? getStepStateFromGates(nextStage.id, llmGates)
                                    : 'pending';
                                  const lineColor = nextState === 'pending' ? 'bg-gray-300' : c.line;
                                  return <div className={`h-[2px] w-10 rounded-full ${lineColor}`} />;
                                })()}
                              </div>
                            )}
                          </div>
                        );
                      };

                      return (
                        <>
                          {/* Mobile: stack (no overlap, no connector) */}
                          <div className="sm:hidden space-y-2">
                            {buildDynamicPipeline(llmGates).map((stage, index) => renderStep(stage, index, { showConnector: false, fullWidth: true }))}
                          </div>

                          {/* Desktop: horizontal sequence with connectors */}
                          <div className="hidden sm:block overflow-x-auto">
                            <div className="flex items-center gap-x-3 py-1 min-w-max">
                              {buildDynamicPipeline(llmGates).map((stage, index) => renderStep(stage, index, { showConnector: true }))}
                            </div>
                          </div>
                        </>
                      );
                    })()}
                  </div>
                );
              })()}
            </div>
          )}

          {/* Stage content */}
          {activeSection === 'iac' && (
            <div className="space-y-5">
              {/* 1. Severity 카드 (맨 위) */}
              <VulnSeverityCards vulns={vulnerabilities.filter(v => ['tfsec', 'checkov'].includes(v.tool?.toLowerCase()))} />

              {/* 2. LLM 합산 검증 분석 결과 — 아코디언 */}
              <Accordion title={<><span className="text-sm font-bold bg-blue-600 text-white px-3 py-1 rounded">Gemini LLM</span><span className="text-base font-semibold text-foreground">합산 검증 분석 결과</span></>}>
                {(() => {
                  const sm = llmSummaries['iac'];
                  const jAll = llmJudgments['iac'] || [];
                  // 폴백: gate LLM
                  const gate = llmGates['iac'];
                  const llm = gate?.llm_analysis || {};
                  const fallbackSummary = sm?.summary || llm.summary;
                  const fallbackReasons = sm?.reasons?.length > 0 ? sm.reasons : (llm.reasons || []);
                  if (!fallbackSummary && jAll.length === 0) return <div className="text-sm text-muted-foreground pt-3">데이터 없음</div>;
                  return (<div className="space-y-3 pt-3">
                    {fallbackSummary && <div className="bg-muted rounded-lg p-4"><div className="text-sm font-semibold text-foreground mb-2">LLM 분석 요약</div><div className="text-sm text-foreground leading-relaxed">{fallbackSummary}</div></div>}
                    {fallbackReasons.length > 0 && <div className="space-y-2"><div className="text-sm font-semibold text-foreground">판정 근거</div>{fallbackReasons.map((r: string, i: number) => <div key={i} className="text-sm text-muted-foreground flex gap-2"><span className="text-foreground font-bold">•</span> {r}</div>)}</div>}
                    {!fallbackSummary && jAll.length > 0 && <div className="bg-muted rounded-lg p-4"><div className="text-sm text-muted-foreground">합산 점검 {jAll.length}건이 확인되었습니다.</div></div>}
                  </div>);
                })()}
              </Accordion>

              {/* 3. 합산 검증 카드 — 심각도 순 상위 5건 — 아코디언 */}
              {(llmJudgments['iac'] && llmJudgments['iac'].length > 0) ? (
              <Accordion title={<><span className="text-sm font-bold bg-blue-600 text-white px-3 py-1 rounded">합산 검증</span><span className="text-base font-semibold text-foreground">tfsec + Checkov 통합 점검 결과</span></>}>
                {(() => {
                  const sevOrder: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
                  const iacVulns = vulnerabilities.filter((v) => ['tfsec', 'checkov'].includes(v.tool?.toLowerCase()));
                  const sortBySev = (items: any[]) => [...items].sort((a, b) => (sevOrder[a.severity] ?? 9) - (sevOrder[b.severity] ?? 9));
                  const tfsecTop = sortBySev(iacVulns.filter(v => v.tool?.toLowerCase() === 'tfsec')).slice(0, 5);
                  const checkovTop = sortBySev(iacVulns.filter(v => v.tool?.toLowerCase() === 'checkov')).slice(0, 5);
                  // judgments에서 한국어 매칭
                  const iacJ = llmJudgments['iac'] || [];
                  const findKo = (v: any) => {
                    const desc = (v.description || '').toLowerCase().slice(0, 40);
                    // 1차: 파일명 + 라인번호
                    const exact = iacJ.find((j: any) => {
                      const fa = j.finding_a || {};
                      const fileMatch = fa.file_path && v.file && fa.file_path.split('/').pop() === v.file.split('/').pop();
                      return fileMatch && fa.line_number && v.line && fa.line_number === v.line;
                    });
                    if (exact) return exact;
                    // 2차: 원본 title 키워드
                    if (desc.length > 5) {
                      return iacJ.find((j: any) => {
                        const fa = j.finding_a || {};
                        const faTitle = (fa.title || '').toLowerCase();
                        return faTitle.includes(desc) || desc.includes(faTitle.slice(0, 30));
                      }) || null;
                    }
                    return null;
                  };
                  // 중복 제거
                  const dedup = (items: any[]) => { const seen = new Set<string>(); return items.filter(v => { const k = v.description || ''; if (seen.has(k)) return false; seen.add(k); return true; }); };
                  const renderIacItem = (v: any, i: number) => {
                    const sev = (v.severity || 'MEDIUM').toUpperCase();
                    const sevColor = sev === 'CRITICAL' ? 'bg-red-600' : sev === 'HIGH' ? 'bg-orange-600' : sev === 'MEDIUM' ? 'bg-yellow-600' : 'bg-gray-500';
                    const ko = findKo(v);
                    return (
                      <div key={i} className="bg-blue-50 border border-blue-100 rounded p-3">
                        <div className="flex items-center gap-2 mb-1">
                          <span className={`text-xs font-bold text-white px-1.5 py-0.5 rounded ${sevColor}`}>{sev}</span>
                        </div>
                        <div className="text-sm font-medium text-foreground">{ko?.title_ko || v.description}</div>
                        {v.file && <div className="text-xs text-muted-foreground mt-1">📁 {v.file}</div>}
                      </div>
                    );
                  };
                  return (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div>
                        <div className="text-sm font-bold text-foreground mb-2 bg-muted rounded p-2">tfsec ({dedup(tfsecTop).length}건)</div>
                        <div className="space-y-2">{dedup(tfsecTop).map(renderIacItem)}</div>
                      </div>
                      <div>
                        <div className="text-sm font-bold text-foreground mb-2 bg-muted rounded p-2">Checkov ({dedup(checkovTop).length}건)</div>
                        <div className="space-y-2">{dedup(checkovTop).map(renderIacItem)}</div>
                      </div>
                    </div>
                  );
                })()}
              </Accordion>
              ) : (
              <div className="bg-card rounded-lg border border-border p-6 text-center text-muted-foreground text-sm">
                IaC LLM 판정 데이터가 없습니다. 다음 CI 실행 후 표시됩니다.
              </div>
              )}

              {/* 4. 취약점 목록 — 전체, 심각도 순, CWE 없음 */}
              <VulnerabilityTable
                vulnerabilities={(() => {
                  const sevOrder: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
                  return vulnerabilities
                    .filter((v) => ['tfsec', 'checkov'].includes(v.tool?.toLowerCase()))
                    .sort((a, b) => (sevOrder[a.severity] ?? 9) - (sevOrder[b.severity] ?? 9));
                })()}
                judgments={llmJudgments['iac']}
                category="IaC"
              />
            </div>
          )}

          {activeSection === 'sast' && (
            <div className="space-y-4">
              <VulnSeverityCards vulns={vulnerabilities.filter(v => ['semgrep', 'sonarqube', 'bandit'].includes(v.tool?.toLowerCase()))} />
              <Accordion title={<><span className="text-sm font-bold bg-blue-600 text-white px-3 py-1 rounded">Gemini LLM</span><span className="text-base font-semibold text-foreground">CI 교차검증 분석 결과</span></>}>
                {(() => { const jAll = llmJudgments['sast'] || []; const jTP = jAll.filter((j:any) => j.judgement_code === 'TRUE_POSITIVE' && j.finding_b); const jRV = jAll.filter((j:any) => !(j.judgement_code === 'TRUE_POSITIVE' && j.finding_b)); const sm = llmSummaries['sast']; return (<div className="space-y-3 pt-3">
                  <div className="grid grid-cols-2 gap-3"><div className="bg-muted rounded-md p-3 text-center"><div className="text-xl font-bold text-green-600">{jTP.length}</div><div className="text-sm text-muted-foreground">동시 탐지</div></div><div className="bg-muted rounded-md p-3 text-center"><div className="text-xl font-bold text-amber-600">{jRV.length}</div><div className="text-sm text-muted-foreground">단독 탐지</div></div></div>
                  {sm?.summary && <div className="bg-muted rounded-lg p-4"><div className="text-sm font-semibold text-foreground mb-2">LLM 분석 요약</div><div className="text-sm text-foreground leading-relaxed">{sm.summary}</div></div>}
                  {sm?.reasons?.length > 0 && <div className="space-y-2"><div className="text-sm font-semibold text-foreground">판정 근거</div>{sm.reasons.map((r:string,i:number) => <div key={i} className="text-sm text-muted-foreground flex gap-2"><span className="text-foreground font-bold">•</span> {r}</div>)}</div>}
                  {!sm?.summary && jAll.length > 0 && <div className="bg-muted rounded-lg p-4"><div className="text-sm text-muted-foreground">동시 탐지 {jTP.length}건, 단독 탐지 {jRV.length}건이 확인되었습니다.</div></div>}
                </div>); })()}
              </Accordion>
              <Accordion title={<><span className="text-sm font-bold bg-red-600 text-white px-3 py-1 rounded">동시 탐지</span><span className="text-base font-semibold text-foreground">두 도구가 동시에 발견한 취약점</span></>}>
                {(() => { const jAll = llmJudgments['sast'] || []; const _so: Record<string,number> = {CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3}; const confirmed = jAll.filter((j:any) => j.judgement_code === 'TRUE_POSITIVE' && j.finding_b).sort((a:any,b:any) => (_so[(a.reassessed_severity||a.severity||'LOW').toUpperCase()]??9) - (_so[(b.reassessed_severity||b.severity||'LOW').toUpperCase()]??9)); return confirmed.length > 0 ? <div className="space-y-4 pt-3">{confirmed.map((j:any,i:number) => { const sev = (j.reassessed_severity||j.severity||'HIGH').toUpperCase(); const sc = sev==='CRITICAL'?'bg-red-600':sev==='HIGH'?'bg-orange-600':'bg-yellow-600'; const fa=j.finding_a||{}; const fb=j.finding_b||{}; return <div key={i} className="bg-red-50 border border-red-200 rounded-lg p-4"><div className="flex items-center gap-2 mb-1"><span className={`text-sm font-bold text-white px-2 py-0.5 rounded ${sc}`}>{sev}</span>{fa.cwe_id && <span className="text-sm font-bold text-blue-700">{fa.cwe_id}</span>}</div><div className="text-base font-semibold text-foreground mb-1">{j.title_ko}</div>{fa.file_path && <div className="text-sm text-muted-foreground mb-3">📁 {fa.file_path}{fa.line_number?`:${fa.line_number}`:''}</div>}<div className="grid grid-cols-2 gap-3 mb-3"><div className="bg-white rounded-lg border border-red-100 p-3"><div className="text-sm font-bold text-red-700 mb-1">✓ {fa.tool} 탐지</div><div className="text-xs text-muted-foreground">{fa.cwe_id||''}</div></div><div className="bg-white rounded-lg border border-red-100 p-3"><div className="text-sm font-bold text-red-700 mb-1">✓ {fb.tool} 탐지</div><div className="text-xs text-muted-foreground">{fb.cwe_id||''}</div></div></div><div className="bg-red-100 rounded-lg p-3 space-y-1">{j.risk_summary && <div className="text-sm text-red-800"><strong>위험:</strong> {j.risk_summary}</div>}{j.action_text && <div className="text-sm text-blue-800"><strong>수정 방법:</strong> {j.action_text}</div>}</div></div>; })}</div> : <div className="text-sm text-muted-foreground pt-3">동시 탐지 항목 없음</div>; })()}
              </Accordion>
              <Accordion title={<><span className="text-sm font-bold bg-amber-600 text-white px-3 py-1 rounded">단독 탐지</span><span className="text-base font-semibold text-foreground">한 도구에서만 발견 — 오탐 가능성</span></>} defaultOpen={false}>
                {(() => { const jAll = llmJudgments['sast'] || []; const review = jAll.filter((j:any) => !(j.judgement_code === 'TRUE_POSITIVE' && j.finding_b)); const tools = llmGates['sast']?.tool_summaries || []; const tA = tools[0]?.tool || 'semgrep'; const tB = tools[1]?.tool || 'sonarqube';
                  const dedup = (items: any[]) => { const seen = new Set<string>(); return items.filter(j => { const k = j.title_ko || j.finding_a?.title || ''; if (seen.has(k)) return false; seen.add(k); return true; }); };
                  const rA = dedup(review.filter((j:any) => (j.finding_a?.tool||'').toLowerCase() === tA.toLowerCase()));
                  const rB = dedup(review.filter((j:any) => (j.finding_a?.tool||'').toLowerCase() === tB.toLowerCase()));
                  const renderItem = (j:any, i:number) => { const sev = (j.reassessed_severity||j.severity||'MEDIUM').toUpperCase(); const sc = sev==='CRITICAL'?'bg-red-600':sev==='HIGH'?'bg-orange-600':sev==='MEDIUM'?'bg-yellow-600':'bg-gray-500'; return <div key={i} className="bg-amber-50 border border-amber-100 rounded p-3"><div className="flex items-center gap-2 mb-1"><span className={`text-xs font-bold text-white px-1.5 py-0.5 rounded ${sc}`}>{sev}</span></div><div className="text-sm font-medium">{j.title_ko||j.finding_a?.title}</div>{j.finding_a?.file_path && <div className="text-xs text-muted-foreground mt-1">📁 {j.finding_a.file_path}</div>}</div>; };
                  return <div className="grid grid-cols-2 gap-4 pt-3"><div><div className="text-sm font-bold mb-2 bg-muted rounded p-2">{tA} ({rA.length}건)</div><div className="space-y-2">{rA.length>0?rA.map(renderItem):<div className="text-sm text-muted-foreground p-3">단독 탐지 없음</div>}</div></div><div><div className="text-sm font-bold mb-2 bg-muted rounded p-2">{tB} ({rB.length}건)</div><div className="space-y-2">{rB.length>0?rB.map(renderItem):<div className="text-sm text-muted-foreground p-3">단독 탐지 없음</div>}</div></div></div>; })()}
              </Accordion>
              <GateToolSummary gate={llmGates['sast']} judgments={llmJudgments['sast']} />
              <VulnerabilityTable vulnerabilities={vulnerabilities.filter((v) => ['semgrep', 'sonarqube', 'bandit'].includes(v.tool?.toLowerCase()))} judgments={llmJudgments['sast']} category="SAST" />
            </div>
          )}

          {activeSection === 'sca' && (
            <div className="space-y-4">
              <VulnSeverityCards vulns={vulnerabilities.filter(v => ['trivy', 'depcheck', 'dep-check'].includes(v.tool?.toLowerCase()) && v.category !== 'IMAGE')} />
              <Accordion title={<><span className="text-sm font-bold bg-blue-600 text-white px-3 py-1 rounded">Gemini LLM</span><span className="text-base font-semibold text-foreground">CI 교차검증 분석 결과</span></>}>
                {(() => { const jAll = llmJudgments['sca'] || []; const jTP = jAll.filter((j:any) => j.judgement_code === 'TRUE_POSITIVE' && j.finding_b); const jRV = jAll.filter((j:any) => !(j.judgement_code === 'TRUE_POSITIVE' && j.finding_b)); const sm = llmSummaries['sca']; return (<div className="space-y-3 pt-3">
                  <div className="grid grid-cols-2 gap-3"><div className="bg-muted rounded-md p-3 text-center"><div className="text-xl font-bold text-green-600">{jTP.length}</div><div className="text-sm text-muted-foreground">동시 탐지</div></div><div className="bg-muted rounded-md p-3 text-center"><div className="text-xl font-bold text-amber-600">{jRV.length}</div><div className="text-sm text-muted-foreground">단독 탐지</div></div></div>
                  {sm?.summary && <div className="bg-muted rounded-lg p-4"><div className="text-sm font-semibold text-foreground mb-2">LLM 분석 요약</div><div className="text-sm text-foreground leading-relaxed">{sm.summary}</div></div>}
                  {sm?.reasons?.length > 0 && <div className="space-y-2"><div className="text-sm font-semibold text-foreground">판정 근거</div>{sm.reasons.map((r:string,i:number) => <div key={i} className="text-sm text-muted-foreground flex gap-2"><span className="text-foreground font-bold">•</span> {r}</div>)}</div>}
                  {!sm?.summary && jAll.length > 0 && <div className="bg-muted rounded-lg p-4"><div className="text-sm text-muted-foreground">동시 탐지 {jTP.length}건, 단독 탐지 {jRV.length}건이 확인되었습니다.</div></div>}
                </div>); })()}
              </Accordion>
              <Accordion title={<><span className="text-sm font-bold bg-red-600 text-white px-3 py-1 rounded">동시 탐지</span><span className="text-base font-semibold text-foreground">두 도구가 동시에 발견한 취약점</span></>}>
                {(() => { const jAll = llmJudgments['sca'] || []; const _so: Record<string,number> = {CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3}; const confirmed = jAll.filter((j:any) => j.judgement_code === 'TRUE_POSITIVE' && j.finding_b).sort((a:any,b:any) => (_so[(a.reassessed_severity||a.severity||'LOW').toUpperCase()]??9) - (_so[(b.reassessed_severity||b.severity||'LOW').toUpperCase()]??9)); return confirmed.length > 0 ? <div className="space-y-4 pt-3">{confirmed.map((j:any,i:number) => { const sev = (j.reassessed_severity||j.severity||'HIGH').toUpperCase(); const sc = sev==='CRITICAL'?'bg-red-600':sev==='HIGH'?'bg-orange-600':'bg-yellow-600'; const fa=j.finding_a||{}; const fb=j.finding_b||{}; return <div key={i} className="bg-red-50 border border-red-200 rounded-lg p-4"><div className="flex items-center gap-2 mb-1"><span className={`text-sm font-bold text-white px-2 py-0.5 rounded ${sc}`}>{sev}</span>{(fa.cve_id||fa.cwe_id) && <span className="text-sm font-bold text-blue-700">{fa.cve_id||fa.cwe_id}</span>}</div><div className="text-base font-semibold text-foreground mb-1">{j.title_ko}</div>{fa.file_path && <div className="text-sm text-muted-foreground mb-3">📁 {fa.file_path}</div>}<div className="grid grid-cols-2 gap-3 mb-3"><div className="bg-white rounded-lg border border-red-100 p-3"><div className="text-sm font-bold text-red-700 mb-1">✓ {fa.tool} 탐지</div></div><div className="bg-white rounded-lg border border-red-100 p-3"><div className="text-sm font-bold text-red-700 mb-1">✓ {fb.tool} 탐지</div></div></div><div className="bg-red-100 rounded-lg p-3 space-y-1">{j.risk_summary && <div className="text-sm text-red-800"><strong>위험:</strong> {j.risk_summary}</div>}{j.action_text && <div className="text-sm text-blue-800"><strong>수정 방법:</strong> {j.action_text}</div>}</div></div>; })}</div> : <div className="text-sm text-muted-foreground pt-3">동시 탐지 항목 없음</div>; })()}
              </Accordion>
              <Accordion title={<><span className="text-sm font-bold bg-amber-600 text-white px-3 py-1 rounded">단독 탐지</span><span className="text-base font-semibold text-foreground">한 도구에서만 발견 — 오탐 가능성</span></>} defaultOpen={false}>
                {(() => { const jAll = llmJudgments['sca'] || []; const review = jAll.filter((j:any) => !(j.judgement_code === 'TRUE_POSITIVE' && j.finding_b)); const tools = llmGates['sca']?.tool_summaries || []; const tA = tools[0]?.tool || 'trivy'; const tB = tools[1]?.tool || 'depcheck';
                  const dedup = (items: any[]) => { const seen = new Set<string>(); return items.filter(j => { const k = j.title_ko || j.finding_a?.title || ''; if (seen.has(k)) return false; seen.add(k); return true; }); };
                  const rA = dedup(review.filter((j:any) => (j.finding_a?.tool||'').toLowerCase() === tA.toLowerCase()));
                  const rB = dedup(review.filter((j:any) => (j.finding_a?.tool||'').toLowerCase() === tB.toLowerCase()));
                  const renderItem = (j:any, i:number) => { const sev = (j.reassessed_severity||j.severity||'MEDIUM').toUpperCase(); const sc = sev==='CRITICAL'?'bg-red-600':sev==='HIGH'?'bg-orange-600':sev==='MEDIUM'?'bg-yellow-600':'bg-gray-500'; return <div key={i} className="bg-amber-50 border border-amber-100 rounded p-3"><div className="flex items-center gap-2 mb-1"><span className={`text-xs font-bold text-white px-1.5 py-0.5 rounded ${sc}`}>{sev}</span></div><div className="text-sm font-medium">{j.title_ko||j.finding_a?.title}</div>{j.finding_a?.file_path && <div className="text-xs text-muted-foreground mt-1">📁 {j.finding_a.file_path}</div>}</div>; };
                  return <div className="grid grid-cols-2 gap-4 pt-3"><div><div className="text-sm font-bold mb-2 bg-muted rounded p-2">{tA} ({rA.length}건)</div><div className="space-y-2">{rA.length>0?rA.map(renderItem):<div className="text-sm text-muted-foreground p-3">단독 탐지 없음</div>}</div></div><div><div className="text-sm font-bold mb-2 bg-muted rounded p-2">{tB} ({rB.length}건)</div><div className="space-y-2">{rB.length>0?rB.map(renderItem):<div className="text-sm text-muted-foreground p-3">단독 탐지 없음</div>}</div></div></div>; })()}
              </Accordion>
              <GateToolSummary gate={llmGates['sca']} judgments={llmJudgments['sca']} />
              <VulnerabilityTable vulnerabilities={(() => { const _s: Record<string,number> = {CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3}; return vulnerabilities.filter((v) => ['trivy', 'depcheck', 'dep-check'].includes(v.tool?.toLowerCase()) && v.category !== 'IMAGE').sort((a,b) => (_s[a.severity]??9) - (_s[b.severity]??9)); })()} judgments={llmJudgments['sca']} category="SCA" />
            </div>
          )}

          {activeSection === 'cross' && (
            <div className="space-y-5">

              {/* 파이프라인 실행 상태 + 보안 검사 단계 */}
              {(() => {
                const getDecisionX = (g: any) => {
                  const dx = (g?.decision || g?.gate_result || g?.llm_analysis?.recommended_decision || '').toLowerCase();
                  return (dx === 'fail' || dx === 'block') ? 'block' : dx;
                };
                const hasBlock = ['iac', 'sast', 'sca', 'image', 'dast'].some(s => getDecisionX(llmGates[s]) === 'block');
                const blockedAt = ['iac', 'sast', 'sca', 'image', 'dast'].find(s => getDecisionX(llmGates[s]) === 'block');
                const labelMapX: Record<string, string> = { iac: 'IaC', sast: 'SAST', sca: 'SCA', image: '이미지 스캔', dast: 'DAST' };
                // llmGates에서 commit_hash 추출
                const firstGate = llmGates['sast'] || llmGates['sca'] || llmGates['iac'] || llmGates['image'] || {};
                const commit = (firstGate.commit_hash || '').slice(0, 8) || '—';
                const gate = hasBlock ? 'BLOCK' : 'REVIEW';
                const timeStr2 = firstGate.commit_hash ? new Date().toLocaleString('ko-KR') : '—';

                // 보안 검사 단계 동적 생성
                const scanSteps = [
                  { label: 'IaC 스캔 (tfsec + Checkov)', key: 'iac' },
                  { label: 'SAST (SonarQube + Semgrep)', key: 'sast' },
                  { label: 'SCA (Trivy + Dep-Check)', key: 'sca' },
                ];
                // Phase 1 gate
                const phase1Block = ['iac', 'sast', 'sca'].some(s => getDecisionX(llmGates[s]) === 'block');

                type StepInfo = { label: string; status: string; state: 'ok' | 'fail' | 'skip' };
                const steps: StepInfo[] = [];

                // Phase 1
                steps.push({ label: 'Phase 1 — SAST + SCA + IaC', status: '완료', state: 'ok' });
                steps.push({ label: '교차검증 + LLM 판정', status: '완료', state: 'ok' });

                if (phase1Block) {
                  steps.push({ label: '게이트 판정 (Phase 1)', status: 'BLOCK', state: 'fail' });
                  steps.push({ label: 'Docker 이미지 빌드', status: '차단됨', state: 'skip' });
                  steps.push({ label: '이미지 스캔 (Trivy + Grype)', status: '미실행', state: 'skip' });
                  steps.push({ label: 'Phase 2 — DAST (ZAP + Nuclei)', status: '미실행', state: 'skip' });
                  steps.push({ label: '배포 (ECS Fargate)', status: '차단됨', state: 'skip' });
                } else {
                  steps.push({ label: '게이트 판정 (Phase 1)', status: 'PASS', state: 'ok' });
                  steps.push({ label: 'Docker 이미지 빌드', status: '완료', state: 'ok' });
                  const imageBlock = getDecisionX(llmGates['image']) === 'block';
                  steps.push({ label: '이미지 스캔 (Trivy + Grype)', status: imageBlock ? 'BLOCK' : '완료', state: imageBlock ? 'fail' : 'ok' });
                  if (imageBlock) {
                    steps.push({ label: 'Phase 2 — DAST (ZAP + Nuclei)', status: '미실행', state: 'skip' });
                    steps.push({ label: '배포 (ECS Fargate)', status: '차단됨', state: 'skip' });
                  } else {
                    const dastBlock = getDecisionX(llmGates['dast']) === 'block';
                    steps.push({ label: 'Phase 2 — DAST (ZAP + Nuclei)', status: dastBlock ? 'BLOCK' : '완료', state: dastBlock ? 'fail' : 'ok' });
                    steps.push({ label: '배포 (ECS Fargate)', status: dastBlock ? '차단됨' : '완료', state: dastBlock ? 'skip' : 'ok' });
                  }
                }

                return (
                  <>
                    {/* 배포 판정 배너 */}
                    <div className={`rounded-lg border-2 p-5 ${hasBlock ? 'bg-red-50 border-red-300' : 'bg-green-50 border-green-300'}`}>
                      <div className="flex items-center gap-3 mb-2">
                        <span className={`text-lg font-bold ${hasBlock ? 'text-red-700' : 'text-green-700'}`}>
                          {hasBlock ? <><span className="inline-block w-3 h-3 rounded-full bg-red-500 mr-1" />배포 차단</> : '배포 허용'}
                        </span>
                      </div>
                      <div className={`text-sm ${hasBlock ? 'text-red-600' : 'text-green-600'}`}>
                        {hasBlock
                          ? `${labelMapX[blockedAt!]} 단계에서 CRITICAL 취약점이 발견되어 배포가 차단되었습니다.`
                          : '모든 보안 검사를 통과하여 배포가 허용되었습니다.'}
                      </div>
                    </div>

                    {/* 파이프라인 실행 상태 */}
                    <div className="bg-card rounded-lg border border-border shadow-sm p-5">
                      <h3 className="text-sm font-bold text-foreground mb-4">파이프라인 실행 상태</h3>
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                        <div className="bg-muted rounded-lg p-4">
                          <div className="text-xs text-muted-foreground mb-1">최근 커밋</div>
                          <div className="text-sm font-mono font-bold text-foreground">{commit}</div>
                        </div>
                        <div className="bg-muted rounded-lg p-4">
                          <div className="text-xs text-muted-foreground mb-1">게이트 판정</div>
                          <div className={`text-sm font-bold ${hasBlock ? 'text-red-600' : 'text-green-600'}`}>{gate}</div>
                        </div>
                        <div className="bg-muted rounded-lg p-4">
                          <div className="text-xs text-muted-foreground mb-1">Phase</div>
                          <div className="text-sm font-bold text-foreground">{phase1Block ? 'Phase 1 차단' : blockedAt ? 'Phase 2 차단' : '전체 통과'}</div>
                        </div>
                        <div className="bg-muted rounded-lg p-4">
                          <div className="text-xs text-muted-foreground mb-1">실행 시각</div>
                          <div className="text-xs font-mono text-foreground">{timeStr2}</div>
                        </div>
                      </div>
                    </div>

                    {/* 보안 검사 단계 */}
                    <div className="bg-card rounded-lg border border-border shadow-sm p-5">
                      <h3 className="text-sm font-bold text-foreground mb-4">보안 검사 단계</h3>
                      <div className="space-y-3">
                        {steps.map((step, i) => (
                          <div key={i} className="flex items-center gap-3">
                            <span className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold text-white ${
                              step.state === 'ok' ? 'bg-green-500' : step.state === 'fail' ? 'bg-red-500' : 'bg-gray-300'
                            }`}>
                              {step.state === 'ok' ? '✓' : step.state === 'fail' ? '✕' : '—'}
                            </span>
                            <span className={`text-sm flex-1 ${step.state === 'skip' ? 'text-muted-foreground' : 'text-foreground'}`}>{step.label}</span>
                            <span className={`text-xs font-semibold ${
                              step.state === 'ok' ? 'text-green-600' : step.state === 'fail' ? 'text-red-600' : 'text-muted-foreground'
                            }`}>{step.status}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  </>
                );
              })()}

              {/* 카테고리별 교차검증 요약 — BLOCK 시점까지 동적 */}
              {(() => {
                const getDecision3 = (g: any) => {
                  const d3 = (g?.decision || g?.gate_result || g?.llm_analysis?.recommended_decision || '').toLowerCase();
                  return (d3 === 'fail' || d3 === 'block') ? 'block' : d3;
                };
                const allCards = [
                  { key: 'sast', label: 'SAST', sub: 'SonarQube + Semgrep', mode: 'cross' as const },
                  { key: 'sca', label: 'SCA', sub: 'Trivy + Dep-Check', mode: 'cross' as const },
                  { key: 'iac', label: 'IaC', sub: 'tfsec + Checkov', mode: 'combined' as const },
                  { key: 'image', label: '이미지 스캔', sub: 'Trivy + Grype', mode: 'cross' as const },
                  { key: 'dast', label: 'DAST', sub: 'ZAP + Nuclei', mode: 'cross' as const },
                ];
                // BLOCK 시점까지만 포함
                const visibleCards: typeof allCards = [];
                for (const c of allCards) {
                  visibleCards.push(c);
                  if (getDecision3(llmGates[c.key]) === 'block') break;
                }
                const cols = visibleCards.length <= 3 ? 'md:grid-cols-3' : visibleCards.length === 4 ? 'md:grid-cols-4' : 'md:grid-cols-5';
                return (
              <div className={`grid grid-cols-1 ${cols} gap-4`}>
                {visibleCards.map(({ key, label, sub, mode }) => {
                  const j = llmJudgments[key] || [];
                  const confirmed = j.filter((x: any) => x.judgement_code === 'TRUE_POSITIVE' && x.finding_b).length;
                  const review = j.length - confirmed;
                  const gate = llmGates[key];
                  const decision = gate?.decision || 'unknown';
                  const decisionColor = decision === 'pass' ? 'text-green-600' : decision === 'fail' ? 'text-red-600' : 'text-amber-600';
                  const decisionLabel = decision === 'pass' ? '통과' : decision === 'fail' ? '차단' : '검토 필요';

                  return (
                    <div key={key} className="bg-card rounded-lg border border-border shadow-sm p-4 cursor-pointer hover:border-primary/50 transition-colors"
                      onClick={() => setActiveSection(key)}>
                      <div className="flex items-center justify-between mb-2">
                        <div>
                          <div className="text-sm font-bold text-foreground">{label}</div>
                          <div className="text-xs text-muted-foreground">{sub}</div>
                        </div>
                        <span className={`text-xs font-bold ${decisionColor}`}>{decisionLabel}</span>
                      </div>
                      {mode === 'cross' ? (
                        <div className="flex gap-3 mt-3">
                          <div className="text-center flex-1 bg-red-50 rounded p-2">
                            <div className="text-lg font-bold text-red-600">{confirmed}</div>
                            <div className="text-[10px] text-muted-foreground">동시 탐지</div>
                          </div>
                          <div className="text-center flex-1 bg-amber-50 rounded p-2">
                            <div className="text-lg font-bold text-amber-600">{review}</div>
                            <div className="text-[10px] text-muted-foreground">단독 탐지</div>
                          </div>
                        </div>
                      ) : (
                        <div className="text-center bg-blue-50 rounded p-2 mt-3">
                          <div className="text-lg font-bold text-blue-600">{j.length}</div>
                          <div className="text-[10px] text-muted-foreground">합산 점검</div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
                );
              })()}

              {/* BLOCK 사유 배너 제거됨 — 배포 판정 배너에서 표시 */}

              {/* LLM 단계별 분석 + 종합 분석 */}
              {(() => {
                const getDecision = (g: any) => {
                  const d2 = (g?.decision || g?.gate_result || g?.llm_analysis?.recommended_decision || '').toLowerCase();
                  return (d2 === 'fail' || d2 === 'block') ? 'block' : d2;
                };
                // BLOCK 이전까지의 stage만 포함
                const scanOrder2 = ['iac', 'sast', 'sca', 'image', 'dast'];
                const activeStages: string[] = [];
                for (const s of scanOrder2) {
                  activeStages.push(s);
                  if (getDecision(llmGates[s]) === 'block') break;
                }
                const labelMap: Record<string, string> = { sast: 'SAST', sca: 'SCA', iac: 'IaC', image: '이미지 스캔', dast: 'DAST' };
                const hasSummary = activeStages.some(s => llmGates[s]?.llm_analysis?.summary);
                if (!hasSummary) return null;
                const blockedStage = activeStages.find(s => getDecision(llmGates[s]) === 'block');
                return (
                  <div className="bg-card rounded-lg border border-border shadow-sm p-5">
                    <h3 className="text-sm font-bold text-foreground mb-3">Gemini LLM 종합 분석</h3>
                    <div className="space-y-3">
                      {/* 단계별 분석 */}
                      {activeStages.map(s => {
                        const gate = llmGates[s];
                        if (!gate?.llm_analysis?.summary) return null;
                        const isBlock = getDecision(gate) === 'block';
                        return (
                          <div key={s} className={`rounded-lg p-3 ${isBlock ? 'bg-red-50 border border-red-200' : 'bg-muted'}`}>
                            <div className="flex items-center gap-2 mb-1">
                              <div className="text-xs font-bold text-foreground">{labelMap[s]}</div>
                              {isBlock && <span className="text-[10px] font-bold text-red-600 bg-red-100 px-1.5 py-0.5 rounded">BLOCK</span>}
                            </div>
                            <div className="text-sm text-muted-foreground">{gate.llm_analysis.summary}</div>
                          </div>
                        );
                      })}
                      {/* 종합 분석 */}
                      {(() => {
                        const overall = llmSummaries?.['_overall'] || llmGates?.['overall-verdict']?.summaries?.['_overall'] || {};
                        const verdict = overall.verdict || '';
                        const actions = overall.priority_actions || [];
                        const hasLlmVerdict = !!verdict;
                        // 폴백 텍스트
                        const fallback = blockedStage
                          ? `${labelMap[blockedStage]} 단계에서 CRITICAL 수준의 취약점이 확인되어 파이프라인이 차단(BLOCK)되었습니다. 다음 CI/CD 실행 시 LLM 종합 분석이 생성됩니다.`
                          : '모든 단계를 통과했습니다. 일부 REVIEW 항목이 있으나 배포를 차단할 수준은 아닙니다.';
                        return (
                        <div className="bg-indigo-50 border-2 border-indigo-300 rounded-lg p-4 mt-2">
                          <div className="text-xs font-bold text-indigo-700 mb-2">종합 판정</div>
                          <div className="text-sm text-indigo-800 leading-relaxed">{hasLlmVerdict ? verdict : fallback}</div>
                          {actions.length > 0 && (
                            <div className="mt-3 space-y-1">
                              <div className="text-xs font-bold text-indigo-700">우선 조치 항목</div>
                              {actions.map((a: string, i: number) => (
                                <div key={i} className="text-sm text-indigo-700 flex gap-2"><span className="font-bold">{i + 1}.</span> {a}</div>
                              ))}
                            </div>
                          )}
                        </div>
                        );
                      })()}
                    </div>
                  </div>
                );
              })()}

              {/* 스코어 트렌드 — cross/history 기반 */}
              {/* PipelineTimeline 제거 */}
            </div>
          )}



          {activeSection === 'image' && (
            <div className="space-y-5">
              <ImageScanSection judgments={llmJudgments['image']} summaries={llmSummaries} gates={llmGates} />
            </div>
          )}

          {activeSection === 'deploy' && (
            <div className="space-y-5">
              <DeploySection />
            </div>
          )}

          {activeSection === 'dast' && (
            <div className="space-y-4">
              <DastFullSection gates={llmGates} judgments={llmJudgments} summaries={llmSummaries} />
            </div>
          )}

          {activeSection === 'siem' && (
            <div className="space-y-5">
              <SecurityMonitoring
                summary={apiSiemData ? {
                  securityScore: apiSiemData.total_events ?? 0,
                  activeAlarms: apiSiemData.critical_events ?? 0,
                  guardDutyFindings: apiSiemData.high_events ?? 0,
                  cloudTrailStatus: apiSiemData.sources?.length > 0 ? 'Active' : 'N/A',
                  recentEventTime: apiSiemData.recent_critical_events?.[0]?.time || new Date().toISOString(),
                  monitoringStatus: (apiSiemData.critical_events ?? 0) > 0 ? 'warning' : 'normal',
                } : mockSecurityMonitoringSummary}
                serviceStatuses={mockServiceStatuses}
                eventItems={apiSiemData?.events || mockEventItems}
                trendData={mockTrendChartData}
              />
            </div>
          )}

          {activeSection === 'aws' && (
            <div className="space-y-5">
              <AwsResources />
            </div>
          )}

          {activeSection === 'isms' && (() => {
            const items = apiIsmsData?.items || apiIsmsData?.automated_results || [];
            const s = apiIsmsData?.summary || {};
            const counts = {
              ok: s.compliant || 0,
              ng: s.non_compliant || 0,
              manual: s.manual_required || 0,
              insufficient: s.insufficient_data || 0,
            };
            const rate = s.compliance_rate_pct || 0;
            const total = s.total || items.length;

            const statusMap: Record<string, string> = {
              'COMPLIANT': 'ok', 'NON_COMPLIANT': 'ng',
              'MANUAL_REQUIRED': 'manual', 'INSUFFICIENT_DATA': 'insufficient',
              'NOT_APPLICABLE': 'manual',
            };

            const toggleSection = (key: string) => setIsmsOpenSections((prev: Record<string, boolean>) => ({ ...prev, [key]: !prev[key] }));

            const filtered = ismsFilter === 'all' ? items : items.filter((r: any) => statusMap[r.status] === ismsFilter);

            // 3대 도메인 그룹핑
            const domainGroups: { key: string; label: string; items: any[] }[] = [
              { key: '1', label: '1. 관리체계 수립 및 운영', items: [] },
              { key: '2', label: '2. 보호대책 요구사항', items: [] },
              { key: '3', label: '3. 개인정보 처리 단계별 요구사항', items: [] },
            ];
            filtered.forEach((r: any) => {
              const section = (r.isms_p_id || '').charAt(0);
              const group = domainGroups.find(g => g.key === section);
              if (group) group.items.push(r);
            });

            const statusDot = (status: string) => {
              const colors: Record<string, string> = {
                'COMPLIANT': 'bg-emerald-500', 'NON_COMPLIANT': 'bg-red-500',
                'MANUAL_REQUIRED': 'bg-amber-400', 'INSUFFICIENT_DATA': 'bg-blue-400',
                'NOT_APPLICABLE': 'bg-gray-300',
              };
              return <div className={`w-2.5 h-2.5 rounded-full flex-shrink-0 mt-0.5 ${colors[status] || 'bg-gray-300'}`} />;
            };

            const statusLabel = (status: string) => {
              const map: Record<string, { label: string; cls: string }> = {
                'COMPLIANT': { label: '적합', cls: 'text-emerald-700 bg-emerald-50 border-emerald-200' },
                'NON_COMPLIANT': { label: '부적합', cls: 'text-red-700 bg-red-50 border-red-200' },
                'MANUAL_REQUIRED': { label: '수동 확인', cls: 'text-amber-700 bg-amber-50 border-amber-200' },
                'INSUFFICIENT_DATA': { label: '데이터 부족', cls: 'text-blue-700 bg-blue-50 border-blue-200' },
                'NOT_APPLICABLE': { label: '해당없음', cls: 'text-gray-500 bg-gray-50 border-gray-200' },
              };
              const s = map[status] || { label: status, cls: 'text-gray-500 bg-gray-50 border-gray-200' };
              return <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded border ${s.cls}`}>{s.label}</span>;
            };

            const sectionBadges = (sectionItems: any[]) => {
              const ok = sectionItems.filter(r => r.status === 'COMPLIANT').length;
              const ng = sectionItems.filter(r => r.status === 'NON_COMPLIANT').length;
              const manual = sectionItems.filter(r => r.status === 'MANUAL_REQUIRED').length;
              return (
                <div className="flex gap-2">
                  {ok > 0 && <span className="text-[10px] font-semibold text-emerald-700 bg-emerald-50 px-1.5 py-0.5 rounded">적합 {ok}</span>}
                  {ng > 0 && <span className="text-[10px] font-semibold text-red-700 bg-red-50 px-1.5 py-0.5 rounded">부적합 {ng}</span>}
                  {manual > 0 && <span className="text-[10px] font-semibold text-amber-700 bg-amber-50 px-1.5 py-0.5 rounded">수동 {manual}</span>}
                </div>
              );
            };

            return (
            <div className="space-y-4">
              {/* 1. 상단 요약 카드 */}
              <div className="bg-card rounded-lg p-5 shadow-sm border border-border">
                <div className="flex items-center justify-between mb-4">
                  <div>
                    <div className="text-sm font-semibold text-foreground">ISMS-P 컴플라이언스</div>
                    <div className="text-xs text-muted-foreground">KISA ISMS-P 2023 · AWS 인프라 자동 점검 결과</div>
                  </div>
                  <div className="text-right">
                    <div className="text-2xl font-bold font-mono text-emerald-600">{rate.toFixed(1)}%</div>
                    <div className="text-[10px] text-muted-foreground">자동화 준수율</div>
                  </div>
                </div>
                <div className="h-2 bg-slate-100 rounded-full overflow-hidden mb-4">
                  <div className="h-full bg-emerald-500 rounded-full transition-all" style={{ width: `${rate}%` }} />
                </div>
                <div className="grid grid-cols-4 gap-3">
                  <div className="bg-emerald-50 border border-emerald-200 rounded-lg p-3 text-center">
                    <div className="text-xl font-bold text-emerald-700">{counts.ok}</div>
                    <div className="text-[10px] text-emerald-600 font-medium">적합</div>
                  </div>
                  <div className="bg-red-50 border border-red-200 rounded-lg p-3 text-center">
                    <div className="text-xl font-bold text-red-700">{counts.ng}</div>
                    <div className="text-[10px] text-red-600 font-medium">부적합</div>
                  </div>
                  <div className="bg-amber-50 border border-amber-200 rounded-lg p-3 text-center">
                    <div className="text-xl font-bold text-amber-700">{counts.manual}</div>
                    <div className="text-[10px] text-amber-600 font-medium">수동 확인</div>
                  </div>
                  <div className="bg-blue-50 border border-blue-200 rounded-lg p-3 text-center">
                    <div className="text-xl font-bold text-blue-700">{counts.insufficient}</div>
                    <div className="text-[10px] text-blue-600 font-medium">데이터 부족</div>
                  </div>
                </div>
                <div className="text-[10px] text-muted-foreground mt-2 text-right">전체 {total}개 항목 · 점검: {apiIsmsData?.metadata?.checked_at ? new Date(apiIsmsData.metadata.checked_at).toLocaleString('ko-KR') : '-'}</div>
              </div>

              {/* 부적합 경고 */}
              {counts.ng > 0 && (
                <div className="bg-red-50 border border-red-200 rounded-lg p-3 flex items-center gap-2">
                  <div className="text-red-600 text-sm font-semibold">⚠ 부적합 {counts.ng}건 즉시 조치 필요</div>
                </div>
              )}

              {/* 2. 필터 버튼 */}
              <div className="flex gap-2">
                {[
                  { key: 'all', label: '전체', count: items.length },
                  { key: 'ng', label: '부적합', count: counts.ng },
                  { key: 'ok', label: '적합', count: counts.ok },
                  { key: 'manual', label: '수동 확인', count: counts.manual },
                ].map(f => (
                  <button key={f.key} onClick={() => setIsmsFilter(f.key)}
                    className={`text-xs font-medium px-3 py-1.5 rounded-lg border transition-colors ${ismsFilter === f.key ? 'bg-foreground text-background border-foreground' : 'bg-background text-muted-foreground border-border hover:bg-muted'}`}>
                    {f.label} <span className="font-mono ml-1">{f.count}</span>
                  </button>
                ))}
              </div>

              {/* 3. 섹션별 accordion */}
              {domainGroups.filter(g => g.items.length > 0).map(group => (
                <div key={group.key} className="bg-card rounded-lg shadow-sm border border-border overflow-hidden">
                  <button onClick={() => toggleSection(group.key)}
                    className="w-full flex items-center justify-between px-6 py-3.5 hover:bg-muted/30 transition-colors">
                    <div className="flex items-center gap-3">
                      <ChevronDown size={14} className={`text-muted-foreground transition-transform ${ismsOpenSections[group.key] === true ? 'rotate-0' : '-rotate-90'}`} />
                      <span className="text-base font-semibold text-foreground">{group.label}</span>
                      {sectionBadges(group.items)}
                    </div>
                    <span className="text-xs text-muted-foreground">{group.items.length}개 항목</span>
                  </button>

                  {ismsOpenSections[group.key] === true && (
                    <div className="border-t border-border divide-y divide-border/50">
                      {group.items.map((r: any, i: number) => {
                        const details = (r.check_details || []).map((c: any) => c.reason).filter(Boolean).join(' · ');
                        const reason = r.reason || details || '';
                        const isNg = r.status === 'NON_COMPLIANT';
                        return (
                          <div key={i} id={`isms-${r.isms_p_id}`} className={`px-6 py-3 flex items-start gap-4 ${isNg ? 'bg-red-50/50' : ''}`}>
                            {statusDot(r.status)}
                            <div className="w-14 flex-shrink-0 font-mono text-sm font-bold text-muted-foreground">{r.isms_p_id}</div>
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-2">
                                <span className="text-sm font-medium text-foreground">{r.isms_p_name}</span>
                                {statusLabel(r.status)}
                              </div>
                              {reason && (
                                <div className={`text-xs mt-0.5 ${isNg ? 'text-red-600' : 'text-muted-foreground'}`}>{reason}</div>
                              )}
                              {!reason && r.manual_supplement && r.status === 'MANUAL_REQUIRED' && (
                                <div className="text-xs mt-0.5 text-muted-foreground">{r.manual_supplement}</div>
                              )}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              ))}

            </div>
            );
          })()}
        </div>
      </main>
    </div>
  );
}
