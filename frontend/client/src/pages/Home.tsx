// DevSecOps Dashboard - Home Page
// Design: Clean Governance Dashboard | IBM Plex Sans + IBM Plex Mono
// Layout: Fixed top nav + Scrollable main content

import { useState, useCallback, useMemo, useEffect } from 'react';
import { toast } from 'sonner';
import { Cloud, Code2, ShieldCheck, GitBranch, Image, Server, Bug, Monitor, ArrowLeft } from 'lucide-react';
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

const PIPELINE_STAGES = [
  { id: 'iac', label: 'IaC 스캔', subtitle: 'tfsec + Checkov', icon: Cloud },
  { id: 'sast', label: 'SAST', subtitle: 'SonarQube + Semgrep', icon: Code2 },
  { id: 'sca', label: 'SCA', subtitle: 'Trivy + Dep-Check', icon: ShieldCheck },
  { id: 'cross', label: '교차 검증', subtitle: '', icon: GitBranch },
  // { id: 'normalize', label: '정규화 + 스코어링', subtitle: '', icon: SlidersHorizontal },
  { id: 'image', label: '이미지 스캔', subtitle: 'Trivy', icon: Image },
  { id: 'deploy', label: '배포', subtitle: 'ECS Fargate', icon: Server },
  { id: 'dast', label: 'DAST', subtitle: 'OWASP ZAP', icon: Bug },
];

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
    <div className="bg-card rounded-lg border border-border shadow-sm p-4 mb-4">
      <div className="flex items-center gap-2 mb-3">
        <span className="text-xs font-bold bg-blue-600 text-white px-2 py-1 rounded">Gemini LLM</span>
        <span className="text-sm font-semibold text-foreground">{mode === 'combined' ? '합산 검증 분석 결과' : 'CI 교차검증 분석 결과'}</span>
        <span className={`text-xs font-bold px-2 py-1 rounded border ${decisionColor}`}>{decisionLabel}</span>
      </div>

      {/* 매칭 통계 — 교차검증 모드에서만 표시 */}
      {mode === 'cross' && (
        <div className="grid grid-cols-3 gap-3 mb-3">
          <div className="bg-muted rounded-md p-2 text-center">
            <div className="text-lg font-bold text-green-600">{matching.matched_count || 0}</div>
            <div className="text-xs text-muted-foreground">동시 탐지</div>
          </div>
          <div className="bg-muted rounded-md p-2 text-center">
            <div className="text-lg font-bold text-amber-600">{matching.mismatch_count || 0}</div>
            <div className="text-xs text-muted-foreground">단독 탐지</div>
          </div>
          <div className="bg-muted rounded-md p-2 text-center">
            <div className="text-lg font-bold text-foreground">{combined.total || 0}</div>
            <div className="text-xs text-muted-foreground">전체</div>
          </div>
        </div>
      )}

      {/* 합산 검증 모드: 전체 건수만 표시 */}
      {mode === 'combined' && (
        <div className="grid grid-cols-2 gap-3 mb-3">
          <div className="bg-muted rounded-md p-2 text-center">
            <div className="text-lg font-bold text-foreground">{combined.total || 0}</div>
            <div className="text-xs text-muted-foreground">총 탐지 건수</div>
          </div>
          <div className="bg-muted rounded-md p-2 text-center">
            <div className="text-lg font-bold text-foreground">{(gate?.tool_summaries || []).length}</div>
            <div className="text-xs text-muted-foreground">도구 수</div>
          </div>
        </div>
      )}

      {/* 심각도 요약 */}
      <div className="flex gap-2 mb-3">
        {combined.critical > 0 && <span className="text-xs font-bold bg-red-100 text-red-700 px-2 py-0.5 rounded">CRITICAL {combined.critical}</span>}
        {combined.high > 0 && <span className="text-xs font-bold bg-orange-100 text-orange-700 px-2 py-0.5 rounded">HIGH {combined.high}</span>}
        {combined.medium > 0 && <span className="text-xs font-bold bg-yellow-100 text-yellow-700 px-2 py-0.5 rounded">MEDIUM {combined.medium}</span>}
        {combined.low > 0 && <span className="text-xs font-bold bg-blue-100 text-blue-700 px-2 py-0.5 rounded">LOW {combined.low}</span>}
      </div>

      {/* LLM 분석 요약 */}
      {llm.summary && (
        <div className="bg-muted rounded-md p-3 mb-2">
          <div className="text-xs font-semibold text-foreground mb-1">LLM 분석 요약</div>
          <div className="text-xs text-muted-foreground">{llm.summary}</div>
        </div>
      )}

      {/* LLM 판정 근거 */}
      {reasons.length > 0 && (
        <div className="space-y-1">
          <div className="text-xs font-semibold text-foreground">판정 근거</div>
          {reasons.map((r: string, i: number) => (
            <div key={i} className="text-xs text-muted-foreground flex gap-1">
              <span className="text-foreground">•</span> {r}
            </div>
          ))}
        </div>
      )}

      {/* Provider notes */}
      {llm.provider_notes && (
        <div className="mt-2 text-xs text-blue-600 bg-blue-50 rounded p-2">
          {llm.provider_notes}
        </div>
      )}

      {/* 개별 취약점 LLM 판정은 동시탐지/단독탐지 카드에 통합됨 */}
    </div>
  );
}

// Gate 기반 교차검증 비교 카드
function GateCrossValidation({ gate, judgments }: { gate: any; judgments?: any[] }) {
  if (!gate && (!judgments || judgments.length === 0)) return null;

  // judgments 기반 동시탐지 / 단독탐지 분리
  // 동시탐지 = TRUE_POSITIVE + finding_b 있음 (두 도구 모두 탐지), 최대 3건
  const confirmed = (judgments || []).filter((j: any) => j.judgement_code === 'TRUE_POSITIVE' && j.finding_b).slice(0, 3);
  const reviewNeeded = (judgments || []).filter((j: any) => {
    const sev = (j.severity || '').toUpperCase();
    if (!['CRITICAL', 'HIGH'].includes(sev)) return false;
    // REVIEW_NEEDED이거나, TRUE_POSITIVE인데 finding_b 없는 것 (LLM이 단독으로 위험 판정)
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
              const sev = (j.severity || 'HIGH').toUpperCase();
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
            <span className="text-sm text-amber-600">(Critical/High만)</span>
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
function GateToolSummary({ gate }: { gate: any }) {
  if (!gate) return null;
  const tools = gate.tool_summaries || [];
  if (tools.length === 0) return null;

  return (
    <div className="bg-card rounded-lg border border-border shadow-sm p-4">
      <h3 className="text-sm font-semibold text-foreground mb-3">도구별 탐지 현황</h3>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {tools.map((t: any, i: number) => {
          const s = t.summary || {};
          return (
            <div key={i} className="bg-muted rounded-md p-3">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-bold text-foreground">{t.tool}</span>
                <span className="text-xs text-muted-foreground">총 {s.total || 0}건</span>
              </div>
              <div className="flex gap-2">
                {s.critical > 0 && <span className="text-xs bg-red-100 text-red-700 px-1.5 py-0.5 rounded font-bold">C:{s.critical}</span>}
                {s.high > 0 && <span className="text-xs bg-orange-100 text-orange-700 px-1.5 py-0.5 rounded font-bold">H:{s.high}</span>}
                {s.medium > 0 && <span className="text-xs bg-yellow-100 text-yellow-700 px-1.5 py-0.5 rounded font-bold">M:{s.medium}</span>}
                {s.low > 0 && <span className="text-xs bg-blue-100 text-blue-700 px-1.5 py-0.5 rounded font-bold">L:{s.low}</span>}
                {(s.total || 0) === 0 && <span className="text-xs text-muted-foreground">탐지 없음</span>}
              </div>
            </div>
          );
        })}
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
  const [apiSiemData, setApiSiemData] = useState<any>(null);
  const [llmGates, setLlmGates] = useState<Record<string, any>>({});
  const [llmJudgments, setLlmJudgments] = useState<Record<string, any[]>>({});

  // 백엔드 API에서 실제 데이터 로드
  useEffect(() => {
    fetchJson<any>('/cross').then((report) => {
      if (!report || !report.sections) return;

      // cross report의 findings → Vulnerability 형식으로 변환
      const vulns: Vulnerability[] = [];
      const crossItems: CrossAnalysisItem[] = [];

      const allFindings = [
        ...(report.sections?.SAST || []),
        ...(report.sections?.SCA || []),
        ...(report.sections?.IaC || []),
        ...(report.sections?.DAST || []),
      ];

      allFindings.forEach((f: any, i: number) => {
        const finding_a = f.finding_a || {};
        const finding_b = f.finding_b || {};
        const tools = [finding_a.tool, finding_b?.tool].filter(Boolean);

        // Vulnerability
        vulns.push({
          id: `v-${i}`,
          severity: f.severity || 'MEDIUM',
          category: f.finding_a?.category || f.finding_b?.category || 'SAST',
          tool: tools[0] || 'unknown',
          file: finding_a.file_path || finding_b.file_path || '',
          line: finding_a.line_number || finding_b.line_number || 0,
          cwe: (finding_a.category === 'SCA' || finding_b.category === 'SCA')
            ? (finding_a.cve_id || finding_b.cve_id || finding_a.cwe_id || finding_b.cwe_id || '')
            : (finding_a.cwe_id || finding_b.cwe_id || ''),
          description: f.title_ko || finding_a.title || finding_b.title || '',
          confidence: f.confidence || 'MED',
          detectedAt: report.generated_at || new Date().toISOString(),
        });

        // CrossAnalysisItem
        crossItems.push({
          id: `c-${i}`,
          severity: f.severity || 'MEDIUM',
          category: finding_a.category || finding_b.category || 'SAST',
          tools,
          file: finding_a.file_path || finding_b.file_path || '',
          line: finding_a.line_number || finding_b.line_number || 0,
          cwe: (finding_a.category === 'SCA' || finding_b.category === 'SCA')
            ? (finding_a.cve_id || finding_b.cve_id || finding_a.cwe_id || finding_b.cwe_id || '')
            : (finding_a.cwe_id || finding_b.cwe_id || ''),
          description: f.title_ko || finding_a.title || '',
          confidence: f.confidence || 'MED',
          detectionCount: tools.length,
          llmJudgment: f.judgement_code ? {
            id: `j-${i}`,
            vulnerabilityId: `v-${i}`,
            judgment: f.judgement_code === 'TRUE_POSITIVE' ? 'TRUE_POSITIVE' :
                      f.judgement_code === 'FALSE_POSITIVE' ? 'FALSE_POSITIVE' : 'UNCERTAIN',
            confidence: f.confidence === 'HIGH' ? 90 : f.confidence === 'MED' ? 60 : 30,
            reasoning: f.reason || '',
            recommendedAction: f.action_text || '',
            riskAssessment: f.reassessed_severity || f.severity || 'MEDIUM',
            judgedAt: report.generated_at || new Date().toISOString(),
          } : undefined,
        });
      });

      setApiVulns(vulns);
      setApiCross(crossItems);
      setApiLoaded(true);

      // summary도 업데이트
      if (report.summary) {
        setSummary(prev => ({
          ...prev,
          totalVulnerabilities: report.summary.total_findings || 0,
          highCount: (report.summary.by_severity?.CRITICAL || 0) + (report.summary.by_severity?.HIGH || 0),
          mediumCount: report.summary.by_severity?.MEDIUM || 0,
          lowCount: report.summary.by_severity?.LOW || 0,
        }));
      }
    }).catch(() => {});

    // CI LLM Gate 결과 + 개별 판정 로드
    fetchJson<{ gates: Record<string, any>; judgments: Record<string, any[]> }>('/cross/gates').then((res) => {
      if (res?.gates) setLlmGates(res.gates);
      if (res?.judgments) setLlmJudgments(res.judgments);
    }).catch(() => {});

    // ISMS-P 데이터 로드
    fetchJson<any>('/isms').then((data) => {
      if (!data || data.message) return;
      setApiIsmsData(data);
    }).catch(() => {});

    // SIEM 데이터 로드
    fetchJson<any>('/siem').then((data) => {
      if (!data || data.message) return;
      setApiSiemData(data);
    }).catch(() => {});
  }, []);

  // API 데이터가 있으면 사용, 없으면 mock fallback
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

  const isPipelineStage = PIPELINE_STAGES.some(stage => stage.id === activeSection);



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
        <div className="mx-auto w-full max-w-[1400px] px-4 sm:px-6 py-6 space-y-5">
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
                      className={`w-2 h-2 rounded-full ${pipelineStatus === 'running' ? 'status-running' : ''}`}
                      style={{ backgroundColor: pipelineStatus === 'success' ? '#10b981' : pipelineStatus === 'failed' ? '#ef4444' : pipelineStatus === 'running' ? '#f59e0b' : '#94a3b8' }}
                    />
                    <span className="text-xs font-medium" style={{ color: pipelineStatus === 'success' ? '#10b981' : pipelineStatus === 'failed' ? '#ef4444' : pipelineStatus === 'running' ? '#f59e0b' : '#94a3b8' }}>
                      {pipelineStatus === 'success' ? 'SUCCESS' : pipelineStatus === 'failed' ? 'FAILED' : pipelineStatus === 'running' ? 'RUNNING' : 'IDLE'}
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
                        const stepState = getStepState(index, currentIdx, pipelineStatus, isFailure, progress);
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
                            ? { label: 'FAIL', className: 'border-red-200 bg-red-50 text-red-700' }
                            : stepState === 'running'
                              ? { label: 'RUN', className: 'border-amber-200 bg-amber-50 text-amber-700' }
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
                                    'w-[120px] md:w-[130px] lg:w-[140px] xl:w-[150px] flex-shrink-0',
                                    'lg:px-2.5 lg:py-2',
                                  ].join(' '),
                                'bg-background hover:bg-muted/40',
                                c.ring,
                                isSelected ? 'ring-2 ring-primary/25 shadow-sm' : 'hover:shadow-sm',
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
                              <div className="min-w-0 text-left flex-1 pr-1">
                                <div className="flex items-start justify-between gap-3">
                                  <div className="min-w-0">
                                    <div className="text-xs lg:text-[11px] font-semibold text-foreground leading-tight whitespace-nowrap">
                                      {stage.label}
                                    </div>
                                    <div className="text-xs lg:text-xs text-muted-foreground leading-snug whitespace-normal lg:whitespace-nowrap lg:truncate">
                                      {stage.subtitle || (index < currentIdx ? '완료' : index === currentIdx ? (stepState === 'failed' ? '실패' : '진행/대기') : '대기')}
                                    </div>
                                  </div>
                                  {badge && (
                                    <span className={`text-xs lg:text-xs font-mono px-2 lg:px-1.5 py-0.5 rounded-md border ${badge.className}`}>
                                      {badge.label}
                                    </span>
                                  )}
                                </div>
                              </div>
                            </button>

                            {opts.showConnector && index < PIPELINE_STAGES.length - 1 && (
                              <div className="hidden sm:block mx-2">
                                <div className={`h-[2px] w-10 rounded-full ${c.line}`} />
                              </div>
                            )}
                          </div>
                        );
                      };

                      return (
                        <>
                          {/* Mobile: stack (no overlap, no connector) */}
                          <div className="sm:hidden space-y-2">
                            {PIPELINE_STAGES.map((stage, index) => renderStep(stage, index, { showConnector: false, fullWidth: true }))}
                          </div>

                          {/* Desktop: horizontal sequence with connectors */}
                          <div className="hidden sm:block overflow-x-auto">
                            <div className="flex items-center gap-x-3 py-1 min-w-max">
                              {PIPELINE_STAGES.map((stage, index) => renderStep(stage, index, { showConnector: true }))}
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
              {/* 1. LLM 합산 검증 분석 결과 (맨 위) */}
              {(() => {
                const gate = llmGates['iac'];
                const llm = gate?.llm_analysis || {};
                const reasons = llm.reasons || [];
                const decision = (gate?.decision || 'review').toLowerCase();
                const decisionColor = decision === 'pass' ? 'text-green-600 bg-green-50 border-green-200'
                  : decision === 'fail' ? 'text-red-600 bg-red-50 border-red-200'
                  : 'text-amber-600 bg-amber-50 border-amber-200';
                const decisionLabel = decision === 'pass' ? '통과' : decision === 'fail' ? '차단' : '검토 필요';
                return gate ? (
                  <div className="bg-card rounded-lg border border-border shadow-sm p-5">
                    <div className="flex items-center gap-2 mb-4">
                      <span className="text-sm font-bold bg-blue-600 text-white px-2 py-1 rounded">Gemini LLM</span>
                      <span className="text-base font-semibold text-foreground">합산 검증 분석 결과</span>
                      <span className={`text-sm font-bold px-2 py-1 rounded border ${decisionColor}`}>{decisionLabel}</span>
                    </div>
                    {llm.summary && (
                      <div className="bg-muted rounded-lg p-4 mb-4">
                        <div className="text-sm font-semibold text-foreground mb-2">LLM 분석 요약</div>
                        <div className="text-sm text-foreground leading-relaxed">{llm.summary}</div>
                      </div>
                    )}
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
                    {llm.provider_notes && (
                      <div className="text-sm text-blue-700 bg-blue-50 rounded-lg p-3">{llm.provider_notes}</div>
                    )}
                  </div>
                ) : null;
              })()}

              {/* 2. 합산 검증 카드 — judgments 기반 한국어 */}
              {(llmJudgments['iac'] && llmJudgments['iac'].length > 0) ? (
              <div className="bg-card rounded-lg border border-border shadow-sm p-5">
                <div className="flex items-center gap-2 mb-4">
                  <span className="text-sm font-bold bg-blue-600 text-white px-3 py-1 rounded">합산 검증</span>
                  <span className="text-base font-semibold text-foreground">tfsec + Checkov 통합 점검 결과</span>
                </div>
                {(() => {
                  const iacJ = llmJudgments['iac'] || [];
                  const tfsecJ = iacJ.filter((j: any) => (j.finding_a?.tool || '').toLowerCase() === 'tfsec').slice(0, 5);
                  const checkovJ = iacJ.filter((j: any) => (j.finding_a?.tool || '').toLowerCase() === 'checkov').slice(0, 5);
                  const renderIacItem = (j: any, i: number) => {
                    const sev = (j.severity || 'MEDIUM').toUpperCase();
                    const sevColor = sev === 'CRITICAL' ? 'bg-red-600' : sev === 'HIGH' ? 'bg-orange-600' : sev === 'MEDIUM' ? 'bg-yellow-600' : 'bg-gray-500';
                    return (
                      <div key={i} className="bg-blue-50 border border-blue-100 rounded-lg p-4">
                        <div className="flex items-center gap-2 mb-1">
                          <span className="text-sm font-bold text-blue-700">#{i + 1}</span>
                          <span className={`text-xs font-bold text-white px-1.5 py-0.5 rounded ${sevColor}`}>{sev}</span>
                        </div>
                        <div className="text-sm font-semibold text-foreground mb-1">{j.title_ko || j.finding_a?.title}</div>
                        {j.risk_summary && <div className="text-sm text-muted-foreground mb-1">{j.risk_summary}</div>}
                        {j.action_text && <div className="text-sm text-blue-700"><strong>수정 방법:</strong> {j.action_text}</div>}
                        {j.finding_a?.file_path && <div className="text-xs text-muted-foreground mt-1">📁 {j.finding_a.file_path}{j.finding_a.line_number ? `:${j.finding_a.line_number}` : ''}</div>}
                      </div>
                    );
                  };
                  return (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div>
                        <div className="text-sm font-bold text-foreground mb-2 bg-muted rounded p-2">tfsec (상위 {tfsecJ.length}건)</div>
                        <div className="space-y-2">{tfsecJ.map(renderIacItem)}</div>
                      </div>
                      <div>
                        <div className="text-sm font-bold text-foreground mb-2 bg-muted rounded p-2">Checkov (상위 {checkovJ.length}건)</div>
                        <div className="space-y-2">{checkovJ.map(renderIacItem)}</div>
                      </div>
                    </div>
                  );
                })()}
              </div>
              ) : (
              <div className="bg-card rounded-lg border border-border p-6 text-center text-muted-foreground text-sm">
                IaC LLM 판정 데이터가 없습니다. 다음 CI 실행 후 표시됩니다.
              </div>
              )}

              {/* 3. Severity 카드 */}
              <GateSeverityCards gate={llmGates['iac']} />

              {/* 4. 취약점 목록 — tfsec + checkov 둘 다 */}
              <VulnerabilityTable
                vulnerabilities={[
                  ...vulnerabilities.filter((v) => v.tool?.toLowerCase() === 'tfsec').slice(0, 5),
                  ...vulnerabilities.filter((v) => v.tool?.toLowerCase() === 'checkov').slice(0, 5),
                ]}
                judgments={llmJudgments['iac']}
                category="IaC"
              />
            </div>
          )}

          {activeSection === 'sast' && (
            <div className="space-y-5">
              <LlmGateSummary gate={llmGates['sast']} judgments={llmJudgments['sast']} mode="cross" />
              <GateCrossValidation gate={llmGates['sast']} judgments={llmJudgments['sast']} />
              <GateSeverityCards gate={llmGates['sast']} />
              <GateToolSummary gate={llmGates['sast']} />
              <VulnerabilityTable vulnerabilities={vulnerabilities.filter((v) => ['semgrep', 'sonarqube', 'bandit'].includes(v.tool?.toLowerCase())).slice(0, 10)} judgments={llmJudgments['sast']} category="SAST" />
            </div>
          )}

          {activeSection === 'sca' && (
            <div className="space-y-5">
              <LlmGateSummary gate={llmGates['sca']} judgments={llmJudgments['sca']} mode="cross" />
              <GateCrossValidation gate={llmGates['sca']} judgments={llmJudgments['sca']} />
              <GateSeverityCards gate={llmGates['sca']} />
              <GateToolSummary gate={llmGates['sca']} />
              <VulnerabilityTable vulnerabilities={vulnerabilities.filter((v) => ['trivy', 'depcheck', 'dep-check'].includes(v.tool?.toLowerCase())).slice(0, 10)} judgments={llmJudgments['sca']} category="SCA" />
            </div>
          )}

          {activeSection === 'cross' && (
            <div className="space-y-5">
              <SummaryCards
                summary={currentSummary}
                activeSection={activeSection}
                vulnerabilities={vulnerabilities}
                crossAnalysisItems={crossAnalysisItems}
              />

              <StageCrossAnalysis items={crossAnalysisItems} />

              <div className="bg-card rounded-lg border border-border shadow-sm p-4">
                <h3 className="text-sm font-semibold text-foreground mb-2">스코어 트렌드</h3>
                <p className="text-xs text-muted-foreground mb-4">
                  최근 스캔 주기별 점수 변화를 확인하세요.
                </p>
                <VulnerabilityCharts
                  summary={currentSummary}
                  toolData={mockToolChartData}
                  categoryData={mockCategoryChartData}
                />
              </div>

              <CrossAnalysis items={crossAnalysisItems} />
            </div>
          )}



          {activeSection === 'image' && (
            <div className="space-y-5">
              <SummaryCards summary={currentSummary} activeSection={activeSection} vulnerabilities={vulnerabilities} crossAnalysisItems={crossAnalysisItems} />
              {/* 교차 검증 결과 테이블 */}
              {(() => {
                const stageCrossAnalysis = crossAnalysisItems.filter(item =>
                  item.tools.some(tool => ['Semgrep', 'Bandit', 'ESLint Security', 'Gitleaks'].includes(tool))
                );

                return <StageCrossAnalysis items={stageCrossAnalysis} />;
              })()}
              <VulnerabilityTable
                vulnerabilities={vulnerabilities.filter((v) => v.tool?.toLowerCase() === 'trivy')}
              />
            </div>
          )}

          {activeSection === 'deploy' && (
            <div className="space-y-5">
              <SummaryCards summary={currentSummary} activeSection={activeSection} vulnerabilities={vulnerabilities} crossAnalysisItems={crossAnalysisItems} />
              {/* 교차 검증 결과 테이블 */}
              {(() => {
                const stageCrossAnalysis = crossAnalysisItems.filter(item =>
                  item.tools.some(tool => ['Semgrep', 'Bandit', 'ESLint Security'].includes(tool))
                );

                return <StageCrossAnalysis items={stageCrossAnalysis} />;
              })()}
              <div className="bg-card rounded-lg border border-border shadow-sm p-4">
                <h3 className="text-sm font-semibold text-foreground mb-2">배포 상태 (ECS Fargate)</h3>
                <p className="text-xs text-muted-foreground mb-4">최근 배포 로그 및 서비스 상태를 확인합니다.</p>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="rounded-md border border-border p-4">
                    <div className="text-xs text-muted-foreground mb-2">서비스 상태</div>
                    <div className="text-sm font-semibold">Running</div>
                    <div className="text-xs text-muted-foreground mt-1">모든 태스크가 정상 실행 중입니다.</div>
                  </div>
                  <div className="rounded-md border border-border p-4">
                    <div className="text-xs text-muted-foreground mb-2">최근 배포</div>
                    <div className="text-sm font-semibold">v2.4.1</div>
                    <div className="text-xs text-muted-foreground mt-1">약 5분 전 완료</div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeSection === 'dast' && (
            <div className="space-y-5">
              <SummaryCards summary={currentSummary} activeSection={activeSection} vulnerabilities={vulnerabilities} crossAnalysisItems={crossAnalysisItems} />
              {/* 교차 검증 결과 테이블 */}
              {(() => {
                const stageCrossAnalysis = crossAnalysisItems.filter(item =>
                  item.tools.some(tool => ['OWASP ZAP'].includes(tool))
                );

                return <StageCrossAnalysis items={stageCrossAnalysis} />;
              })()}
              <VulnerabilityTable
                vulnerabilities={vulnerabilities.filter((v) => ['zap', 'owasp zap'].includes(v.tool?.toLowerCase()))}
              />
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

          {activeSection === 'isms' && (
            <div className="space-y-5">
              <div className="bg-card rounded-lg p-4 shadow-sm border border-border">
                <div className="flex items-start justify-between mb-3 gap-4">
                  <div>
                    <div className="text-sm font-semibold text-foreground">ISMS-P 연관 항목</div>
                    <div className="text-xs text-muted-foreground mt-1">충족률</div>
                  </div>

                  <div className="flex flex-col items-end gap-2">
                    <button
                      onClick={handleIsmpCheck}
                      disabled={scanState.isIsmpChecking}
                      className="inline-flex items-center gap-2 rounded-lg bg-emerald-600 px-4 py-2 text-sm font-semibold text-white hover:bg-emerald-700 disabled:opacity-60 disabled:cursor-not-allowed"
                    >
                      {scanState.isIsmpChecking ? '점검 실행 중...' : 'ISMS-P 점검 실행'}
                    </button>

                    {scanState.isIsmpChecking && (
                      <div className="w-56">
                        <div className="flex justify-between text-[11px] text-muted-foreground mb-1">
                          <span>{scanState.stage}</span>
                          <span>{scanState.progress}%</span>
                        </div>
                        <div className="h-1.5 bg-slate-100 rounded-full overflow-hidden">
                          <div
                            className="h-full bg-emerald-500 rounded-full transition-all duration-300"
                            style={{ width: `${scanState.progress}%` }}
                          />
                        </div>
                      </div>
                    )}
                  </div>
                </div>

                <div className="flex items-center gap-4">
                  <div className="flex-1">
                    <div className="text-2xl font-bold font-mono text-emerald-600">
                      {currentSummary.ismsPCompliance.toFixed(1)}%
                    </div>
                    <div className="mt-2 h-2 bg-emerald-100 rounded-full overflow-hidden">
                      <div
                        className="h-full bg-emerald-500 rounded-full transition-all duration-500"
                        style={{ width: `${currentSummary.ismsPCompliance}%` }}
                      />
                    </div>
                  </div>
                  <div className="text-xs text-muted-foreground">
                    <div>총 {apiIsmsData?.summary?.total_automated ?? mockIsmpItems.length}개 항목 중</div>
                    <div>{apiIsmsData?.summary?.compliant ?? Math.round(mockIsmpItems.length * currentSummary.ismsPCompliance / 100)}개 충족</div>
                  </div>
                </div>
              </div>

              <IsmpSection items={apiIsmsData?.automated_results ? apiIsmsData.automated_results.map((r: any, i: number) => ({
                id: `isms-${i}`,
                controlId: r.isms_p_id || '',
                domain: r.isms_p_name || '',
                requirement: r.manual_supplement || '',
                status: r.status === 'COMPLIANT' ? 'PASS' : r.status === 'NON_COMPLIANT' ? 'FAIL' : 'N/A',
                evidence: r.check_details?.map((c: any) => c.reason).join(', ') || '점검 데이터 부족',
                lastChecked: apiIsmsData.metadata?.checked_at || new Date().toISOString(),
              })) : mockIsmpItems} compliance={apiIsmsData?.summary?.compliance_rate_pct ?? currentSummary.ismsPCompliance} />
            </div>
          )}
        </div>
      </main>
    </div>
  );
}
