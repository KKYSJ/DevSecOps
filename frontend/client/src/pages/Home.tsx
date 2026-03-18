// DevSecOps Dashboard - Home Page
// Design: Clean Governance Dashboard | IBM Plex Sans + IBM Plex Mono
// Layout: Fixed top nav + Scrollable main content

import { useState, useCallback, useMemo } from 'react';
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
import type { ScanSummary } from '@/lib/types';
import StageCrossAnalysis from '@/components/StageCrossAnalysis';

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

  const activeStageLabel = PIPELINE_STAGES.find((s) => s.id === activeSection)?.label ?? '';

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
                                    <div className="text-[10px] lg:text-[9px] text-muted-foreground leading-snug whitespace-normal lg:whitespace-nowrap lg:truncate">
                                      {stage.subtitle || (index < currentIdx ? '완료' : index === currentIdx ? (stepState === 'failed' ? '실패' : '진행/대기') : '대기')}
                                    </div>
                                  </div>
                                  {badge && (
                                    <span className={`text-[10px] lg:text-[9px] font-mono px-2 lg:px-1.5 py-0.5 rounded-md border ${badge.className}`}>
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
              {/* 교차 검증 결과 테이블 */}
              <SummaryCards summary={currentSummary} activeSection={activeSection} vulnerabilities={mockVulnerabilities} crossAnalysisItems={mockCrossAnalysis} />
              {(() => {
                const stageCrossAnalysis = mockCrossAnalysis.filter(item =>
                  item.tools.some(tool => ['tfsec', 'Checkov'].includes(tool))
                );

                return <StageCrossAnalysis items={stageCrossAnalysis} />;
              })()}

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <div className="bg-card rounded-lg border border-border shadow-sm p-4">
                  <h3 className="text-sm font-semibold text-foreground mb-2">IaC 스캔</h3>
                  <p className="text-xs text-muted-foreground mb-4">tfsec + Checkov 결과</p>
                  <div className="space-y-2">
                    {mockVulnerabilities
                      .filter((v) => ['tfsec', 'Checkov'].includes(v.tool))
                      .map((v) => (
                        <div key={v.id} className="rounded-md border border-border p-3">
                          <div className="flex items-center justify-between">
                            <span className="text-xs font-semibold text-foreground">{v.category}</span>
                            <span className="text-[10px] text-muted-foreground">{v.tool}</span>
                          </div>
                          <div className="text-[10px] text-muted-foreground mt-1">{v.description}</div>
                        </div>
                      ))}
                  </div>
                </div>
                <div className="bg-card rounded-lg border border-border shadow-sm p-4">
                  <h3 className="text-sm font-semibold text-foreground mb-2">취약점 테이블</h3>
                  <VulnerabilityTable vulnerabilities={mockVulnerabilities.filter((v) => ['tfsec', 'Checkov'].includes(v.tool))} />
                </div>
              </div>
            </div>
          )}

          {activeSection === 'sast' && (
            <div className="space-y-5">
              <SummaryCards summary={currentSummary} activeSection={activeSection} vulnerabilities={mockVulnerabilities} crossAnalysisItems={mockCrossAnalysis} />
              {/* 교차 검증 결과 테이블 */}
              {(() => {
                const stageCrossAnalysis = mockCrossAnalysis.filter(item =>
                  item.tools.some(tool => ['Semgrep', 'SonarQube', 'Bandit', 'ESLint Security'].includes(tool))
                );

                return <StageCrossAnalysis items={stageCrossAnalysis} />;
              })()}
              <VulnerabilityTable
                vulnerabilities={mockVulnerabilities.filter((v) => ['Semgrep', 'SonarQube', 'Bandit'].includes(v.tool))}
              />
            </div>
          )}

          {activeSection === 'sca' && (
            <div className="space-y-5">
              <SummaryCards summary={currentSummary} activeSection={activeSection} vulnerabilities={mockVulnerabilities} crossAnalysisItems={mockCrossAnalysis} />
              {/* 교차 검증 결과 테이블 */}
              {(() => {
                const stageCrossAnalysis = mockCrossAnalysis.filter(item =>
                  item.tools.some(tool => ['Trivy', 'Dep-Check'].includes(tool))
                );

                return <StageCrossAnalysis items={stageCrossAnalysis} />;
              })()}
              <VulnerabilityTable
                vulnerabilities={mockVulnerabilities.filter((v) => ['Trivy', 'Dep-Check'].includes(v.tool))}
              />
            </div>
          )}

          {activeSection === 'cross' && (
            <div className="space-y-5">
              <SummaryCards
                summary={currentSummary}
                activeSection={activeSection}
                vulnerabilities={mockVulnerabilities}
                crossAnalysisItems={mockCrossAnalysis}
              />

              <StageCrossAnalysis items={mockCrossAnalysis} />

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

              <CrossAnalysis items={mockCrossAnalysis} />
            </div>
          )}



          {activeSection === 'image' && (
            <div className="space-y-5">
              <SummaryCards summary={currentSummary} activeSection={activeSection} vulnerabilities={mockVulnerabilities} crossAnalysisItems={mockCrossAnalysis} />
              {/* 교차 검증 결과 테이블 */}
              {(() => {
                const stageCrossAnalysis = mockCrossAnalysis.filter(item =>
                  item.tools.some(tool => ['Semgrep', 'Bandit', 'ESLint Security', 'Gitleaks'].includes(tool))
                );

                return <StageCrossAnalysis items={stageCrossAnalysis} />;
              })()}
              <VulnerabilityTable
                vulnerabilities={mockVulnerabilities.filter((v) => v.tool === 'Trivy')}
              />
            </div>
          )}

          {activeSection === 'deploy' && (
            <div className="space-y-5">
              <SummaryCards summary={currentSummary} activeSection={activeSection} vulnerabilities={mockVulnerabilities} crossAnalysisItems={mockCrossAnalysis} />
              {/* 교차 검증 결과 테이블 */}
              {(() => {
                const stageCrossAnalysis = mockCrossAnalysis.filter(item =>
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
                    <div className="text-[10px] text-muted-foreground mt-1">모든 태스크가 정상 실행 중입니다.</div>
                  </div>
                  <div className="rounded-md border border-border p-4">
                    <div className="text-xs text-muted-foreground mb-2">최근 배포</div>
                    <div className="text-sm font-semibold">v2.4.1</div>
                    <div className="text-[10px] text-muted-foreground mt-1">약 5분 전 완료</div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeSection === 'dast' && (
            <div className="space-y-5">
              <SummaryCards summary={currentSummary} activeSection={activeSection} vulnerabilities={mockVulnerabilities} crossAnalysisItems={mockCrossAnalysis} />
              {/* 교차 검증 결과 테이블 */}
              {(() => {
                const stageCrossAnalysis = mockCrossAnalysis.filter(item =>
                  item.tools.some(tool => ['OWASP ZAP'].includes(tool))
                );

                return <StageCrossAnalysis items={stageCrossAnalysis} />;
              })()}
              <VulnerabilityTable
                vulnerabilities={mockVulnerabilities.filter((v) => v.tool === 'OWASP ZAP')}
              />
            </div>
          )}

          {activeSection === 'siem' && (
            <div className="space-y-5">
              <SecurityMonitoring
                summary={mockSecurityMonitoringSummary}
                serviceStatuses={mockServiceStatuses}
                eventItems={mockEventItems}
                trendData={mockTrendChartData}
              />
            </div>
          )}

          {activeSection === 'isms' && (
            <div className="space-y-5">
              {/* ISMS-P Compliance Card */}
              <div className="bg-card rounded-lg p-4 shadow-sm border border-border">
                <div className="flex items-center justify-between mb-3">
                  <div className="text-sm font-semibold text-foreground">ISMS-P 연관 항목</div>
                  <div className="text-xs text-muted-foreground">충족률</div>
                </div>
                <div className="flex items-center gap-4">
                  <div className="flex-1">
                    <div className="text-2xl font-bold font-mono text-emerald-600">{currentSummary.ismsPCompliance.toFixed(1)}%</div>
                    <div className="mt-2 h-2 bg-emerald-100 rounded-full overflow-hidden">
                      <div className="h-full bg-emerald-500 rounded-full transition-all duration-500" style={{ width: `${currentSummary.ismsPCompliance}%` }} />
                    </div>
                  </div>
                  <div className="text-xs text-muted-foreground">
                    <div>총 {mockIsmpItems.length}개 항목 중</div>
                    <div>{Math.round(mockIsmpItems.length * currentSummary.ismsPCompliance / 100)}개 충족</div>
                  </div>
                </div>
              </div>

              <ActionButtons
                scanState={scanState}
                onRefresh={handleRefresh}
                onSecurityScan={handleSecurityScan}
                onCrossAnalysis={handleCrossAnalysis}
                onIsmpCheck={handleIsmpCheck}
              />
              <IsmpSection items={mockIsmpItems} compliance={currentSummary.ismsPCompliance} />
            </div>
          )}
        </div>
      </main>
    </div>
  );
}
