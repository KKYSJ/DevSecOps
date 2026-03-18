// DevSecOps Dashboard - Home Page
// Design: Clean Governance Dashboard | IBM Plex Sans + IBM Plex Mono
// Layout: Fixed top nav + Scrollable main content

import { useState, useCallback, useMemo } from 'react';
import { toast } from 'sonner';
import { Cloud, Code2, ShieldCheck, GitBranch, SlidersHorizontal, Image, Server, Bug, Monitor, ArrowLeft } from 'lucide-react';
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

const PIPELINE_STAGES = [
  { id: 'iac', label: 'IaC 스캔', subtitle: 'tfsec + Checkov', icon: Cloud },
  { id: 'sast', label: 'SAST', subtitle: 'SonarQube + Semgrep', icon: Code2 },
  { id: 'sca', label: 'SCA', subtitle: 'Trivy + Dep-Check', icon: ShieldCheck },
  { id: 'cross', label: '교차 검증', subtitle: '', icon: GitBranch },
  { id: 'normalize', label: '정규화 + 스코어링', subtitle: '', icon: SlidersHorizontal },
  { id: 'image', label: '이미지 스캔', subtitle: 'Trivy', icon: Image },
  { id: 'deploy', label: '배포', subtitle: 'ECS Fargate', icon: Server },
  { id: 'dast', label: 'DAST', subtitle: 'OWASP ZAP', icon: Bug },
];

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
    <div className="min-h-screen bg-background pt-14">
      {/* Deployment Header */}
      {deployment && (
        <div
          className="border-b border-border bg-card cursor-pointer hover:bg-muted/50 transition-colors"
          onClick={() => setLocation('/')}
        >
          <div className="max-w-[1400px] mx-auto px-6 py-4 flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div>
                <ArrowLeft size={20} className="text-foreground" />
              </div>
              <div>
                <h1 className="text-lg font-semibold text-foreground">{deployment.name}</h1>
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
          <div className="p-6 space-y-5 max-w-[1400px]">
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
                <div className="flex items-center gap-2 overflow-x-auto pb-2">
                  {PIPELINE_STAGES.map((stage, index) => {
                    const Icon = stage.icon;
                    const isActive = activeSection === stage.id;
                    const isCompleted = false; // TODO: Add completion logic based on scan results

                    return (
                      <div key={stage.id} className="flex items-center gap-2 flex-shrink-0">
                        <button
                          onClick={() => setActiveSection(stage.id)}
                          className={`flex items-center gap-2 px-3 py-2 rounded-md text-xs font-medium transition-all duration-150 min-w-0 ${
                            isActive
                              ? 'bg-primary text-primary-foreground shadow-sm'
                              : 'bg-muted hover:bg-muted/80 text-muted-foreground'
                          }`}
                        >
                          <Icon size={14} />
                          <div className="flex flex-col items-start">
                            <span className="truncate max-w-20">{stage.label}</span>
                            {stage.subtitle && (
                              <span className="text-[10px] opacity-75 truncate max-w-20">{stage.subtitle}</span>
                            )}
                          </div>
                        </button>
                        {index < PIPELINE_STAGES.length - 1 && (
                          <div className="w-4 h-px bg-border flex-shrink-0" />
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {/* Stage content */}
            {activeSection === 'iac' && (
              <div className="space-y-5">
                <SummaryCards summary={currentSummary} activeSection={activeSection} vulnerabilities={mockVulnerabilities} crossAnalysisItems={mockCrossAnalysis} />
                {/* 교차 검증 결과 테이블 */}
                {(() => {
                  const stageCrossAnalysis = mockCrossAnalysis.filter(item =>
                    item.tools.some(tool => ['tfsec', 'Checkov'].includes(tool))
                  );
                  const llmJudgments = stageCrossAnalysis.filter(item => item.llmJudgment).map(item => item.llmJudgment!);

                  return stageCrossAnalysis.length > 0 ? (
                    <div className="bg-card rounded-lg border border-border shadow-sm p-4">
                      <h3 className="text-sm font-semibold text-foreground mb-4">교차 검증 결과</h3>
                      <div className="space-y-3">
                        {stageCrossAnalysis.map((item) => (
                          <div key={item.id} className="border border-border rounded-md p-3">
                            <div className="flex items-center justify-between mb-2">
                              <div className="flex items-center gap-2">
                                <span className="text-sm font-semibold text-foreground">{item.category}</span>
                                <span className={`px-2 py-1 text-xs font-medium rounded ${
                                  item.severity === 'HIGH' ? 'bg-red-100 text-red-700' :
                                  item.severity === 'MEDIUM' ? 'bg-amber-100 text-amber-700' : 'bg-blue-100 text-blue-700'
                                }`}>
                                  {item.severity}
                                </span>
                              </div>
                              <div className="text-xs text-muted-foreground">
                                {item.detectionCount}개 도구 탐지
                              </div>
                            </div>
                            <div className="text-xs text-muted-foreground mb-2">{item.description}</div>
                            <div className="flex flex-wrap gap-1 mb-2">
                              {item.tools.map((tool) => (
                                <span key={tool} className="px-2 py-1 bg-slate-100 text-slate-700 text-xs rounded">
                                  {tool}
                                </span>
                              ))}
                            </div>
                            {item.llmJudgment && (
                              <div className="border-t border-border pt-2 mt-2">
                                <div className="flex items-center justify-between mb-1">
                                  <span className="text-xs font-medium text-foreground">LLM 판정</span>
                                  <span className={`px-2 py-1 text-xs font-medium rounded ${
                                    item.llmJudgment.judgment === 'TRUE_POSITIVE' ? 'bg-green-100 text-green-700' :
                                    item.llmJudgment.judgment === 'FALSE_POSITIVE' ? 'bg-red-100 text-red-700' : 'bg-amber-100 text-amber-700'
                                  }`}>
                                    {item.llmJudgment.judgment === 'TRUE_POSITIVE' ? '확정' :
                                     item.llmJudgment.judgment === 'FALSE_POSITIVE' ? '오탐' : '불확실'}
                                  </span>
                                </div>
                                <div className="text-xs text-muted-foreground mb-1">
                                  신뢰도: {item.llmJudgment.confidence}%
                                </div>
                                <div className="text-xs text-muted-foreground">
                                  {item.llmJudgment.reasoning}
                                </div>
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  ) : null;
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
                  const llmJudgments = stageCrossAnalysis.filter(item => item.llmJudgment).map(item => item.llmJudgment!);

                  return stageCrossAnalysis.length > 0 ? (
                    <div className="bg-card rounded-lg border border-border shadow-sm p-4">
                      <h3 className="text-sm font-semibold text-foreground mb-4">교차 검증 결과</h3>
                      <div className="space-y-3">
                        {stageCrossAnalysis.map((item) => (
                          <div key={item.id} className="border border-border rounded-md p-3">
                            <div className="flex items-center justify-between mb-2">
                              <div className="flex items-center gap-2">
                                <span className="text-sm font-semibold text-foreground">{item.category}</span>
                                <span className={`px-2 py-1 text-xs font-medium rounded ${
                                  item.severity === 'HIGH' ? 'bg-red-100 text-red-700' :
                                  item.severity === 'MEDIUM' ? 'bg-amber-100 text-amber-700' : 'bg-blue-100 text-blue-700'
                                }`}>
                                  {item.severity}
                                </span>
                              </div>
                              <div className="text-xs text-muted-foreground">
                                {item.detectionCount}개 도구 탐지
                              </div>
                            </div>
                            <div className="text-xs text-muted-foreground mb-2">{item.description}</div>
                            <div className="flex flex-wrap gap-1 mb-2">
                              {item.tools.map((tool) => (
                                <span key={tool} className="px-2 py-1 bg-slate-100 text-slate-700 text-xs rounded">
                                  {tool}
                                </span>
                              ))}
                            </div>
                            {item.llmJudgment && (
                              <div className="border-t border-border pt-2 mt-2">
                                <div className="flex items-center justify-between mb-1">
                                  <span className="text-xs font-medium text-foreground">LLM 판정</span>
                                  <span className={`px-2 py-1 text-xs font-medium rounded ${
                                    item.llmJudgment.judgment === 'TRUE_POSITIVE' ? 'bg-green-100 text-green-700' :
                                    item.llmJudgment.judgment === 'FALSE_POSITIVE' ? 'bg-red-100 text-red-700' : 'bg-amber-100 text-amber-700'
                                  }`}>
                                    {item.llmJudgment.judgment === 'TRUE_POSITIVE' ? '확정' :
                                     item.llmJudgment.judgment === 'FALSE_POSITIVE' ? '오탐' : '불확실'}
                                  </span>
                                </div>
                                <div className="text-xs text-muted-foreground mb-1">
                                  신뢰도: {item.llmJudgment.confidence}%
                                </div>
                                <div className="text-xs text-muted-foreground">
                                  {item.llmJudgment.reasoning}
                                </div>
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  ) : null;
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
                  const llmJudgments = stageCrossAnalysis.filter(item => item.llmJudgment).map(item => item.llmJudgment!);

                  return stageCrossAnalysis.length > 0 ? (
                    <div className="bg-card rounded-lg border border-border shadow-sm p-4">
                      <h3 className="text-sm font-semibold text-foreground mb-4">교차 검증 결과</h3>
                      <div className="space-y-3">
                        {stageCrossAnalysis.map((item) => (
                          <div key={item.id} className="border border-border rounded-md p-3">
                            <div className="flex items-center justify-between mb-2">
                              <div className="flex items-center gap-2">
                                <span className="text-sm font-semibold text-foreground">{item.category}</span>
                                <span className={`px-2 py-1 text-xs font-medium rounded ${
                                  item.severity === 'HIGH' ? 'bg-red-100 text-red-700' :
                                  item.severity === 'MEDIUM' ? 'bg-amber-100 text-amber-700' : 'bg-blue-100 text-blue-700'
                                }`}>
                                  {item.severity}
                                </span>
                              </div>
                              <div className="text-xs text-muted-foreground">
                                {item.detectionCount}개 도구 탐지
                              </div>
                            </div>
                            <div className="text-xs text-muted-foreground mb-2">{item.description}</div>
                            <div className="flex flex-wrap gap-1 mb-2">
                              {item.tools.map((tool) => (
                                <span key={tool} className="px-2 py-1 bg-slate-100 text-slate-700 text-xs rounded">
                                  {tool}
                                </span>
                              ))}
                            </div>
                            {item.llmJudgment && (
                              <div className="border-t border-border pt-2 mt-2">
                                <div className="flex items-center justify-between mb-1">
                                  <span className="text-xs font-medium text-foreground">LLM 판정</span>
                                  <span className={`px-2 py-1 text-xs font-medium rounded ${
                                    item.llmJudgment.judgment === 'TRUE_POSITIVE' ? 'bg-green-100 text-green-700' :
                                    item.llmJudgment.judgment === 'FALSE_POSITIVE' ? 'bg-red-100 text-red-700' : 'bg-amber-100 text-amber-700'
                                  }`}>
                                    {item.llmJudgment.judgment === 'TRUE_POSITIVE' ? '확정' :
                                     item.llmJudgment.judgment === 'FALSE_POSITIVE' ? '오탐' : '불확실'}
                                  </span>
                                </div>
                                <div className="text-xs text-muted-foreground mb-1">
                                  신뢰도: {item.llmJudgment.confidence}%
                                </div>
                                <div className="text-xs text-muted-foreground">
                                  {item.llmJudgment.reasoning}
                                </div>
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  ) : null;
                })()}
                <VulnerabilityTable
                  vulnerabilities={mockVulnerabilities.filter((v) => ['Trivy', 'Dep-Check'].includes(v.tool))}
                />
              </div>
            )}

            {activeSection === 'cross' && (
              <div className="space-y-5">
                <SummaryCards summary={currentSummary} activeSection={activeSection} vulnerabilities={mockVulnerabilities} crossAnalysisItems={mockCrossAnalysis} />
                {/* 교차 검증 결과 테이블 - 모든 항목 표시 */}
                <div className="bg-card rounded-lg border border-border shadow-sm p-4">
                  <h3 className="text-sm font-semibold text-foreground mb-4">교차 검증 결과</h3>
                  <div className="space-y-3">
                    {mockCrossAnalysis.map((item) => (
                      <div key={item.id} className="border border-border rounded-md p-3">
                        <div className="flex items-center justify-between mb-2">
                          <div className="flex items-center gap-2">
                            <span className="text-sm font-semibold text-foreground">{item.category}</span>
                            <span className={`px-2 py-1 text-xs font-medium rounded ${
                              item.severity === 'HIGH' ? 'bg-red-100 text-red-700' :
                              item.severity === 'MEDIUM' ? 'bg-amber-100 text-amber-700' : 'bg-blue-100 text-blue-700'
                            }`}>
                              {item.severity}
                            </span>
                          </div>
                          <div className="text-xs text-muted-foreground">
                            {item.detectionCount}개 도구 탐지
                          </div>
                        </div>
                        <div className="text-xs text-muted-foreground mb-2">{item.description}</div>
                        <div className="flex flex-wrap gap-1 mb-2">
                          {item.tools.map((tool) => (
                            <span key={tool} className="px-2 py-1 bg-slate-100 text-slate-700 text-xs rounded">
                              {tool}
                            </span>
                          ))}
                        </div>
                        {item.llmJudgment && (
                          <div className="border-t border-border pt-2 mt-2">
                            <div className="flex items-center justify-between mb-1">
                              <span className="text-xs font-medium text-foreground">LLM 판정</span>
                              <span className={`px-2 py-1 text-xs font-medium rounded ${
                                item.llmJudgment.judgment === 'TRUE_POSITIVE' ? 'bg-green-100 text-green-700' :
                                item.llmJudgment.judgment === 'FALSE_POSITIVE' ? 'bg-red-100 text-red-700' : 'bg-amber-100 text-amber-700'
                              }`}>
                                {item.llmJudgment.judgment === 'TRUE_POSITIVE' ? '확정' :
                                 item.llmJudgment.judgment === 'FALSE_POSITIVE' ? '오탐' : '불확실'}
                              </span>
                            </div>
                            <div className="text-xs text-muted-foreground mb-1">
                              신뢰도: {item.llmJudgment.confidence}%
                            </div>
                            <div className="text-xs text-muted-foreground">
                              {item.llmJudgment.reasoning}
                            </div>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
                <CrossAnalysis items={mockCrossAnalysis} />
              </div>
            )}

            {activeSection === 'normalize' && (
              <div className="space-y-5">
                <SummaryCards summary={currentSummary} activeSection={activeSection} vulnerabilities={mockVulnerabilities} crossAnalysisItems={mockCrossAnalysis} />
                {/* 교차 검증 결과 테이블 */}
                {(() => {
                  const stageCrossAnalysis = mockCrossAnalysis.filter(item =>
                    item.tools.some(tool => ['Semgrep', 'Bandit', 'ESLint Security', 'Gitleaks'].includes(tool))
                  );
                  const llmJudgments = stageCrossAnalysis.filter(item => item.llmJudgment).map(item => item.llmJudgment!);

                  return stageCrossAnalysis.length > 0 ? (
                    <div className="bg-card rounded-lg border border-border shadow-sm p-4">
                      <h3 className="text-sm font-semibold text-foreground mb-4">교차 검증 결과</h3>
                      <div className="space-y-3">
                        {stageCrossAnalysis.map((item) => (
                          <div key={item.id} className="border border-border rounded-md p-3">
                            <div className="flex items-center justify-between mb-2">
                              <div className="flex items-center gap-2">
                                <span className="text-sm font-semibold text-foreground">{item.category}</span>
                                <span className={`px-2 py-1 text-xs font-medium rounded ${
                                  item.severity === 'HIGH' ? 'bg-red-100 text-red-700' :
                                  item.severity === 'MEDIUM' ? 'bg-amber-100 text-amber-700' : 'bg-blue-100 text-blue-700'
                                }`}>
                                  {item.severity}
                                </span>
                              </div>
                              <div className="text-xs text-muted-foreground">
                                {item.detectionCount}개 도구 탐지
                              </div>
                            </div>
                            <div className="text-xs text-muted-foreground mb-2">{item.description}</div>
                            <div className="flex flex-wrap gap-1 mb-2">
                              {item.tools.map((tool) => (
                                <span key={tool} className="px-2 py-1 bg-slate-100 text-slate-700 text-xs rounded">
                                  {tool}
                                </span>
                              ))}
                            </div>
                            {item.llmJudgment && (
                              <div className="border-t border-border pt-2 mt-2">
                                <div className="flex items-center justify-between mb-1">
                                  <span className="text-xs font-medium text-foreground">LLM 판정</span>
                                  <span className={`px-2 py-1 text-xs font-medium rounded ${
                                    item.llmJudgment.judgment === 'TRUE_POSITIVE' ? 'bg-green-100 text-green-700' :
                                    item.llmJudgment.judgment === 'FALSE_POSITIVE' ? 'bg-red-100 text-red-700' : 'bg-amber-100 text-amber-700'
                                  }`}>
                                    {item.llmJudgment.judgment === 'TRUE_POSITIVE' ? '확정' :
                                     item.llmJudgment.judgment === 'FALSE_POSITIVE' ? '오탐' : '불확실'}
                                  </span>
                                </div>
                                <div className="text-xs text-muted-foreground mb-1">
                                  신뢰도: {item.llmJudgment.confidence}%
                                </div>
                                <div className="text-xs text-muted-foreground">
                                  {item.llmJudgment.reasoning}
                                </div>
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  ) : null;
                })()}
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                  <div className="bg-card rounded-lg border border-border shadow-sm p-4">
                    <h3 className="text-sm font-semibold text-foreground mb-2">스코어 계산</h3>
                    <p className="text-xs text-muted-foreground mb-4">취약점별 가중치 적용 및 최종 스코어 계산</p>
                    <div className="space-y-3">
                      <div className="flex items-center justify-between">
                        <span className="text-sm text-muted-foreground">전체 취약점</span>
                        <span className="font-semibold">{mockVulnerabilities.length}</span>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-sm text-muted-foreground">가중치 적용</span>
                        <span className="font-semibold">85%</span>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-sm text-foreground font-medium">최종 스코어</span>
                        <span className="font-semibold">{(100 - mockVulnerabilities.length).toFixed(0)} / 100</span>
                      </div>
                    </div>
                  </div>
                  <div className="bg-card rounded-lg border border-border shadow-sm p-4">
                    <h3 className="text-sm font-semibold text-foreground mb-2">스코어 트렌드</h3>
                    <p className="text-xs text-muted-foreground">최근 스캔 주기별 점수 변화를 확인하세요.</p>
                    <VulnerabilityCharts
                      summary={currentSummary}
                      toolData={mockToolChartData}
                      categoryData={mockCategoryChartData}
                    />
                  </div>
                </div>
              </div>
            )}

            {activeSection === 'image' && (
              <div className="space-y-5">
                <SummaryCards summary={currentSummary} activeSection={activeSection} vulnerabilities={mockVulnerabilities} crossAnalysisItems={mockCrossAnalysis} />
                {/* 교차 검증 결과 테이블 */}
                {(() => {
                  const stageCrossAnalysis = mockCrossAnalysis.filter(item =>
                    item.tools.some(tool => ['Trivy'].includes(tool))
                  );
                  const llmJudgments = stageCrossAnalysis.filter(item => item.llmJudgment).map(item => item.llmJudgment!);

                  return stageCrossAnalysis.length > 0 ? (
                    <div className="bg-card rounded-lg border border-border shadow-sm p-4">
                      <h3 className="text-sm font-semibold text-foreground mb-4">교차 검증 결과</h3>
                      <div className="space-y-3">
                        {stageCrossAnalysis.map((item) => (
                          <div key={item.id} className="border border-border rounded-md p-3">
                            <div className="flex items-center justify-between mb-2">
                              <div className="flex items-center gap-2">
                                <span className="text-sm font-semibold text-foreground">{item.category}</span>
                                <span className={`px-2 py-1 text-xs font-medium rounded ${
                                  item.severity === 'HIGH' ? 'bg-red-100 text-red-700' :
                                  item.severity === 'MEDIUM' ? 'bg-amber-100 text-amber-700' : 'bg-blue-100 text-blue-700'
                                }`}>
                                  {item.severity}
                                </span>
                              </div>
                              <div className="text-xs text-muted-foreground">
                                {item.detectionCount}개 도구 탐지
                              </div>
                            </div>
                            <div className="text-xs text-muted-foreground mb-2">{item.description}</div>
                            <div className="flex flex-wrap gap-1 mb-2">
                              {item.tools.map((tool) => (
                                <span key={tool} className="px-2 py-1 bg-slate-100 text-slate-700 text-xs rounded">
                                  {tool}
                                </span>
                              ))}
                            </div>
                            {item.llmJudgment && (
                              <div className="border-t border-border pt-2 mt-2">
                                <div className="flex items-center justify-between mb-1">
                                  <span className="text-xs font-medium text-foreground">LLM 판정</span>
                                  <span className={`px-2 py-1 text-xs font-medium rounded ${
                                    item.llmJudgment.judgment === 'TRUE_POSITIVE' ? 'bg-green-100 text-green-700' :
                                    item.llmJudgment.judgment === 'FALSE_POSITIVE' ? 'bg-red-100 text-red-700' : 'bg-amber-100 text-amber-700'
                                  }`}>
                                    {item.llmJudgment.judgment === 'TRUE_POSITIVE' ? '확정' :
                                     item.llmJudgment.judgment === 'FALSE_POSITIVE' ? '오탐' : '불확실'}
                                  </span>
                                </div>
                                <div className="text-xs text-muted-foreground mb-1">
                                  신뢰도: {item.llmJudgment.confidence}%
                                </div>
                                <div className="text-xs text-muted-foreground">
                                  {item.llmJudgment.reasoning}
                                </div>
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  ) : null;
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
                  const llmJudgments = stageCrossAnalysis.filter(item => item.llmJudgment).map(item => item.llmJudgment!);

                  return stageCrossAnalysis.length > 0 ? (
                    <div className="bg-card rounded-lg border border-border shadow-sm p-4">
                      <h3 className="text-sm font-semibold text-foreground mb-4">교차 검증 결과</h3>
                      <div className="space-y-3">
                        {stageCrossAnalysis.map((item) => (
                          <div key={item.id} className="border border-border rounded-md p-3">
                            <div className="flex items-center justify-between mb-2">
                              <div className="flex items-center gap-2">
                                <span className="text-sm font-semibold text-foreground">{item.category}</span>
                                <span className={`px-2 py-1 text-xs font-medium rounded ${
                                  item.severity === 'HIGH' ? 'bg-red-100 text-red-700' :
                                  item.severity === 'MEDIUM' ? 'bg-amber-100 text-amber-700' : 'bg-blue-100 text-blue-700'
                                }`}>
                                  {item.severity}
                                </span>
                              </div>
                              <div className="text-xs text-muted-foreground">
                                {item.detectionCount}개 도구 탐지
                              </div>
                            </div>
                            <div className="text-xs text-muted-foreground mb-2">{item.description}</div>
                            <div className="flex flex-wrap gap-1 mb-2">
                              {item.tools.map((tool) => (
                                <span key={tool} className="px-2 py-1 bg-slate-100 text-slate-700 text-xs rounded">
                                  {tool}
                                </span>
                              ))}
                            </div>
                            {item.llmJudgment && (
                              <div className="border-t border-border pt-2 mt-2">
                                <div className="flex items-center justify-between mb-1">
                                  <span className="text-xs font-medium text-foreground">LLM 판정</span>
                                  <span className={`px-2 py-1 text-xs font-medium rounded ${
                                    item.llmJudgment.judgment === 'TRUE_POSITIVE' ? 'bg-green-100 text-green-700' :
                                    item.llmJudgment.judgment === 'FALSE_POSITIVE' ? 'bg-red-100 text-red-700' : 'bg-amber-100 text-amber-700'
                                  }`}>
                                    {item.llmJudgment.judgment === 'TRUE_POSITIVE' ? '확정' :
                                     item.llmJudgment.judgment === 'FALSE_POSITIVE' ? '오탐' : '불확실'}
                                  </span>
                                </div>
                                <div className="text-xs text-muted-foreground mb-1">
                                  신뢰도: {item.llmJudgment.confidence}%
                                </div>
                                <div className="text-xs text-muted-foreground">
                                  {item.llmJudgment.reasoning}
                                </div>
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  ) : null;
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
                  const llmJudgments = stageCrossAnalysis.filter(item => item.llmJudgment).map(item => item.llmJudgment!);

                  return stageCrossAnalysis.length > 0 ? (
                    <div className="bg-card rounded-lg border border-border shadow-sm p-4">
                      <h3 className="text-sm font-semibold text-foreground mb-4">교차 검증 결과</h3>
                      <div className="space-y-3">
                        {stageCrossAnalysis.map((item) => (
                          <div key={item.id} className="border border-border rounded-md p-3">
                            <div className="flex items-center justify-between mb-2">
                              <div className="flex items-center gap-2">
                                <span className="text-sm font-semibold text-foreground">{item.category}</span>
                                <span className={`px-2 py-1 text-xs font-medium rounded ${
                                  item.severity === 'HIGH' ? 'bg-red-100 text-red-700' :
                                  item.severity === 'MEDIUM' ? 'bg-amber-100 text-amber-700' : 'bg-blue-100 text-blue-700'
                                }`}>
                                  {item.severity}
                                </span>
                              </div>
                              <div className="text-xs text-muted-foreground">
                                {item.detectionCount}개 도구 탐지
                              </div>
                            </div>
                            <div className="text-xs text-muted-foreground mb-2">{item.description}</div>
                            <div className="flex flex-wrap gap-1 mb-2">
                              {item.tools.map((tool) => (
                                <span key={tool} className="px-2 py-1 bg-slate-100 text-slate-700 text-xs rounded">
                                  {tool}
                                </span>
                              ))}
                            </div>
                            {item.llmJudgment && (
                              <div className="border-t border-border pt-2 mt-2">
                                <div className="flex items-center justify-between mb-1">
                                  <span className="text-xs font-medium text-foreground">LLM 판정</span>
                                  <span className={`px-2 py-1 text-xs font-medium rounded ${
                                    item.llmJudgment.judgment === 'TRUE_POSITIVE' ? 'bg-green-100 text-green-700' :
                                    item.llmJudgment.judgment === 'FALSE_POSITIVE' ? 'bg-red-100 text-red-700' : 'bg-amber-100 text-amber-700'
                                  }`}>
                                    {item.llmJudgment.judgment === 'TRUE_POSITIVE' ? '확정' :
                                     item.llmJudgment.judgment === 'FALSE_POSITIVE' ? '오탐' : '불확실'}
                                  </span>
                                </div>
                                <div className="text-xs text-muted-foreground mb-1">
                                  신뢰도: {item.llmJudgment.confidence}%
                                </div>
                                <div className="text-xs text-muted-foreground">
                                  {item.llmJudgment.reasoning}
                                </div>
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  ) : null;
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
