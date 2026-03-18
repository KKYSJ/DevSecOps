// DevSecOps Dashboard - SummaryCards Component
// Design: Clean Governance Dashboard | 4-column severity + ISMS-P cards for each pipeline stage

import { AlertTriangle, CheckCircle, GitMerge, Brain } from 'lucide-react';
import type { ScanSummary, Vulnerability, CrossAnalysisItem } from '@/lib/types';

interface SummaryCardsProps {
  summary: ScanSummary;
  activeSection: string;
  vulnerabilities: Vulnerability[];
  crossAnalysisItems: CrossAnalysisItem[];
}

export default function SummaryCards({ summary, activeSection, vulnerabilities, crossAnalysisItems }: SummaryCardsProps) {
  // 각 단계별 취약점 필터링 로직
  const getStageVulnerabilities = (stage: string) => {
    const toolFilters: Record<string, string[]> = {
      iac: ['tfsec', 'Checkov'],
      sast: ['Semgrep', 'SonarQube', 'Bandit', 'ESLint Security'],
      sca: ['Trivy', 'Dep-Check'],
      cross: [], // 교차 검증은 별도 로직 필요
      normalize: [], // 정규화는 별도 로직 필요
      image: ['Trivy'],
      deploy: [], // 배포 단계는 취약점 없음
      dast: ['OWASP ZAP'],
      siem: [], // 모니터링은 취약점 없음
      isms: [], // ISMS는 별도
    };

    const tools = toolFilters[stage] || [];
    return vulnerabilities.filter(v => tools.includes(v.tool));
  };

  // 각 단계별 교차 검증 결과 계산
  const getStageCrossAnalysis = (stage: string) => {
    const toolFilters: Record<string, string[]> = {
      iac: ['tfsec', 'Checkov'],
      sast: ['Semgrep', 'SonarQube', 'Bandit', 'ESLint Security'],
      sca: ['Trivy', 'Dep-Check'],
      cross: [], // 교차 검증 단계는 모든 항목 표시
      normalize: [], // 정규화 단계는 모든 항목 표시
      image: ['Trivy'],
      deploy: [], // 배포 단계는 취약점 없음
      dast: ['OWASP ZAP'],
      siem: [], // 모니터링은 취약점 없음
      isms: [], // ISMS는 별도
    };

    const tools = toolFilters[stage] || [];
    if (tools.length === 0) {
      // cross, normalize 단계는 모든 교차 분석 항목 표시
      return stage === 'cross' || stage === 'normalize' ? crossAnalysisItems : [];
    }

    // 해당 단계의 도구들로 탐지된 교차 분석 항목 필터링
    return crossAnalysisItems.filter(item =>
      item.tools.some(tool => tools.includes(tool))
    );
  };

  const stageVulnerabilities = getStageVulnerabilities(activeSection);

  // 각 심각도별 카운트 계산
  const criticalCount = stageVulnerabilities.filter(v => v.severity === 'CRITICAL').length;
  const highCount = stageVulnerabilities.filter(v => v.severity === 'HIGH').length;
  const mediumCount = stageVulnerabilities.filter(v => v.severity === 'MEDIUM').length;
  const lowCount = stageVulnerabilities.filter(v => v.severity === 'LOW').length;

  const stageCrossAnalysis = getStageCrossAnalysis(activeSection);

  // LLM 판정 결과 계산
  const llmJudgments = stageCrossAnalysis
    .filter(item => item.llmJudgment)
    .map(item => item.llmJudgment!);

  const truePositives = llmJudgments.filter(j => j.judgment === 'TRUE_POSITIVE').length;
  const falsePositives = llmJudgments.filter(j => j.judgment === 'FALSE_POSITIVE').length;
  const uncertain = llmJudgments.filter(j => j.judgment === 'UNCERTAIN').length;

  // LLM 신뢰도 평균 계산
  const avgLLMConfidence = llmJudgments.length > 0
    ? Math.round(llmJudgments.reduce((sum, j) => sum + j.confidence, 0) / llmJudgments.length)
    : 0;

  // ISMS-P 관련 취약점 계산 (임시 로직: HIGH 심각도의 취약점을 ISMS-P 관련으로 가정)
  const ismsRelatedCount = stageVulnerabilities.filter(v => v.severity === 'HIGH').length;
  const ismsCompliance = ismsRelatedCount === 0 ? 100 : Math.max(0, 100 - (ismsRelatedCount * 10));

  const cards = [
    {
      title: 'CRITICAL',
      accent: '#dc2626',
      bg: '#fef2f2',
      icon: <AlertTriangle size={15} className="text-red-700" />,
      delay: 0,
      content: (
        <>
          <div className="text-2xl font-bold font-mono text-red-700">{criticalCount}</div>
          <div className="text-[10px] text-muted-foreground mt-0.5">긴급 조치 필요</div>
        </>
      ),
    },
    {
      title: 'HIGH',
      accent: '#ef4444',
      bg: '#fef2f2',
      icon: <AlertTriangle size={15} className="text-red-600" />,
      delay: 50,
      content: (
        <>
          <div className="text-2xl font-bold font-mono text-red-600">{highCount}</div>
          <div className="text-[10px] text-muted-foreground mt-0.5">즉시 조치 필요</div>
        </>
      ),
    },
    {
      title: 'MEDIUM',
      accent: '#f59e0b',
      bg: '#fffbeb',
      icon: <AlertTriangle size={15} className="text-amber-600" />,
      delay: 100,
      content: (
        <>
          <div className="text-2xl font-bold font-mono text-amber-600">{mediumCount}</div>
          <div className="text-[10px] text-muted-foreground mt-0.5">우선 검토 필요</div>
        </>
      ),
    },
    {
      title: 'LOW',
      accent: '#3b82f6',
      bg: '#eff6ff',
      icon: <AlertTriangle size={15} className="text-blue-600" />,
      delay: 150,
      content: (
        <>
          <div className="text-2xl font-bold font-mono text-blue-600">{lowCount}</div>
          <div className="text-[10px] text-muted-foreground mt-0.5">모니터링 권장</div>
        </>
      ),
    },
    {
      title: 'ISMS-P 연관',
      accent: '#10b981',
      bg: '#ecfdf5',
      icon: <CheckCircle size={15} className="text-emerald-600" />,
      delay: 200,
      content: (
        <>
          <div className="text-2xl font-bold font-mono text-emerald-600">{ismsCompliance.toFixed(0)}%</div>
          <div className="mt-1.5 h-1 bg-emerald-100 rounded-full overflow-hidden">
            <div className="h-full bg-emerald-500 rounded-full" style={{ width: `${ismsCompliance}%` }} />
          </div>
          <div className="text-[10px] text-muted-foreground mt-0.5">{ismsRelatedCount}개 항목</div>
        </>
      ),
    },
  ];

  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
      {cards.map((card) => (
        <div
          key={card.title}
          className="bg-card rounded-lg p-3.5 shadow-sm border border-border animate-fade-in-up"
          style={{
            borderLeft: `3px solid ${card.accent}`,
            animationDelay: `${card.delay}ms`,
            opacity: 0,
            animationFillMode: 'forwards',
          }}
        >
          <div className="flex items-center justify-between mb-2">
            <div className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wider leading-tight">
              {card.title}
            </div>
            <div className="w-6 h-6 rounded flex items-center justify-center flex-shrink-0"
              style={{ backgroundColor: card.bg }}>
              {card.icon}
            </div>
          </div>
          {card.content}
        </div>
      ))}
    </div>
  );
}
