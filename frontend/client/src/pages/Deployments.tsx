// DevSecOps Dashboard - Deployments List Page
// API 연동: GET /api/v1/pipelines + GET /api/v1/cross

import { useState, useEffect } from 'react';
import { useLocation } from 'wouter';
import { CheckCircle, AlertCircle, Clock, Server, XCircle, Loader2 } from 'lucide-react';
import { fetchJson } from '@/lib/api';

interface PipelineRun {
  id: number;
  project_name: string;
  commit_hash: string;
  branch: string;
  status: string; // scanning_phase1 | scanning_phase2 | completed | blocked
  gate_result: string | null; // BLOCK | REVIEW | ALLOW
  gate_score: number | null;
  scan_ids: number[] | null;
  created_at: string;
}

interface CrossReport {
  gate_decision: string;
  total_score: number;
  summary: {
    total_findings: number;
    true_positive: number;
    review_needed: number;
    false_positive: number;
    by_severity: Record<string, number>;
    phase: number;
  };
  commit_hash: string;
  project_name?: string;
  generated_at?: string;
}

export default function Deployments() {
  const [, setLocation] = useLocation();
  const [pipelines, setPipelines] = useState<PipelineRun[]>([]);
  const [crossReport, setCrossReport] = useState<CrossReport | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([
      fetchJson<{ pipelines: PipelineRun[] }>('/pipelines').catch(() => ({ pipelines: [] })),
      fetchJson<CrossReport>('/cross').catch(() => null),
      fetchJson<{ scans: Array<{ branch: string }> }>('/scans?limit=1').catch(() => ({ scans: [] })),
    ]).then(([pRes, cRes, sRes]) => {
      const latestBranch = sRes.scans?.[0]?.branch || 'main';
      let pipelineList = pRes.pipelines || [];
      setCrossReport(cRes);

      // pipelines가 비어있지만 cross report가 있으면 가상 파이프라인 생성
      if (pipelineList.length === 0 && cRes && cRes.gate_decision) {
        pipelineList = [{
          id: 0,
          project_name: cRes.project_name || 'secureflow',
          commit_hash: cRes.commit_hash || '',
          branch: latestBranch,
          status: cRes.gate_decision === 'BLOCK' ? 'blocked' : 'completed',
          gate_result: cRes.gate_decision,
          gate_score: cRes.total_score,
          scan_ids: null,
          created_at: cRes.generated_at || new Date().toISOString(),
        }];
      }
      setPipelines(pipelineList);
    }).finally(() => setLoading(false));
  }, []);

  const getStatusIcon = (status: string, gate: string | null) => {
    if (status === 'blocked' || gate === 'BLOCK')
      return <XCircle size={18} className="text-red-600" />;
    if (status === 'completed' && gate === 'ALLOW')
      return <CheckCircle size={18} className="text-green-600" />;
    if (status === 'completed' && gate === 'REVIEW')
      return <AlertCircle size={18} className="text-amber-600" />;
    if (status.startsWith('scanning'))
      return <Clock size={18} className="text-blue-600" />;
    return <CheckCircle size={18} className="text-green-600" />;
  };

  const getStatusLabel = (status: string, gate: string | null) => {
    if (status === 'blocked') return '차단됨';
    if (status === 'completed' && gate === 'ALLOW') return '배포 허용';
    if (status === 'completed' && gate === 'REVIEW') return '검토 필요';
    if (status === 'completed' && gate === 'BLOCK') return '차단됨';
    if (status === 'scanning_phase1') return 'Phase 1 스캔 중';
    if (status === 'scanning_phase2') return 'Phase 2 스캔 중';
    return status;
  };

  const getGateColor = (gate: string | null) => {
    switch (gate) {
      case 'BLOCK': return 'bg-red-50 text-red-700 border-red-200';
      case 'REVIEW': return 'bg-amber-50 text-amber-700 border-amber-200';
      case 'ALLOW': return 'bg-green-50 text-green-700 border-green-200';
      default: return 'bg-gray-50 text-gray-700 border-gray-200';
    }
  };

  const getPhaseProgress = (status: string) => {
    switch (status) {
      case 'scanning_phase1': return 30;
      case 'scanning_phase2': return 70;
      case 'completed': return 100;
      case 'blocked': return 100;
      default: return 0;
    }
  };

  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    return date.toLocaleDateString('ko-KR', {
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  // cross report에서 해당 파이프라인의 취약점 수 가져오기
  const getVulnCount = (pipeline: PipelineRun) => {
    if (crossReport && crossReport.commit_hash === pipeline.commit_hash) {
      return crossReport.summary?.total_findings || 0;
    }
    return 0;
  };

  const getHighCount = (pipeline: PipelineRun) => {
    if (crossReport && crossReport.commit_hash === pipeline.commit_hash) {
      const sev = crossReport.summary?.by_severity || {};
      return (sev.CRITICAL || 0) + (sev.HIGH || 0);
    }
    return 0;
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <Loader2 className="animate-spin text-muted-foreground" size={32} />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <div className="border-b border-border bg-card sticky top-0 z-10">
        <div className="max-w-7xl mx-auto px-6 py-4">
          <div className="flex items-center gap-3 mb-2">
            <Server size={32} className="text-foreground" />
            <div>
              <h1 className="text-2xl font-bold text-foreground">배포 결과</h1>
              <p className="text-sm text-muted-foreground">파이프라인 실행 이력 및 게이트 결정</p>
            </div>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="max-w-7xl mx-auto px-6 py-8">
        {pipelines.length === 0 ? (
          <div className="text-center py-20 text-muted-foreground">
            <Server size={48} className="mx-auto mb-4 opacity-50" />
            <p className="text-lg">파이프라인 실행 이력이 없습니다</p>
            <p className="text-sm mt-2">코드를 푸시하면 CI/CD 파이프라인이 실행됩니다</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {pipelines.map((pipeline) => (
              <div
                key={pipeline.id}
                onClick={() => setLocation(`/deployment/${pipeline.id}`)}
                className="bg-card border border-border rounded-lg p-5 hover:shadow-md transition-all cursor-pointer hover:border-primary/50"
              >
                <div className="flex items-start justify-between mb-4">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-2">
                      <h3 className="text-lg font-semibold text-foreground">
                        {pipeline.project_name}
                      </h3>
                      <div className="flex items-center gap-1">
                        {getStatusIcon(pipeline.status, pipeline.gate_result)}
                        <span className="text-xs font-medium text-muted-foreground">
                          {getStatusLabel(pipeline.status, pipeline.gate_result)}
                        </span>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <code className="text-sm bg-muted px-2 py-1 rounded text-foreground">
                        {pipeline.commit_hash?.slice(0, 8)}
                      </code>
                      <span className="text-xs bg-blue-50 text-blue-700 border border-blue-200 px-2.5 py-1.5 rounded font-medium">
                        {pipeline.branch || 'main'}
                      </span>
                      {pipeline.gate_result && (
                        <span className={`text-xs font-medium px-2.5 py-1.5 rounded border ${getGateColor(pipeline.gate_result)}`}>
                          {pipeline.gate_result}
                        </span>
                      )}
                    </div>
                  </div>
                </div>

                <div className="text-xs text-muted-foreground mb-4">
                  실행일: {formatDate(pipeline.created_at)}
                </div>

                {/* Metrics Grid */}
                <div className="grid grid-cols-3 gap-3 mb-4">
                  <div className="bg-muted rounded-md p-3">
                    <div className="text-2xl font-bold text-red-600">
                      {getVulnCount(pipeline)}
                    </div>
                    <div className="text-xs text-muted-foreground mt-1">취약점</div>
                  </div>
                  <div className="bg-muted rounded-md p-3">
                    <div className="text-2xl font-bold text-amber-600">
                      {getHighCount(pipeline)}
                    </div>
                    <div className="text-xs text-muted-foreground mt-1">Critical+High</div>
                  </div>
                  <div className="bg-muted rounded-md p-3">
                    <div className="text-2xl font-bold text-blue-600">
                      {pipeline.gate_score?.toFixed(1) || '0'}
                    </div>
                    <div className="text-xs text-muted-foreground mt-1">위험 점수</div>
                  </div>
                </div>

                {/* Pipeline Status Bar */}
                <div className="border-t border-border pt-3">
                  <div className="flex items-center justify-between">
                    <div className="text-xs text-muted-foreground">
                      {pipeline.status === 'completed' ? '파이프라인 완료' :
                       pipeline.status === 'blocked' ? '파이프라인 차단' :
                       pipeline.status === 'scanning_phase1' ? 'Phase 1 진행 중' :
                       'Phase 2 진행 중'}
                    </div>
                    <div className="w-32 bg-muted rounded-full h-2 overflow-hidden">
                      <div
                        className={`h-full rounded-full transition-all ${
                          pipeline.status === 'blocked' ? 'bg-red-600' :
                          pipeline.status === 'completed' && pipeline.gate_result === 'ALLOW' ? 'bg-green-600' :
                          pipeline.status === 'completed' ? 'bg-amber-600' :
                          'bg-blue-600'
                        }`}
                        style={{ width: `${getPhaseProgress(pipeline.status)}%` }}
                      />
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
