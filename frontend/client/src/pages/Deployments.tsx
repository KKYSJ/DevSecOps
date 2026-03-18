// DevSecOps Dashboard - Deployments List Page
// Design: Clean Governance Dashboard | Grid view of all deployments

import { useLocation } from 'wouter';
import { CheckCircle, AlertCircle, Clock, Server, TrendingDown, Shield } from 'lucide-react';
import { mockDeployments } from '@/lib/mockData';
import type { Deployment } from '@/lib/types';

export default function Deployments() {
  const [, setLocation] = useLocation();

  const handleDeploymentClick = (deploymentId: string) => {
    setLocation(`/deployment/${deploymentId}`);
  };

  const getStatusIcon = (status: Deployment['status']) => {
    switch (status) {
      case 'success':
        return <CheckCircle size={18} className="text-green-600" />;
      case 'failed':
        return <AlertCircle size={18} className="text-red-600" />;
      case 'pending':
        return <Clock size={18} className="text-amber-600" />;
      default:
        return null;
    }
  };

  const getStatusLabel = (status: Deployment['status']) => {
    switch (status) {
      case 'success':
        return '성공';
      case 'failed':
        return '실패';
      case 'pending':
        return '진행중';
      default:
        return '알수없음';
    }
  };

  const getEnvironmentColor = (env: Deployment['environment']) => {
    switch (env) {
      case 'prod':
        return 'bg-red-50 text-red-700 border-red-200';
      case 'staging':
        return 'bg-amber-50 text-amber-700 border-amber-200';
      case 'dev':
        return 'bg-blue-50 text-blue-700 border-blue-200';
      default:
        return 'bg-gray-50 text-gray-700 border-gray-200';
    }
  };

  const getEnvironmentLabel = (env: Deployment['environment']) => {
    switch (env) {
      case 'prod':
        return 'Production';
      case 'staging':
        return 'Staging';
      case 'dev':
        return 'Development';
      default:
        return 'Unknown';
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

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <div className="border-b border-border bg-card sticky top-0 z-10">
        <div className="max-w-7xl mx-auto px-6 py-6">
          <div className="flex items-center gap-3 mb-2">
            <Server size={32} className="text-foreground" />
            <div>
              <h1 className="text-2xl font-bold text-foreground">배포 결과</h1>
              <p className="text-sm text-muted-foreground">스캔 및 보안 분석 이력 조회</p>
            </div>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="max-w-7xl mx-auto px-6 py-8">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-1 gap-4">
          {mockDeployments.map((deployment) => (
            <div
              key={deployment.id}
              onClick={() => handleDeploymentClick(deployment.id)}
              className="bg-card border border-border rounded-lg p-5 hover:shadow-md transition-all cursor-pointer hover:border-primary/50"
            >
              <div className="flex items-start justify-between mb-4">
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-2">
                    <h3 className="text-lg font-semibold text-foreground">{deployment.name}</h3>
                    <div className="flex items-center gap-1">
                      {getStatusIcon(deployment.status)}
                      <span className="text-xs font-medium text-muted-foreground">
                        {getStatusLabel(deployment.status)}
                      </span>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <code className="text-sm bg-muted px-2 py-1 rounded text-foreground">
                      v{deployment.version}
                    </code>
                    <span
                      className={`text-xs font-medium px-2.5 py-1.5 rounded border ${getEnvironmentColor(deployment.environment)}`}
                    >
                      {getEnvironmentLabel(deployment.environment)}
                    </span>
                  </div>
                </div>
              </div>

              <div className="text-xs text-muted-foreground mb-4">
                배포일: {formatDate(deployment.deployedAt)}
              </div>

              {/* Metrics Grid */}
              <div className="grid grid-cols-4 gap-3 mb-4">
                {/* Vulnerabilities */}
                <div className="bg-muted rounded-md p-3">
                  <div className="text-2xl font-bold text-red-600">{deployment.vulnerabilityCount}</div>
                  <div className="text-xs text-muted-foreground mt-1">취약점</div>
                </div>

                {/* High Severity */}
                <div className="bg-muted rounded-md p-3">
                  <div className="text-2xl font-bold text-amber-600">
                    {deployment.scanSummary.highCount}
                  </div>
                  <div className="text-xs text-muted-foreground mt-1">High</div>
                </div>

                {/* ISMS-P Compliance */}
                <div className="bg-muted rounded-md p-3">
                  <div className="text-2xl font-bold text-green-600">
                    {deployment.ismsPCompliance.toFixed(1)}%
                  </div>
                  <div className="text-xs text-muted-foreground mt-1">ISMS-P</div>
                </div>

                {/* Pipeline Progress */}
                <div className="bg-muted rounded-md p-3">
                  <div className="text-2xl font-bold text-blue-600">
                    {deployment.pipelineProgress}%
                  </div>
                  <div className="text-xs text-muted-foreground mt-1">진행률</div>
                </div>
              </div>

              {/* Pipeline Status */}
              <div className="border-t border-border pt-3">
                <div className="flex items-center justify-between">
                  <div className="text-xs text-muted-foreground">
                    마지막 상태: {deployment.scanSummary.pipelineStage}
                  </div>
                  <div className="w-32 bg-muted rounded-full h-2 overflow-hidden">
                    <div
                      className={`h-full rounded-full transition-all ${
                        deployment.status === 'success'
                          ? 'bg-green-600'
                          : deployment.status === 'failed'
                            ? 'bg-red-600'
                            : 'bg-amber-600'
                      }`}
                      style={{ width: `${deployment.pipelineProgress}%` }}
                    />
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
