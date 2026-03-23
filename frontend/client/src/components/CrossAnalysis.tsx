// DevSecOps Dashboard - CrossAnalysis Component
// Design: Clean Governance Dashboard | Multi-tool detection cross-reference

import { GitMerge, AlertTriangle, Zap } from 'lucide-react';
import type { CrossAnalysisItem } from '@/lib/types';
import SeverityBadge from './SeverityBadge';

interface CrossAnalysisProps {
  items: CrossAnalysisItem[];
}

function ToolBadge({ tool }: { tool: string }) {
  const colors: Record<string, string> = {
    'Semgrep': 'bg-purple-50 text-purple-700 border-purple-200',
    'Bandit': 'bg-orange-50 text-orange-700 border-orange-200',
    'Gitleaks': 'bg-pink-50 text-pink-700 border-pink-200',
    'ESLint Security': 'bg-blue-50 text-blue-700 border-blue-200',
    'Trivy': 'bg-teal-50 text-teal-700 border-teal-200',
  };
  const cls = colors[tool] || 'bg-slate-50 text-slate-700 border-slate-200';
  return (
    <span className={`inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium border ${cls}`}>
      {tool}
    </span>
  );
}

export default function CrossAnalysis({ items }: CrossAnalysisProps) {
  const highConfidenceItems = items.filter(i => i.confidence === 'HIGH');
  const tripleDetected = items.filter(i => i.detectionCount >= 3);

  return (
    <div className="bg-card rounded-lg border border-border shadow-sm animate-fade-in-up"
      style={{ animationDelay: '650ms', opacity: 0, animationFillMode: 'forwards' }}>
      {/* Header */}
      <div className="p-4 border-b border-border">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="w-7 h-7 rounded-md bg-rose-50 flex items-center justify-center">
              <GitMerge size={14} className="text-rose-600" />
            </div>
            <div>
              <h3 className="text-sm font-semibold text-foreground">교차 분석 결과</h3>
              <p className="text-xs text-muted-foreground">복수 도구에서 동시 탐지된 취약점</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <div className="flex items-center gap-1.5 px-2.5 py-1 bg-red-50 rounded-md border border-red-200">
              <AlertTriangle size={12} className="text-red-600" />
              <span className="text-xs font-semibold text-red-700 font-mono">
                HIGH Confidence: {highConfidenceItems.length}건
              </span>
            </div>
            {tripleDetected.length > 0 && (
              <div className="flex items-center gap-1.5 px-2.5 py-1 bg-rose-50 rounded-md border border-rose-200">
                <Zap size={12} className="text-rose-600" />
                <span className="text-xs font-semibold text-rose-700 font-mono">
                  3중 탐지: {tripleDetected.length}건
                </span>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Items */}
      <div className="divide-y divide-border">
        {items.map((item) => {
          const isHighConfidence = item.confidence === 'HIGH';
          const isTriple = item.detectionCount >= 3;

          return (
            <div
              key={item.id}
              className={`p-4 transition-colors hover:bg-muted/20 ${
                isTriple ? 'bg-rose-50/30' : isHighConfidence ? 'bg-red-50/20' : ''
              }`}
              style={{
                borderLeft: `3px solid ${
                  item.severity === 'HIGH' ? '#ef4444' :
                  item.severity === 'MEDIUM' ? '#f59e0b' : '#3b82f6'
                }`,
              }}
            >
              <div className="flex items-start gap-3">
                {/* Detection count badge */}
                <div className={`flex-shrink-0 w-8 h-8 rounded-lg flex items-center justify-center text-xs font-bold font-mono ${
                  isTriple
                    ? 'bg-rose-100 text-rose-700 border border-rose-300'
                    : 'bg-red-50 text-red-600 border border-red-200'
                }`}>
                  {item.detectionCount}x
                </div>

                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap mb-1.5">
                    <SeverityBadge severity={item.severity} />
                    <span className="text-sm font-semibold text-foreground">{item.category}</span>
                    {isHighConfidence && (
                      <span className="inline-flex items-center gap-1 px-1.5 py-0.5 bg-red-100 text-red-700 text-[10px] font-semibold rounded border border-red-200">
                        <Zap size={9} />
                        HIGH CONFIDENCE
                      </span>
                    )}
                    {isTriple && (
                      <span className="inline-flex items-center gap-1 px-1.5 py-0.5 bg-rose-100 text-rose-700 text-[10px] font-semibold rounded border border-rose-200">
                        3중 탐지
                      </span>
                    )}
                  </div>

                  <p className="text-xs text-muted-foreground mb-2 leading-relaxed">{item.description}</p>

                  <div className="flex items-center gap-3 flex-wrap">
                    {/* Tools */}
                    <div className="flex items-center gap-1 flex-wrap">
                      {item.tools.map((tool) => (
                        <ToolBadge key={tool} tool={tool} />
                      ))}
                    </div>

                    {/* File info */}
                    <div className="flex items-center gap-1 text-[10px] text-muted-foreground font-mono">
                      <span className="truncate max-w-[200px]">{item.file}</span>
                      <span>:{item.line}</span>
                    </div>

                    {/* CWE */}
                    <span className="text-[10px] font-mono text-blue-600">{item.cwe}</span>
                  </div>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Summary footer */}
      <div className="px-4 py-3 border-t border-border bg-muted/20">
        <div className="flex items-center gap-4 text-xs text-muted-foreground">
          <span>총 <span className="font-mono font-semibold text-foreground">{items.length}</span>건의 교차 탐지 취약점</span>
          <span>·</span>
          <span>HIGH Confidence <span className="font-mono font-semibold text-red-600">{highConfidenceItems.length}</span>건 즉시 조치 권고</span>
        </div>
      </div>
    </div>
  );
}
