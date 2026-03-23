// DevSecOps Dashboard - Type Definitions
// Design: Clean Governance Dashboard | IBM Plex Sans + IBM Plex Mono

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type PipelineStatus = 'idle' | 'running' | 'success' | 'failed';
export type ScanType = 'security' | 'cross-analysis' | 'isms-p' | 'refresh';

export interface ScanState {
  isRefreshing: boolean;
  isSecurityScanning: boolean;
  isCrossAnalyzing: boolean;
  isIsmpChecking: boolean;
  currentScanType: ScanType | null;
  progress: number;
  stage: string;
}

export type Confidence = 'HIGH' | 'MEDIUM' | 'LOW';

export interface Vulnerability {
  id: string;
  severity: Severity;
  category: string;
  tool: string;
  file: string;
  line: number;
  cwe: string;
  description: string;
  confidence: Confidence;
  detectedAt: string;
}

export interface CrossAnalysisItem {
  id: string;
  severity: Severity;
  category: string;
  tools: string[];
  file: string;
  line: number;
  cwe: string;
  description: string;
  confidence: Confidence;
  detectionCount: number;
  llmJudgment?: LLMJudgment;
}

export interface LLMJudgment {
  id: string;
  vulnerabilityId: string;
  judgment: 'TRUE_POSITIVE' | 'FALSE_POSITIVE' | 'UNCERTAIN';
  confidence: number; // 0-100
  reasoning: string;
  recommendedAction: string;
  riskAssessment: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  judgedAt: string;
}

export interface IsmpItem {
  id: string;
  controlId: string;
  domain: string;
  requirement: string;
  status: 'PASS' | 'FAIL' | 'PARTIAL' | 'N/A';
  evidence: string;
  lastChecked: string;
}

export interface ScanSummary {
  lastScanTime: string;
  totalVulnerabilities: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
  crossVerifiedHighCount: number;
  ismsPCompliance: number;
  pipelineStatus: PipelineStatus;
  pipelineStage?: string;
  pipelineProgress?: number;
}

export interface Deployment {
  id: string;
  name: string;
  version: string;
  environment: 'prod' | 'staging' | 'dev';
  status: 'success' | 'failed' | 'pending';
  deployedAt: string;
  scanSummary: ScanSummary;
  vulnerabilityCount: number;
  ismsPCompliance: number;
  pipelineProgress: number;
}

export interface SeverityChartData {
  name: string;
  value: number;
  color: string;
}

export interface ToolChartData {
  tool: string;
  HIGH: number;
  MEDIUM: number;
  LOW: number;
  INFO: number;
}

export interface CategoryChartData {
  name: string;
  value: number;
  color: string;
}

export interface SecurityMonitoringSummary {
  securityScore: number;
  activeAlarms: number;
  guardDutyFindings: number;
  cloudTrailStatus: string;
  recentEventTime: string;
  monitoringStatus: 'normal' | 'warning' | 'critical';
}

export interface ServiceStatus {
  service: string;
  status: string;
  details: Record<string, any>;
}

export interface EventItem {
  time: string;
  service: string;
  eventType: string;
  severity: Severity;
  resource: string;
  status: 'Open' | 'Resolved';
  description: string;
}

export interface TrendChartData {
  time: string;
  events: number;
}
