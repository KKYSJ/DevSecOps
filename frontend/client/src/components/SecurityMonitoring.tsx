import React, { useEffect, useMemo, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';
import {
  Shield,
  AlertTriangle,
  Activity,
  TrendingUp,
  RefreshCw,
  Clock3,
} from 'lucide-react';

const MONITORING_API_URL =
  'https://kfaqoo0o1c.execute-api.ap-northeast-2.amazonaws.com/aws/monitoring';

type Summary = {
  activeAlarms: number;
  guardDutyFindings: number;
  securityHubFindings: number;
  cloudTrailStatus: string;
  recentEventTime: string;
};

type ServiceStatusItem = {
  service: string;
  status: string;
  details: Record<string, any>;
};

type EventItem = {
  time: string;
  service: string;
  eventType: string;
  severity: 'HIGH' | 'MEDIUM' | 'LOW' | string;
  resource: string;
  status: string;
  description: string;
};

function formatRecentTime(value?: string) {
  if (!value) return '-';
  if (value.includes('T')) {
    const timePart = value.split('T')[1] ?? '';
    return timePart.split('+')[0]?.replace('Z', '') || value;
  }
  return value;
}

function getSeverityColor(severity: string) {
  switch (severity) {
    case 'HIGH':
      return 'bg-red-50 text-red-700 border-red-200';
    case 'MEDIUM':
      return 'bg-amber-50 text-amber-700 border-amber-200';
    case 'LOW':
      return 'bg-blue-50 text-blue-700 border-blue-200';
    default:
      return 'bg-slate-50 text-slate-600 border-slate-200';
  }
}

function getSeverityDotColor(severity: string) {
  switch (severity) {
    case 'HIGH':
      return 'bg-red-500';
    case 'MEDIUM':
      return 'bg-amber-500';
    case 'LOW':
      return 'bg-blue-500';
    default:
      return 'bg-slate-400';
  }
}

function getServiceStatusColor(status: string) {
  switch (status) {
    case '정상':
      return 'bg-green-50 text-green-700 border-green-200';
    case '경고':
      return 'bg-amber-50 text-amber-700 border-amber-200';
    case '주의':
      return 'bg-blue-50 text-blue-700 border-blue-200';
    default:
      return 'bg-slate-50 text-slate-600 border-slate-200';
  }
}

function getMonitoringStatus(summary: Summary) {
  if (summary.activeAlarms > 0 || summary.guardDutyFindings > 0 || summary.securityHubFindings > 0) {
    return 'warning';
  }
  if (summary.cloudTrailStatus !== 'Enabled') {
    return 'warning';
  }
  return 'normal';
}

function getMonitoringPercent(summary: Summary) {
  let score = 100;

  score -= summary.activeAlarms * 12;
  score -= summary.guardDutyFindings * 10;
  score -= summary.securityHubFindings * 6;
  if (summary.cloudTrailStatus !== 'Enabled') score -= 20;

  return Math.max(15, Math.min(100, score));
}

function getMonitoringBarColor(status: string) {
  switch (status) {
    case 'normal':
      return 'bg-green-500';
    case 'warning':
      return 'bg-amber-500';
    default:
      return 'bg-red-500';
  }
}

function getServiceHealthPercent(service: ServiceStatusItem) {
  if (service.service === 'CloudWatch') {
    const count = service.details?.alarmCount ?? 0;
    return count === 0 ? 92 : Math.max(35, 85 - count * 12);
  }

  if (service.service === 'GuardDuty') {
    const count = service.details?.findingCount ?? 0;
    return count === 0 ? 90 : Math.max(30, 82 - count * 10);
  }

  if (service.service === 'Security Hub') {
    const count = service.details?.failedFindings ?? 0;
    return count === 0 ? 91 : Math.max(35, 84 - count * 8);
  }

  if (service.service === 'CloudTrail') {
    return service.details?.enabled ? 95 : 45;
  }

  return 50;
}

function getServiceHealthBarColor(status: string) {
  switch (status) {
    case '정상':
      return 'bg-green-500';
    case '경고':
      return 'bg-amber-500';
    case '주의':
      return 'bg-blue-500';
    default:
      return 'bg-slate-400';
  }
}

function KpiCard({
  title,
  value,
  description,
  icon,
  accentClass,
}: {
  title: string;
  value: React.ReactNode;
  description: string;
  icon: React.ReactNode;
  accentClass: string;
}) {
  return (
    <Card className="border-border shadow-sm">
      <CardContent className="p-4">
        <div className="flex items-center gap-3">
          <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${accentClass}`}>
            {icon}
          </div>
          <div>
            <div className="text-2xl font-bold text-foreground">{value}</div>
            <div className="text-sm text-muted-foreground">{title}</div>
            <div className="text-[11px] text-muted-foreground mt-0.5">{description}</div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

export default function SecurityMonitoring() {
  const [summary, setSummary] = useState<Summary | null>(null);
  const [serviceStatuses, setServiceStatuses] = useState<ServiceStatusItem[]>([]);
  const [eventItems, setEventItems] = useState<EventItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchMonitoringData = async (isManualRefresh = false) => {
    try {
      if (isManualRefresh) {
        setRefreshing(true);
      } else {
        setLoading(true);
      }

      setError(null);

      const res = await fetch(MONITORING_API_URL);
      if (!res.ok) {
        throw new Error(`모니터링 API 호출 실패: ${res.status}`);
      }

      const data = await res.json();
      const parsed = typeof data.body === 'string' ? JSON.parse(data.body) : data;

      setSummary(parsed.summary ?? null);
      setServiceStatuses(parsed.serviceStatuses ?? []);
      setEventItems(parsed.eventItems ?? []);
    } catch (err) {
      setError(err instanceof Error ? err.message : '알 수 없는 오류');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchMonitoringData();
  }, []);

  const severityChartData = useMemo(
    () => [
      {
        name: 'HIGH',
        count: eventItems.filter((e) => e.severity === 'HIGH').length,
      },
      {
        name: 'MEDIUM',
        count: eventItems.filter((e) => e.severity === 'MEDIUM').length,
      },
      {
        name: 'LOW',
        count: eventItems.filter((e) => e.severity === 'LOW').length,
      },
    ],
    [eventItems]
  );

  const recentEvents = useMemo(() => eventItems.slice(0, 5), [eventItems]);

  if (loading) {
    return (
      <div className="rounded-xl border border-border bg-card p-6 shadow-sm">
        <div className="text-sm text-muted-foreground">모니터링 데이터를 불러오는 중...</div>
      </div>
    );
  }

  if (error || !summary) {
    return (
      <div className="rounded-xl border border-red-200 bg-red-50 p-6 shadow-sm">
        <div className="text-sm font-semibold text-red-700">모니터링 데이터 조회 실패</div>
        <div className="mt-2 text-sm text-red-600">{error ?? 'summary 데이터가 없습니다.'}</div>
        <button
          onClick={() => fetchMonitoringData(true)}
          className="mt-4 inline-flex items-center gap-2 rounded-lg border border-red-200 bg-white px-3.5 py-2 text-sm font-medium text-red-700 hover:bg-red-100 transition-colors"
        >
          다시 시도
        </button>
      </div>
    );
  }

  const monitoringStatus = getMonitoringStatus(summary);
  const monitoringPercent = getMonitoringPercent(summary);

  return (
    <div className="space-y-6">
      {/* 상단 헤더 */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-foreground">보안 모니터링</h2>
          <p className="text-sm text-muted-foreground">
            CloudWatch · GuardDuty · CloudTrail · Security Hub 실데이터 기반 요약
          </p>
        </div>

        <button
          onClick={() => fetchMonitoringData(true)}
          disabled={refreshing}
          className="inline-flex items-center gap-2 rounded-lg border border-blue-200 bg-blue-50 px-3.5 py-2 text-sm font-medium text-blue-700 hover:bg-blue-100 transition-colors disabled:opacity-60 disabled:cursor-not-allowed"
        >
          <RefreshCw size={15} className={refreshing ? 'animate-spin' : ''} />
          {refreshing ? '재조회 중...' : '모니터링 새로고침'}
        </button>
      </div>

      {/* KPI */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4">
        <KpiCard
          title="Security Hub Findings"
          value={summary.securityHubFindings}
          description="미해결 finding 수"
          icon={<Shield className="w-5 h-5 text-blue-700" />}
          accentClass="bg-blue-100"
        />

        <KpiCard
          title="활성 경보"
          value={summary.activeAlarms}
          description="CloudWatch ALARM 상태"
          icon={<AlertTriangle className="w-5 h-5 text-red-700" />}
          accentClass="bg-red-100"
        />

        <KpiCard
          title="GuardDuty 탐지"
          value={summary.guardDutyFindings}
          description="현재 탐지 finding 수"
          icon={<Activity className="w-5 h-5 text-amber-700" />}
          accentClass="bg-amber-100"
        />

        <KpiCard
          title="CloudTrail"
          value={summary.cloudTrailStatus}
          description="감사 로그 활성 상태"
          icon={<TrendingUp className="w-5 h-5 text-green-700" />}
          accentClass="bg-green-100"
        />

        <KpiCard
          title="최근 이벤트"
          value={formatRecentTime(summary.recentEventTime)}
          description="최근 수집 시각"
          icon={<Clock3 className="w-5 h-5 text-slate-700" />}
          accentClass="bg-slate-100"
        />

        <Card className="border-border shadow-sm">
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div
                className={`w-10 h-10 rounded-lg flex items-center justify-center ${monitoringStatus === 'normal'
                  ? 'bg-green-100'
                  : monitoringStatus === 'warning'
                    ? 'bg-amber-100'
                    : 'bg-red-100'
                  }`}
              >
                <span className="text-sm font-bold">
                  {monitoringStatus === 'normal' ? '✓' : monitoringStatus === 'warning' ? '⚠' : '✗'}
                </span>
              </div>
              <div>
                <div className="text-2xl font-bold capitalize">{monitoringStatus}</div>
                <div className="text-sm text-muted-foreground">모니터링 상태</div>
                <div className="text-[11px] text-muted-foreground mt-0.5">
                  실데이터 기반 파생 지표
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* 요약 + 심각도 분포 */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>보안 상태 요약</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex flex-col md:flex-row items-start md:items-center gap-6">
              <div className="relative w-28 h-28 rounded-full border-8 border-blue-100 flex items-center justify-center shrink-0">
                <div className="text-center">
                  <div className="text-3xl font-bold text-blue-600">{monitoringPercent}</div>
                  <div className="text-xs text-muted-foreground">운영 지수</div>
                </div>
              </div>

              <div className="flex-1 w-full space-y-4">
                <div>
                  <div className="flex items-center justify-between text-sm mb-1">
                    <span>모니터링 안정도</span>
                    <span className="font-semibold">{monitoringPercent}%</span>
                  </div>
                  <div className="h-2 rounded-full bg-slate-100 overflow-hidden">
                    <div
                      className={`h-full rounded-full ${getMonitoringBarColor(monitoringStatus)}`}
                      style={{ width: `${monitoringPercent}%` }}
                    />
                  </div>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-4 gap-3 pt-1">
                  <div className="rounded-md bg-slate-50 p-3">
                    <div className="text-xs text-muted-foreground">활성 경보</div>
                    <div className="text-lg font-bold text-red-600">
                      {summary.activeAlarms}
                    </div>
                  </div>
                  <div className="rounded-md bg-slate-50 p-3">
                    <div className="text-xs text-muted-foreground">GuardDuty</div>
                    <div className="text-lg font-bold text-amber-600">
                      {summary.guardDutyFindings}
                    </div>
                  </div>
                  <div className="rounded-md bg-slate-50 p-3">
                    <div className="text-xs text-muted-foreground">Security Hub</div>
                    <div className="text-lg font-bold text-blue-600">
                      {summary.securityHubFindings}
                    </div>
                  </div>
                  <div className="rounded-md bg-slate-50 p-3">
                    <div className="text-xs text-muted-foreground">CloudTrail</div>
                    <div className="text-lg font-bold text-green-600">
                      {summary.cloudTrailStatus}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>심각도 분포</CardTitle>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={240}>
              <BarChart data={severityChartData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="name" />
                <YAxis allowDecimals={false} />
                <Tooltip />
                <Bar dataKey="count" radius={[6, 6, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      </div>

      {/* 서비스별 상태 카드 */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {serviceStatuses.map((service) => {
          const healthPercent = getServiceHealthPercent(service);
          const healthBarColor = getServiceHealthBarColor(service.status);

          return (
            <Card key={service.service}>
              <CardHeader className="pb-3">
                <CardTitle className="text-lg">{service.service}</CardTitle>
              </CardHeader>
              <CardContent>
                <Badge className={`mb-3 border ${getServiceStatusColor(service.status)}`}>
                  {service.status}
                </Badge>

                <div className="space-y-2 text-sm">
                  {service.service === 'CloudWatch' && (
                    <>
                      <div>알람 개수: {service.details.alarmCount}</div>
                    </>
                  )}

                  {service.service === 'GuardDuty' && (
                    <>
                      <div>탐지 건수: {service.details.findingCount}</div>
                    </>
                  )}

                  {service.service === 'CloudTrail' && (
                    <>
                      <div>
                        수집 활성화: {service.details.enabled ? '예' : '아니오'}
                      </div>
                    </>
                  )}

                  {service.service === 'Security Hub' && (
                    <>
                      <div>미해결 Findings: {service.details.failedFindings}</div>
                    </>
                  )}
                </div>

                <div className="mt-4">
                  <div className="flex items-center justify-between text-xs mb-1">
                    <span className="text-muted-foreground">상태 지수</span>
                    <span className="font-medium">{healthPercent}%</span>
                  </div>
                  <div className="h-2 rounded-full bg-slate-100 overflow-hidden">
                    <div
                      className={`h-full rounded-full ${healthBarColor}`}
                      style={{ width: `${healthPercent}%` }}
                    />
                  </div>
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>

      {/* 최근 이벤트 타임라인 */}
      <div className="grid grid-cols-1 gap-4">
        <Card>
          <CardHeader>
            <CardTitle>최근 이벤트 타임라인</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {recentEvents.map((event, index) => (
                <div key={index} className="flex gap-3">
                  <div className="flex flex-col items-center">
                    <div
                      className={`w-3 h-3 rounded-full ${getSeverityDotColor(event.severity)}`}
                    />
                    {index !== recentEvents.length - 1 && (
                      <div className="w-px flex-1 bg-border mt-1 min-h-[24px]" />
                    )}
                  </div>

                  <div className="pb-2">
                    <div className="text-sm font-medium">{event.eventType}</div>
                    <div className="text-xs text-muted-foreground">
                      {event.time} · {event.service} · {event.resource}
                    </div>
                    <div className="text-sm mt-1">{event.description}</div>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* 이벤트/경보 테이블 */}
      <Card>
        <CardHeader>
          <CardTitle>이벤트 및 경보</CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>시간</TableHead>
                <TableHead>서비스</TableHead>
                <TableHead>이벤트 유형</TableHead>
                <TableHead>심각도</TableHead>
                <TableHead>리소스</TableHead>
                <TableHead>상태</TableHead>
                <TableHead>설명</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {eventItems.map((event, index) => (
                <TableRow key={index}>
                  <TableCell className="font-mono">{event.time}</TableCell>
                  <TableCell>{event.service}</TableCell>
                  <TableCell>{event.eventType}</TableCell>
                  <TableCell>
                    <Badge className={`border ${getSeverityColor(event.severity)}`}>
                      {event.severity}
                    </Badge>
                  </TableCell>
                  <TableCell className="font-mono text-xs">{event.resource}</TableCell>
                  <TableCell>
                    <Badge
                      variant={event.status === 'Open' ? 'destructive' : 'secondary'}
                    >
                      {event.status}
                    </Badge>
                  </TableCell>
                  <TableCell>{event.description}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}