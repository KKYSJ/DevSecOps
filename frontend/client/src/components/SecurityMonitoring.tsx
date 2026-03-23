// DevSecOps Dashboard - Security Monitoring Component
// Design: Clean Governance Dashboard | IBM Plex Sans + IBM Plex Mono

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
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
} from 'recharts';
import { Shield, AlertTriangle, Activity, TrendingUp } from 'lucide-react';
import type {
  SecurityMonitoringSummary,
  ServiceStatus,
  EventItem,
  TrendChartData,
} from '@/lib/types';

interface SecurityMonitoringProps {
  summary: SecurityMonitoringSummary;
  serviceStatuses: ServiceStatus[];
  eventItems: EventItem[];
  trendData: TrendChartData[];
}

export default function SecurityMonitoring({
  summary,
  serviceStatuses,
  eventItems,
  trendData,
}: SecurityMonitoringProps) {
  const getStatusColor = (status: string) => {
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
  };

  const getSeverityColor = (severity: string) => {
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
  };

  const getSeverityDotColor = (severity: string) => {
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
  };

  const getMonitoringBarColor = (status: string) => {
    switch (status) {
      case 'normal':
        return 'bg-green-500';
      case 'warning':
        return 'bg-amber-500';
      default:
        return 'bg-red-500';
    }
  };

  const getMonitoringPercent = (status: string) => {
    switch (status) {
      case 'normal':
        return 90;
      case 'warning':
        return 65;
      default:
        return 35;
    }
  };

  const getServiceHealthPercent = (status: string) => {
    switch (status) {
      case '정상':
        return 90;
      case '경고':
        return 65;
      case '주의':
        return 45;
      default:
        return 50;
    }
  };

  const getServiceHealthBarColor = (status: string) => {
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
  };

  const severityChartData = [
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
  ];

  const recentEvents = eventItems.slice(0, 5);

  return (
    <div className="space-y-6">
      {/* 상단 KPI 카드 */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4">
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <Shield className="w-8 h-8 text-blue-600" />
              <div>
                <div className="text-2xl font-bold">{summary.securityScore}</div>
                <div className="text-sm text-muted-foreground">Security Score</div>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <AlertTriangle className="w-8 h-8 text-red-600" />
              <div>
                <div className="text-2xl font-bold">{summary.activeAlarms}</div>
                <div className="text-sm text-muted-foreground">활성 경보</div>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <Activity className="w-8 h-8 text-orange-600" />
              <div>
                <div className="text-2xl font-bold">{summary.guardDutyFindings}</div>
                <div className="text-sm text-muted-foreground">GuardDuty 탐지</div>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <TrendingUp className="w-8 h-8 text-green-600" />
              <div>
                <div className="text-2xl font-bold">{summary.cloudTrailStatus}</div>
                <div className="text-sm text-muted-foreground">CloudTrail</div>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-full bg-gray-100 flex items-center justify-center">
                <span className="text-sm font-bold">⏰</span>
              </div>
              <div>
                <div className="text-sm font-bold">
                  {summary.recentEventTime.split('T')[1].split('+')[0]}
                </div>
                <div className="text-xs text-muted-foreground">최근 이벤트</div>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div
                className={`w-8 h-8 rounded-full flex items-center justify-center ${summary.monitoringStatus === 'normal'
                    ? 'bg-green-100'
                    : summary.monitoringStatus === 'warning'
                      ? 'bg-amber-100'
                      : 'bg-red-100'
                  }`}
              >
                <span className="text-sm font-bold">
                  {summary.monitoringStatus === 'normal'
                    ? '✓'
                    : summary.monitoringStatus === 'warning'
                      ? '⚠'
                      : '✗'}
                </span>
              </div>
              <div>
                <div className="text-sm font-bold capitalize">{summary.monitoringStatus}</div>
                <div className="text-xs text-muted-foreground">모니터링 상태</div>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* 보안 상태 요약 + 심각도 분포 */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>보안 상태 요약</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex flex-col md:flex-row items-start md:items-center gap-6">
              <div className="relative w-28 h-28 rounded-full border-8 border-blue-100 flex items-center justify-center shrink-0">
                <div className="text-center">
                  <div className="text-3xl font-bold text-blue-600">{summary.securityScore}</div>
                  <div className="text-xs text-muted-foreground">/ 100</div>
                </div>
              </div>

              <div className="flex-1 w-full space-y-4">
                <div>
                  <div className="flex items-center justify-between text-sm mb-1">
                    <span>보안 점수</span>
                    <span className="font-semibold">{summary.securityScore}%</span>
                  </div>
                  <div className="h-2 rounded-full bg-slate-100 overflow-hidden">
                    <div
                      className="h-full bg-blue-600 rounded-full"
                      style={{ width: `${summary.securityScore}%` }}
                    />
                  </div>
                </div>

                <div>
                  <div className="flex items-center justify-between text-sm mb-1">
                    <span>모니터링 안정도</span>
                    <span className="font-semibold capitalize">
                      {summary.monitoringStatus}
                    </span>
                  </div>
                  <div className="h-2 rounded-full bg-slate-100 overflow-hidden">
                    <div
                      className={`h-full rounded-full ${getMonitoringBarColor(
                        summary.monitoringStatus
                      )}`}
                      style={{
                        width: `${getMonitoringPercent(summary.monitoringStatus)}%`,
                      }}
                    />
                  </div>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-1">
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
          const healthPercent = getServiceHealthPercent(service.status);
          const healthBarColor = getServiceHealthBarColor(service.status);

          return (
            <Card key={service.service}>
              <CardHeader className="pb-3">
                <CardTitle className="text-lg">{service.service}</CardTitle>
              </CardHeader>
              <CardContent>
                <Badge className={`mb-3 ${getStatusColor(service.status)}`}>
                  {service.status}
                </Badge>

                <div className="space-y-2 text-sm">
                  {service.service === 'CloudWatch' && (
                    <>
                      <div>알람 개수: {service.details.alarmCount}</div>
                      <div>
                        최근 트리거:{' '}
                        {service.details.recentTrigger.split('T')[1].split('+')[0]}
                      </div>
                    </>
                  )}

                  {service.service === 'GuardDuty' && (
                    <>
                      <div>탐지 건수: {service.details.findingCount}</div>
                      <div>
                        심각도: H:{service.details.severityDistribution.HIGH} M:
                        {service.details.severityDistribution.MEDIUM} L:
                        {service.details.severityDistribution.LOW}
                      </div>
                    </>
                  )}

                  {service.service === 'CloudTrail' && (
                    <>
                      <div>
                        수집 활성화: {service.details.collectionEnabled ? '예' : '아니오'}
                      </div>
                      <div>API 호출 수: {service.details.apiCallCount}</div>
                    </>
                  )}

                  {service.service === 'Security Hub' && (
                    <>
                      <div>보안 점수: {service.details.securityScore}</div>
                      <div>실패 컨트롤: {service.details.failedControls}</div>
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

      {/* 타임라인 + 추세 차트 */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
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
                      className={`w-3 h-3 rounded-full ${getSeverityDotColor(
                        event.severity
                      )}`}
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

        <Card>
          <CardHeader>
            <CardTitle>이벤트 추세 (지난 24시간)</CardTitle>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={260}>
              <LineChart data={trendData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="time" />
                <YAxis />
                <Tooltip />
                <Line type="monotone" dataKey="events" stroke="#3b82f6" strokeWidth={2} />
              </LineChart>
            </ResponsiveContainer>
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
                    <Badge className={getSeverityColor(event.severity)}>
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