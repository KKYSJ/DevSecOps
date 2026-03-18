// DevSecOps Dashboard - Security Monitoring Component
// Design: Clean Governance Dashboard | IBM Plex Sans + IBM Plex Mono

import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar } from 'recharts';
import { Shield, AlertTriangle, Activity, TrendingUp } from 'lucide-react';
import type { SecurityMonitoringSummary, ServiceStatus, EventItem, TrendChartData } from '@/lib/types';

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

  return (
    <div className="space-y-6">
      {/* 상단 요약 카드 */}
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
                <div className="text-sm font-bold">{summary.recentEventTime.split('T')[1].split('+')[0]}</div>
                <div className="text-xs text-muted-foreground">최근 이벤트</div>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className={`w-8 h-8 rounded-full flex items-center justify-center ${
                summary.monitoringStatus === 'normal' ? 'bg-green-100' :
                summary.monitoringStatus === 'warning' ? 'bg-amber-100' : 'bg-red-100'
              }`}>
                <span className="text-sm font-bold">
                  {summary.monitoringStatus === 'normal' ? '✓' :
                   summary.monitoringStatus === 'warning' ? '⚠' : '✗'}
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

      {/* 서비스별 상태 카드 */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {serviceStatuses.map((service) => (
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
                    <div>최근 트리거: {service.details.recentTrigger.split('T')[1].split('+')[0]}</div>
                  </>
                )}
                {service.service === 'GuardDuty' && (
                  <>
                    <div>탐지 건수: {service.details.findingCount}</div>
                    <div>심각도: H:{service.details.severityDistribution.HIGH} M:{service.details.severityDistribution.MEDIUM} L:{service.details.severityDistribution.LOW}</div>
                  </>
                )}
                {service.service === 'CloudTrail' && (
                  <>
                    <div>수집 활성화: {service.details.collectionEnabled ? '예' : '아니오'}</div>
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
            </CardContent>
          </Card>
        ))}
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
                    <Badge variant={event.status === 'Open' ? 'destructive' : 'secondary'}>
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

      {/* 추세 차트 */}
      <Card>
        <CardHeader>
          <CardTitle>이벤트 추세 (지난 24시간)</CardTitle>
        </CardHeader>
        <CardContent>
          <ResponsiveContainer width="100%" height={300}>
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
  );
}