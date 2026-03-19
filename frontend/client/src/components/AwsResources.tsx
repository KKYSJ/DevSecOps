import React, { useMemo } from 'react';
import {
    RefreshCw,
    Server,
    Database,
    Box,
    FunctionSquare,
    ShieldAlert,
    ShieldCheck,
    AlertTriangle,
    Search,
} from 'lucide-react';

type ResourceStatus = '정상' | '경고' | '위험';
type ResourceType = 'ECS SERVICE' | 'RDS INSTANCE' | 'LAMBDA' | 'S3 BUCKET' | 'ALB';

type Resource = {
    id: string;
    name: string;
    type: ResourceType;
    region: string;
    accountId: string;
    status: ResourceStatus;
    critical: number;
    high: number;
    medium: number;
    checks: number;
    passed: number;
    failed: number;
    score: number;
};

const mockResources: Resource[] = [
    {
        id: '1',
        name: 'my-api-service',
        type: 'ECS SERVICE',
        region: 'ap-northeast-2a',
        accountId: '123456789012',
        status: '경고',
        critical: 0,
        high: 1,
        medium: 3,
        checks: 38,
        passed: 30,
        failed: 8,
        score: 78,
    },
    {
        id: '2',
        name: 'my-frontend-service',
        type: 'ECS SERVICE',
        region: 'ap-northeast-2a',
        accountId: '123456789012',
        status: '정상',
        critical: 0,
        high: 0,
        medium: 1,
        checks: 38,
        passed: 35,
        failed: 3,
        score: 91,
    },
    {
        id: '3',
        name: 'my-db-postgres',
        type: 'RDS INSTANCE',
        region: 'ap-northeast-2b',
        accountId: '123456789012',
        status: '정상',
        critical: 0,
        high: 0,
        medium: 0,
        checks: 38,
        passed: 36,
        failed: 2,
        score: 95,
    },
    {
        id: '4',
        name: 'my-auth-handler',
        type: 'LAMBDA',
        region: 'ap-northeast-2',
        accountId: '123456789012',
        status: '위험',
        critical: 1,
        high: 2,
        medium: 4,
        checks: 38,
        passed: 24,
        failed: 14,
        score: 62,
    },
    {
        id: '5',
        name: 'my-devsecops-logs',
        type: 'S3 BUCKET',
        region: 'ap-northeast-2',
        accountId: '123456789012',
        status: '정상',
        critical: 0,
        high: 0,
        medium: 1,
        checks: 38,
        passed: 33,
        failed: 5,
        score: 88,
    },
    {
        id: '6',
        name: 'my-alb-public',
        type: 'ALB',
        region: 'ap-northeast-2',
        accountId: '123456789012',
        status: '경고',
        critical: 0,
        high: 1,
        medium: 2,
        checks: 38,
        passed: 29,
        failed: 9,
        score: 75,
    },
];

function getStatusConfig(status: ResourceStatus) {
    if (status === '정상') {
        return {
            badge: 'bg-emerald-50 text-emerald-700 border-emerald-200',
            border: 'border-l-4 border-l-emerald-500',
            label: '정상',
        };
    }

    if (status === '경고') {
        return {
            badge: 'bg-amber-50 text-amber-700 border-amber-200',
            border: 'border-l-4 border-l-amber-500',
            label: '경고',
        };
    }

    return {
        badge: 'bg-red-50 text-red-700 border-red-200',
        border: 'border-l-4 border-l-red-500',
        label: '위험',
    };
}

function getTypeIcon(type: ResourceType) {
    const className = 'text-slate-500';
    switch (type) {
        case 'ECS SERVICE':
            return <Server size={16} className={className} />;
        case 'RDS INSTANCE':
            return <Database size={16} className={className} />;
        case 'LAMBDA':
            return <FunctionSquare size={16} className={className} />;
        case 'S3 BUCKET':
            return <Box size={16} className={className} />;
        case 'ALB':
            return <Search size={16} className={className} />;
        default:
            return <Server size={16} className={className} />;
    }
}

function ScoreBar({ score }: { score: number }) {
    return (
        <div className="flex items-center gap-3">
            <div className="flex-1 h-2 rounded-full bg-slate-100 overflow-hidden">
                <div
                    className="h-full rounded-full bg-violet-500 transition-all duration-500"
                    style={{ width: `${score}%` }}
                />
            </div>
            <div className="min-w-[72px] text-right text-sm font-semibold text-violet-600">
                ISMS-P {score}%
            </div>
        </div>
    );
}

function SeverityMetric({
    label,
    value,
    valueClassName,
}: {
    label: string;
    value: number;
    valueClassName: string;
}) {
    return (
        <div>
            <div className={`text-xl font-bold font-mono ${valueClassName}`}>{value}</div>
            <div className="mt-0.5 text-[10px] tracking-wide text-muted-foreground uppercase">{label}</div>
        </div>
    );
}

function SummaryCard({
    title,
    value,
    sub,
    icon,
}: {
    title: string;
    value: string;
    sub: string;
    icon: React.ReactNode;
}) {
    return (
        <div className="rounded-xl border border-border bg-card p-4 shadow-sm">
            <div className="flex items-start justify-between gap-3">
                <div>
                    <div className="text-xs font-medium text-muted-foreground">{title}</div>
                    <div className="mt-2 text-2xl font-bold text-foreground">{value}</div>
                    <div className="mt-1 text-xs text-muted-foreground">{sub}</div>
                </div>
                <div className="rounded-lg bg-slate-50 p-2 border border-slate-200">{icon}</div>
            </div>
        </div>
    );
}

function ResourceCard({ resource }: { resource: Resource }) {
    const status = getStatusConfig(resource.status);

    return (
        <div className={`rounded-xl border border-border bg-card p-5 shadow-sm ${status.border}`}>
            <div className="flex items-start justify-between gap-4">
                <div className="min-w-0">
                    <div className="flex items-center gap-2 text-[11px] tracking-wider text-muted-foreground uppercase">
                        {getTypeIcon(resource.type)}
                        <span>{resource.type}</span>
                    </div>
                    <div className="mt-2 text-2xl font-bold text-foreground break-all">{resource.name}</div>
                    <div className="mt-1 text-sm text-muted-foreground">{resource.region}</div>
                </div>

                <span className={`shrink-0 inline-flex rounded-md border px-3 py-1 text-xs font-semibold ${status.badge}`}>
                    {status.label}
                </span>
            </div>

            <div className="mt-5 border-t border-border pt-4">
                <div className="grid grid-cols-3 gap-6">
                    <SeverityMetric label="CRITICAL" value={resource.critical} valueClassName="text-red-500" />
                    <SeverityMetric label="HIGH" value={resource.high} valueClassName="text-orange-500" />
                    <SeverityMetric label="MEDIUM" value={resource.medium} valueClassName="text-blue-500" />
                </div>
            </div>

            <div className="mt-5">
                <ScoreBar score={resource.score} />
            </div>
        </div>
    );
}

export default function AwsResources() {
    const summary = useMemo(() => {
        const total = mockResources.length;
        const healthy = mockResources.filter((r) => r.status === '정상').length;
        const warning = mockResources.filter((r) => r.status === '경고').length;
        const danger = mockResources.filter((r) => r.status === '위험').length;
        const avgScore = Math.round(
            mockResources.reduce((sum, r) => sum + r.score, 0) / mockResources.length
        );
        const totalCritical = mockResources.reduce((sum, r) => sum + r.critical, 0);
        const totalHigh = mockResources.reduce((sum, r) => sum + r.high, 0);
        const totalMedium = mockResources.reduce((sum, r) => sum + r.medium, 0);

        return {
            total,
            healthy,
            warning,
            danger,
            avgScore,
            totalCritical,
            totalHigh,
            totalMedium,
        };
    }, []);

    return (
        <div className="space-y-6">
            {/* Header */}
            <div className="rounded-xl border border-border bg-card p-5 shadow-sm">
                <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
                    <div>
                        <h2 className="text-2xl font-bold text-foreground">AWS 리소스 현황</h2>
                        <p className="mt-1 text-sm text-muted-foreground">
                            계정 내 배포 서비스 자동 감지 · boto3 API 수집
                        </p>
                    </div>

                    <div className="flex items-center gap-3">
                        <div className="rounded-lg border border-border bg-slate-50 px-3 py-2 text-sm text-slate-600">
                            Account: <span className="font-semibold text-foreground">123456789012</span>
                            <span className="mx-2 text-slate-300">·</span>
                            ap-northeast-2
                        </div>

                        <button className="inline-flex items-center gap-2 rounded-lg border border-blue-200 bg-blue-50 px-3.5 py-2 text-sm font-medium text-blue-700 hover:bg-blue-100 transition-colors">
                            <RefreshCw size={15} />
                            리소스 재스캔
                        </button>
                    </div>
                </div>

                <div className="mt-5 text-sm text-muted-foreground">
                    감지된 리소스 <span className="font-semibold text-foreground">{summary.total}개</span>
                    <span className="mx-2">·</span>
                    클릭하면 상세 표시
                </div>
            </div>

            {/* Top summary */}
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
                <SummaryCard
                    title="전체 리소스"
                    value={`${summary.total}개`}
                    sub={`정상 ${summary.healthy} · 경고 ${summary.warning} · 위험 ${summary.danger}`}
                    icon={<ShieldCheck size={18} className="text-emerald-600" />}
                />
                <SummaryCard
                    title="평균 ISMS-P 준수율"
                    value={`${summary.avgScore}%`}
                    sub="자동 점검 기준 평균 점수"
                    icon={<ShieldAlert size={18} className="text-violet-600" />}
                />
                <SummaryCard
                    title="고위험 항목"
                    value={`${summary.totalCritical + summary.totalHigh}건`}
                    sub={`Critical ${summary.totalCritical} · High ${summary.totalHigh}`}
                    icon={<AlertTriangle size={18} className="text-red-600" />}
                />
                <SummaryCard
                    title="중간 위험 항목"
                    value={`${summary.totalMedium}건`}
                    sub="추가 검토가 필요한 항목"
                    icon={<Search size={18} className="text-blue-600" />}
                />
            </div>

            {/* Resource cards */}
            <div className="space-y-4">
                {mockResources.map((resource) => (
                    <ResourceCard key={resource.id} resource={resource} />
                ))}
            </div>

            {/* Summary table */}
            <div className="rounded-xl border border-border bg-card shadow-sm overflow-hidden">
                <div className="border-b border-border px-5 py-4">
                    <div className="text-sm font-semibold text-foreground">리소스별 ISMS-P 준수율</div>
                    <div className="mt-1 text-xs text-muted-foreground">
                        자동 점검 기준 리소스별 충족/미충족 현황
                    </div>
                </div>

                <div className="overflow-x-auto">
                    <table className="w-full min-w-[760px] text-sm">
                        <thead className="bg-muted/30">
                            <tr className="border-b border-border text-left">
                                <th className="px-5 py-3 font-medium text-muted-foreground">리소스</th>
                                <th className="px-5 py-3 font-medium text-muted-foreground">유형</th>
                                <th className="px-5 py-3 font-medium text-muted-foreground">자동 점검</th>
                                <th className="px-5 py-3 font-medium text-muted-foreground">충족</th>
                                <th className="px-5 py-3 font-medium text-muted-foreground">미충족</th>
                                <th className="px-5 py-3 font-medium text-muted-foreground">준수율</th>
                            </tr>
                        </thead>
                        <tbody>
                            {mockResources.map((resource) => (
                                <tr key={resource.id} className="border-b border-border last:border-b-0 hover:bg-muted/20">
                                    <td className="px-5 py-4 font-semibold text-foreground">{resource.name}</td>
                                    <td className="px-5 py-4 text-muted-foreground">{resource.type}</td>
                                    <td className="px-5 py-4 text-muted-foreground">{resource.checks}개</td>
                                    <td className="px-5 py-4 font-semibold text-emerald-600">{resource.passed}</td>
                                    <td className="px-5 py-4 font-semibold text-red-500">{resource.failed}</td>
                                    <td className="px-5 py-4 font-semibold text-violet-600">{resource.score}%</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    );
}