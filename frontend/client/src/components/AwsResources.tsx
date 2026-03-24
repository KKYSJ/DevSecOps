import React, { useEffect, useMemo, useState } from 'react';
import {
    RefreshCw,
    Server,
    Database,
    Box,
    FunctionSquare,
    ShieldCheck,
    AlertTriangle,
    Search,
    Globe,
    Lock,
    Layers3,
    Activity,
    ChevronDown,
    ChevronUp,
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

    clusterArn?: string;
    serviceArn?: string;
    statusRaw?: string;
    desiredCount?: number;
    runningCount?: number;
    pendingCount?: number;
    launchType?: string;
    platformVersion?: string;
    taskDefinition?: string;
    createdAt?: string | null;

    dbInstanceArn?: string;
    engine?: string;
    engineVersion?: string;
    dbInstanceClass?: string;
    storageEncrypted?: boolean;
    publiclyAccessible?: boolean;
    multiAZ?: boolean;
    backupRetentionPeriod?: number;
    endpoint?: string;
    port?: number;

    functionArn?: string;
    runtime?: string;
    handler?: string;
    memorySize?: number;
    timeout?: number;
    lastModified?: string;
    vpcAttached?: boolean;
    state?: string;

    bucketName?: string;

    loadBalancerArn?: string;
    dnsName?: string;
    scheme?: string;
    ipAddressType?: string;
    vpcId?: string;
    stateRaw?: string;
    createdTime?: string | null;
};

type AwsResourcesApiBody = {
    account_id: string;
    region: string;
    resourceCount?: number;
    resources: Resource[];
};

const API_URL = 'https://mosx43w73a.execute-api.ap-northeast-2.amazonaws.com/aws/resources';

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

function InfoPill({
    icon,
    label,
}: {
    icon?: React.ReactNode;
    label: string;
}) {
    return (
        <div className="inline-flex items-center gap-1.5 rounded-md border border-slate-200 bg-slate-50 px-2.5 py-1 text-xs text-slate-700">
            {icon}
            <span>{label}</span>
        </div>
    );
}

function formatDateTime(value?: string | null) {
    if (!value) return '-';
    return value;
}

function ResourceDetailCard({ resource }: { resource: Resource }) {
    const status = getStatusConfig(resource.status);

    return (
        <div className={`rounded-xl border border-border bg-card p-5 shadow-sm ${status.border}`}>
            <div className="flex flex-col gap-5">
                <div className="min-w-0">
                    <div className="flex items-center gap-2 text-[11px] tracking-wider text-muted-foreground uppercase">
                        {getTypeIcon(resource.type)}
                        <span>{resource.type}</span>
                    </div>

                    <div className="mt-2 flex flex-wrap items-center gap-2">
                        <div className="text-2xl font-bold text-foreground break-all">{resource.name}</div>
                        <span className={`inline-flex rounded-md border px-3 py-1 text-xs font-semibold ${status.badge}`}>
                            {status.label}
                        </span>
                    </div>

                    <div className="mt-2 text-sm text-muted-foreground">{resource.region}</div>
                </div>

                <div className="flex flex-wrap gap-2">
                    {resource.type === 'ECS SERVICE' && (
                        <>
                            <InfoPill
                                icon={<Activity size={12} />}
                                label={`Running ${resource.runningCount ?? 0} / Desired ${resource.desiredCount ?? 0}`}
                            />
                            {typeof resource.pendingCount === 'number' && (
                                <InfoPill label={`Pending ${resource.pendingCount}`} />
                            )}
                            {resource.launchType && <InfoPill label={resource.launchType} />}
                            {resource.platformVersion && <InfoPill label={`Platform ${resource.platformVersion}`} />}
                            {resource.statusRaw && <InfoPill label={`Raw ${resource.statusRaw}`} />}
                        </>
                    )}

                    {resource.type === 'RDS INSTANCE' && (
                        <>
                            {resource.engine && <InfoPill label={`${resource.engine} ${resource.engineVersion ?? ''}`.trim()} />}
                            {resource.dbInstanceClass && <InfoPill label={resource.dbInstanceClass} />}
                            <InfoPill
                                icon={resource.storageEncrypted ? <Lock size={12} /> : <AlertTriangle size={12} />}
                                label={resource.storageEncrypted ? '암호화 활성' : '암호화 비활성'}
                            />
                            <InfoPill label={resource.publiclyAccessible ? 'Public 접근 가능' : 'Private 접근'} />
                            <InfoPill label={resource.multiAZ ? 'Multi-AZ' : 'Single-AZ'} />
                            {typeof resource.backupRetentionPeriod === 'number' && (
                                <InfoPill label={`Backup ${resource.backupRetentionPeriod}d`} />
                            )}
                        </>
                    )}

                    {resource.type === 'LAMBDA' && (
                        <>
                            {resource.runtime && <InfoPill label={resource.runtime} />}
                            {resource.memorySize && <InfoPill label={`${resource.memorySize} MB`} />}
                            {typeof resource.timeout === 'number' && <InfoPill label={`Timeout ${resource.timeout}s`} />}
                            <InfoPill label={resource.vpcAttached ? 'VPC 연결' : 'VPC 미연결'} />
                            {resource.state && <InfoPill label={`State ${resource.state}`} />}
                        </>
                    )}

                    {resource.type === 'S3 BUCKET' && (
                        <>
                            <InfoPill label="Bucket 리소스" />
                            {resource.bucketName && <InfoPill label={resource.bucketName} />}
                            <InfoPill icon={<Layers3 size={12} />} label="세부 검사 별도 예정" />
                        </>
                    )}

                    {resource.type === 'ALB' && (
                        <>
                            {resource.scheme && (
                                <InfoPill
                                    icon={resource.scheme === 'internet-facing' ? <Globe size={12} /> : <Lock size={12} />}
                                    label={resource.scheme}
                                />
                            )}
                            {resource.ipAddressType && <InfoPill label={resource.ipAddressType} />}
                            {resource.stateRaw && <InfoPill label={`State ${resource.stateRaw}`} />}
                        </>
                    )}
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
                    {resource.type === 'ECS SERVICE' && (
                        <>
                            <div className="rounded-lg border border-border bg-slate-50 p-4">
                                <div className="text-xs text-muted-foreground">Cluster ARN</div>
                                <div className="mt-1 text-sm font-medium break-all">{resource.clusterArn ?? '-'}</div>
                            </div>
                            <div className="rounded-lg border border-border bg-slate-50 p-4">
                                <div className="text-xs text-muted-foreground">Task Definition</div>
                                <div className="mt-1 text-sm font-medium break-all">{resource.taskDefinition ?? '-'}</div>
                            </div>
                            <div className="rounded-lg border border-border bg-slate-50 p-4">
                                <div className="text-xs text-muted-foreground">Created At</div>
                                <div className="mt-1 text-sm font-medium">{formatDateTime(resource.createdAt)}</div>
                            </div>
                        </>
                    )}

                    {resource.type === 'RDS INSTANCE' && (
                        <>
                            <div className="rounded-lg border border-border bg-slate-50 p-4">
                                <div className="text-xs text-muted-foreground">Endpoint</div>
                                <div className="mt-1 text-sm font-medium break-all">{resource.endpoint ?? '-'}</div>
                            </div>
                            <div className="rounded-lg border border-border bg-slate-50 p-4">
                                <div className="text-xs text-muted-foreground">Port</div>
                                <div className="mt-1 text-sm font-medium">{resource.port ?? '-'}</div>
                            </div>
                            <div className="rounded-lg border border-border bg-slate-50 p-4">
                                <div className="text-xs text-muted-foreground">Raw Status</div>
                                <div className="mt-1 text-sm font-medium">{resource.statusRaw ?? '-'}</div>
                            </div>
                        </>
                    )}

                    {resource.type === 'LAMBDA' && (
                        <>
                            <div className="rounded-lg border border-border bg-slate-50 p-4">
                                <div className="text-xs text-muted-foreground">Handler</div>
                                <div className="mt-1 text-sm font-medium break-all">{resource.handler ?? '-'}</div>
                            </div>
                            <div className="rounded-lg border border-border bg-slate-50 p-4">
                                <div className="text-xs text-muted-foreground">Last Modified</div>
                                <div className="mt-1 text-sm font-medium">{resource.lastModified ?? '-'}</div>
                            </div>
                            <div className="rounded-lg border border-border bg-slate-50 p-4">
                                <div className="text-xs text-muted-foreground">Function ARN</div>
                                <div className="mt-1 text-sm font-medium break-all">{resource.functionArn ?? '-'}</div>
                            </div>
                        </>
                    )}

                    {resource.type === 'S3 BUCKET' && (
                        <>
                            <div className="rounded-lg border border-border bg-slate-50 p-4">
                                <div className="text-xs text-muted-foreground">Bucket Name</div>
                                <div className="mt-1 text-sm font-medium break-all">{resource.bucketName ?? resource.name}</div>
                            </div>
                            <div className="rounded-lg border border-border bg-slate-50 p-4">
                                <div className="text-xs text-muted-foreground">Created At</div>
                                <div className="mt-1 text-sm font-medium">{formatDateTime(resource.createdAt)}</div>
                            </div>
                        </>
                    )}

                    {resource.type === 'ALB' && (
                        <>
                            <div className="rounded-lg border border-border bg-slate-50 p-4">
                                <div className="text-xs text-muted-foreground">DNS Name</div>
                                <div className="mt-1 text-sm font-medium break-all">{resource.dnsName ?? '-'}</div>
                            </div>
                            <div className="rounded-lg border border-border bg-slate-50 p-4">
                                <div className="text-xs text-muted-foreground">VPC ID</div>
                                <div className="mt-1 text-sm font-medium break-all">{resource.vpcId ?? '-'}</div>
                            </div>
                            <div className="rounded-lg border border-border bg-slate-50 p-4">
                                <div className="text-xs text-muted-foreground">Created Time</div>
                                <div className="mt-1 text-sm font-medium">{formatDateTime(resource.createdTime)}</div>
                            </div>
                        </>
                    )}
                </div>
            </div>
        </div>
    );
}

function ResourceTableRow({ resource }: { resource: Resource }) {
    const status = getStatusConfig(resource.status);

    return (
        <tr className="border-b border-border last:border-b-0 hover:bg-muted/20">
            <td className="px-5 py-4 font-semibold text-foreground">{resource.name}</td>
            <td className="px-5 py-4 text-muted-foreground">{resource.type}</td>
            <td className="px-5 py-4 text-muted-foreground">{resource.region}</td>
            <td className="px-5 py-4">
                <span className={`inline-flex rounded-md border px-2.5 py-1 text-xs font-semibold ${status.badge}`}>
                    {status.label}
                </span>
            </td>
            <td className="px-5 py-4 text-muted-foreground">
                {resource.type === 'ECS SERVICE' && `Running ${resource.runningCount ?? 0}/${resource.desiredCount ?? 0}`}
                {resource.type === 'RDS INSTANCE' && (resource.publiclyAccessible ? 'Public' : 'Private')}
                {resource.type === 'LAMBDA' && (resource.vpcAttached ? 'VPC 연결' : 'VPC 미연결')}
                {resource.type === 'S3 BUCKET' && 'Bucket'}
                {resource.type === 'ALB' && (resource.scheme ?? '-')}
            </td>
            <td className="px-5 py-4 text-muted-foreground">
                {resource.type === 'RDS INSTANCE' && resource.engine}
                {resource.type === 'LAMBDA' && resource.runtime}
                {resource.type === 'ALB' && resource.stateRaw}
                {resource.type === 'ECS SERVICE' && resource.launchType}
                {resource.type === 'S3 BUCKET' && formatDateTime(resource.createdAt)}
            </td>
        </tr>
    );
}

export default function AwsResources() {
    const [resources, setResources] = useState<Resource[]>([]);
    const [accountId, setAccountId] = useState('');
    const [region, setRegion] = useState('ap-northeast-2');
    const [loading, setLoading] = useState(true);
    const [refreshing, setRefreshing] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [showAll, setShowAll] = useState(false);

    const fetchResources = async (isManualRefresh = false) => {
        try {
            if (isManualRefresh) {
                setRefreshing(true);
            } else {
                setLoading(true);
            }
            setError(null);

            const res = await fetch(API_URL);
            if (!res.ok) {
                throw new Error(`API 호출 실패: ${res.status}`);
            }

            const data = await res.json();
            const parsed: AwsResourcesApiBody =
                typeof data.body === 'string' ? JSON.parse(data.body) : data;

            setResources(parsed.resources ?? []);
            setAccountId(parsed.account_id ?? '');
            setRegion(parsed.region ?? 'ap-northeast-2');
        } catch (err) {
            setError(err instanceof Error ? err.message : '알 수 없는 오류');
        } finally {
            setLoading(false);
            setRefreshing(false);
        }
    };

    useEffect(() => {
        fetchResources();
    }, []);

    const summary = useMemo(() => {
        const total = resources.length;
        const healthy = resources.filter((r) => r.status === '정상').length;
        const warning = resources.filter((r) => r.status === '경고').length;
        const danger = resources.filter((r) => r.status === '위험').length;

        const ecsCount = resources.filter((r) => r.type === 'ECS SERVICE').length;
        const rdsCount = resources.filter((r) => r.type === 'RDS INSTANCE').length;
        const lambdaCount = resources.filter((r) => r.type === 'LAMBDA').length;
        const s3Count = resources.filter((r) => r.type === 'S3 BUCKET').length;
        const albCount = resources.filter((r) => r.type === 'ALB').length;

        return {
            total,
            healthy,
            warning,
            danger,
            ecsCount,
            rdsCount,
            lambdaCount,
            s3Count,
            albCount,
        };
    }, [resources]);

    const visibleResources = showAll ? resources : resources.slice(0, 6);

    if (loading) {
        return (
            <div className="rounded-xl border border-border bg-card p-6 shadow-sm">
                <div className="text-sm text-muted-foreground">AWS 리소스를 불러오는 중...</div>
            </div>
        );
    }

    if (error) {
        return (
            <div className="rounded-xl border border-red-200 bg-red-50 p-6 shadow-sm">
                <div className="text-sm font-semibold text-red-700">AWS 리소스 조회 실패</div>
                <div className="mt-2 text-sm text-red-600">{error}</div>
                <button
                    onClick={() => fetchResources(true)}
                    className="mt-4 inline-flex items-center gap-2 rounded-lg border border-red-200 bg-white px-3.5 py-2 text-sm font-medium text-red-700 hover:bg-red-100 transition-colors"
                >
                    <RefreshCw size={15} />
                    다시 시도
                </button>
            </div>
        );
    }

    return (
        <div className="space-y-6">
            {/* Header */}
            <div className="rounded-xl border border-border bg-card p-5 shadow-sm">
                <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
                    <div>
                        <h2 className="text-2xl font-bold text-foreground">AWS 리소스 인벤토리</h2>
                        <p className="mt-1 text-sm text-muted-foreground">
                            AWS API 실데이터 기반 리소스 조회 화면
                        </p>
                    </div>

                    <div className="flex items-center gap-3">
                        <div className="rounded-lg border border-border bg-slate-50 px-3 py-2 text-sm text-slate-600">
                            Account: <span className="font-semibold text-foreground">{accountId || '-'}</span>
                            <span className="mx-2 text-slate-300">·</span>
                            {region}
                        </div>

                        <button
                            onClick={() => fetchResources(true)}
                            disabled={refreshing}
                            className="inline-flex items-center gap-2 rounded-lg border border-blue-200 bg-blue-50 px-3.5 py-2 text-sm font-medium text-blue-700 hover:bg-blue-100 transition-colors disabled:opacity-60 disabled:cursor-not-allowed"
                        >
                            <RefreshCw size={15} className={refreshing ? 'animate-spin' : ''} />
                            {refreshing ? '재조회 중...' : '리소스 재조회'}
                        </button>
                    </div>
                </div>
            </div>

            {/* Top summary */}
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-5 gap-4">
                <SummaryCard
                    title="전체 리소스"
                    value={`${summary.total}개`}
                    sub={`정상 ${summary.healthy} · 경고 ${summary.warning} · 위험 ${summary.danger}`}
                    icon={<ShieldCheck size={18} className="text-emerald-600" />}
                />
                <SummaryCard
                    title="ECS / RDS"
                    value={`${summary.ecsCount} / ${summary.rdsCount}`}
                    sub="서비스 / 데이터베이스"
                    icon={<Server size={18} className="text-blue-600" />}
                />
                <SummaryCard
                    title="Lambda / S3"
                    value={`${summary.lambdaCount} / ${summary.s3Count}`}
                    sub="함수 / 버킷"
                    icon={<FunctionSquare size={18} className="text-amber-600" />}
                />
                <SummaryCard
                    title="ALB"
                    value={`${summary.albCount}개`}
                    sub="Application Load Balancer"
                    icon={<Search size={18} className="text-violet-600" />}
                />
                <SummaryCard
                    title="리전"
                    value={region}
                    sub="현재 조회 기준"
                    icon={<Globe size={18} className="text-green-600" />}
                />
            </div>

            {/* Full inventory detail */}
            <div className="rounded-xl border border-border bg-card shadow-sm overflow-hidden">
                <div className="border-b border-border px-5 py-4 flex items-center justify-between gap-3">
                    <div>
                        <div className="text-sm font-semibold text-foreground">전체 리소스 상세</div>
                        <div className="mt-1 text-xs text-muted-foreground">
                            AWS에서 내려온 실제 속성만 표시
                        </div>
                    </div>

                    {resources.length > 6 && (
                        <button
                            onClick={() => setShowAll((prev) => !prev)}
                            className="inline-flex items-center gap-2 rounded-lg border border-border bg-white px-3 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50 transition-colors"
                        >
                            {showAll ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
                            {showAll ? '접기' : `더보기 (${resources.length - 6})`}
                        </button>
                    )}
                </div>

                <div className="p-5 space-y-4">
                    {visibleResources.map((resource) => (
                        <ResourceDetailCard key={resource.id} resource={resource} />
                    ))}
                </div>
            </div>

            {/* Inventory summary table */}
            <div className="rounded-xl border border-border bg-card shadow-sm overflow-hidden">
                <div className="border-b border-border px-5 py-4">
                    <div className="text-sm font-semibold text-foreground">리소스 요약 테이블</div>
                    <div className="mt-1 text-xs text-muted-foreground">
                        빠르게 전체 리소스 확인
                    </div>
                </div>

                <div className="overflow-x-auto">
                    <table className="w-full min-w-[980px] text-sm">
                        <thead className="bg-muted/30">
                            <tr className="border-b border-border text-left">
                                <th className="px-5 py-3 font-medium text-muted-foreground">리소스</th>
                                <th className="px-5 py-3 font-medium text-muted-foreground">유형</th>
                                <th className="px-5 py-3 font-medium text-muted-foreground">리전</th>
                                <th className="px-5 py-3 font-medium text-muted-foreground">상태</th>
                                <th className="px-5 py-3 font-medium text-muted-foreground">핵심 속성</th>
                                <th className="px-5 py-3 font-medium text-muted-foreground">추가 정보</th>
                            </tr>
                        </thead>
                        <tbody>
                            {resources.map((resource) => (
                                <ResourceTableRow key={resource.id} resource={resource} />
                            ))}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    );
}