import React, { useEffect, useMemo, useState } from 'react';
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
    Globe,
    Lock,
    Layers3,
    Activity,
    ChevronDown,
    ChevronUp,
} from 'lucide-react';

function AwsAccordion({ title, subtitle, defaultOpen = false, children }: { title: string; subtitle?: string; defaultOpen?: boolean; children: React.ReactNode }) {
    const [open, setOpen] = useState(defaultOpen);
    return (
        <div className="rounded-xl border border-border bg-card shadow-sm overflow-hidden">
            <button onClick={() => setOpen(!open)} className="w-full flex items-center justify-between px-5 py-4 hover:bg-muted/30 transition-colors">
                <div className="flex items-center gap-3">
                    <ChevronDown size={16} className={`text-muted-foreground transition-transform ${open ? 'rotate-0' : '-rotate-90'}`} />
                    <div className="text-left">
                        <div className="text-sm font-semibold text-foreground">{title}</div>
                        {subtitle && <div className="text-xs text-muted-foreground">{subtitle}</div>}
                    </div>
                </div>
            </button>
            {open && <div className="border-t border-border">{children}</div>}
        </div>
    );
}

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

function getDerivedRisk(resource: Resource) {
    let high = 0;
    let medium = 0;
    const issues: string[] = [];

    if (resource.type === 'ECS SERVICE') {
        const desired = resource.desiredCount ?? 0;
        const running = resource.runningCount ?? 0;

        if (desired > 0 && running < desired) {
            high += 1;
            issues.push('실행 태스크 수 부족');
        }

        if ((resource.pendingCount ?? 0) > 0) {
            medium += 1;
            issues.push('Pending 태스크 존재');
        }
    }

    if (resource.type === 'RDS INSTANCE') {
        if (resource.publiclyAccessible) {
            high += 1;
            issues.push('Public 접근 허용');
        }
        if (resource.storageEncrypted === false) {
            high += 1;
            issues.push('스토리지 암호화 비활성');
        }
        if (resource.multiAZ === false) {
            medium += 1;
            issues.push('Multi-AZ 미구성');
        }
        if ((resource.backupRetentionPeriod ?? 0) <= 0) {
            medium += 1;
            issues.push('백업 보존 기간 없음');
        }
    }

    if (resource.type === 'LAMBDA') {
        if (!resource.vpcAttached) {
            medium += 1;
            issues.push('VPC 미연결');
        }
        if ((resource.timeout ?? 0) > 30) {
            medium += 1;
            issues.push('타임아웃 과다');
        }
    }

    if (resource.type === 'ALB') {
        if (resource.scheme === 'internet-facing') {
            high += 1;
            issues.push('외부 공개 ALB');
        }
    }

    if (resource.type === 'S3 BUCKET') {
        issues.push('S3 보안 세부 검사는 별도 API 예정');
    }

    return { high, medium, issues };
}

function getDisplayStatus(resource: Resource): ResourceStatus {
    const risk = getDerivedRisk(resource);

    if (risk.high >= 2) return '위험';
    if (resource.status === '경고' || risk.high >= 1 || risk.medium >= 2) return '경고';
    return '정상';
}

function getMockIsmsScore(resource: Resource) {
    if (resource.type === 'RDS INSTANCE') return 92;
    if (resource.type === 'LAMBDA') return 88;
    if (resource.type === 'ALB') return 84;
    if (resource.type === 'ECS SERVICE') return 86;
    return 82;
}

function getMockIsmsChecks(resource: Resource) {
    const score = getMockIsmsScore(resource);
    const checks = 38;
    const passed = Math.round((checks * score) / 100);
    const failed = checks - passed;
    return { checks, passed, failed, score };
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

function ScoreBar({ score }: { score: number }) {
    return (
        <div className="flex items-center gap-3">
            <div className="flex-1 h-2 rounded-full bg-slate-100 overflow-hidden">
                <div
                    className="h-full rounded-full bg-violet-500 transition-all duration-500"
                    style={{ width: `${score}%` }}
                />
            </div>
            <div className="min-w-[80px] text-right text-sm font-semibold text-violet-600">
                ISMS-P {score}%
            </div>
        </div>
    );
}

function ResourceTableRow({ resource }: { resource: Resource }) {
    const derived = getDerivedRisk(resource);
    const displayStatus = getDisplayStatus(resource);
    const status = getStatusConfig(displayStatus);

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
            <td className="px-5 py-4 font-semibold text-red-500">{derived.high}</td>
            <td className="px-5 py-4 font-semibold text-amber-500">{derived.medium}</td>
            <td className="px-5 py-4 text-muted-foreground">{derived.issues[0] ?? '-'}</td>
        </tr>
    );
}

function PriorityRiskCard({ resource }: { resource: Resource }) {
    const derived = getDerivedRisk(resource);
    const displayStatus = getDisplayStatus(resource);
    const status = getStatusConfig(displayStatus);

    return (
        <div className={`rounded-xl border border-border bg-card p-5 shadow-sm ${status.border}`}>
            <div className="flex items-start justify-between gap-4">
                <div className="min-w-0">
                    <div className="flex items-center gap-2 text-[11px] tracking-wider text-muted-foreground uppercase">
                        {getTypeIcon(resource.type)}
                        <span>{resource.type}</span>
                    </div>
                    <div className="mt-2 text-xl font-bold text-foreground break-all">{resource.name}</div>
                    <div className="mt-1 text-sm text-muted-foreground">{resource.region}</div>
                </div>

                <span className={`shrink-0 inline-flex rounded-md border px-3 py-1 text-xs font-semibold ${status.badge}`}>
                    {status.label}
                </span>
            </div>

            <div className="mt-4 grid grid-cols-2 gap-3">
                <div className="rounded-lg border border-red-200 bg-red-50 p-3">
                    <div className="text-xs text-red-700">HIGH</div>
                    <div className="mt-1 text-2xl font-bold text-red-600">{derived.high}</div>
                </div>
                <div className="rounded-lg border border-amber-200 bg-amber-50 p-3">
                    <div className="text-xs text-amber-700">MEDIUM</div>
                    <div className="mt-1 text-2xl font-bold text-amber-600">{derived.medium}</div>
                </div>
            </div>

            <div className="mt-4 space-y-2">
                {derived.issues.map((issue, idx) => (
                    <div
                        key={idx}
                        className="rounded-md border border-slate-200 bg-white px-3 py-2 text-sm text-slate-700"
                    >
                        {issue}
                    </div>
                ))}
            </div>
        </div>
    );
}

function ResourceDetailCard({ resource }: { resource: Resource }) {
    const derivedRisk = getDerivedRisk(resource);
    const displayStatus = getDisplayStatus(resource);
    const status = getStatusConfig(displayStatus);
    const isms = getMockIsmsChecks(resource);

    return (
        <div className={`rounded-xl border border-border bg-card p-5 shadow-sm ${status.border}`}>
            <div className="flex flex-col gap-5 xl:flex-row xl:items-start xl:justify-between">
                <div className="min-w-0 flex-1">
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

                    <div className="mt-4 flex flex-wrap gap-2">
                        {resource.type === 'ECS SERVICE' && (
                            <>
                                <InfoPill
                                    icon={<Activity size={12} />}
                                    label={`Running ${resource.runningCount ?? 0} / Desired ${resource.desiredCount ?? 0}`}
                                />
                                {resource.launchType && <InfoPill label={resource.launchType} />}
                                {resource.platformVersion && <InfoPill label={`Platform ${resource.platformVersion}`} />}
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
                            </>
                        )}

                        {resource.type === 'LAMBDA' && (
                            <>
                                {resource.runtime && <InfoPill label={resource.runtime} />}
                                {resource.memorySize && <InfoPill label={`${resource.memorySize} MB`} />}
                                {typeof resource.timeout === 'number' && <InfoPill label={`Timeout ${resource.timeout}s`} />}
                                <InfoPill label={resource.vpcAttached ? 'VPC 연결' : 'VPC 미연결'} />
                            </>
                        )}

                        {resource.type === 'S3 BUCKET' && (
                            <>
                                <InfoPill label="Bucket 리소스" />
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
                </div>

                <div className="xl:w-[340px] w-full">
                    <div className="rounded-lg border border-border bg-slate-50/60 p-4">
                        <div className="text-sm font-semibold text-foreground">파생 리스크 요약</div>

                        <div className="mt-4 grid grid-cols-2 gap-6">
                            <div>
                                <div className="text-xl font-bold font-mono text-red-500">{derivedRisk.high}</div>
                                <div className="mt-0.5 text-[10px] tracking-wide text-muted-foreground uppercase">HIGH</div>
                            </div>
                            <div>
                                <div className="text-xl font-bold font-mono text-amber-500">{derivedRisk.medium}</div>
                                <div className="mt-0.5 text-[10px] tracking-wide text-muted-foreground uppercase">MEDIUM</div>
                            </div>
                        </div>

                        <div className="mt-4">
                            <ScoreBar score={isms.score} />
                        </div>

                        <div className="mt-4 space-y-2">
                            <div className="text-xs font-medium text-muted-foreground">주요 포인트</div>
                            {derivedRisk.issues.length > 0 ? (
                                derivedRisk.issues.map((issue, idx) => (
                                    <div
                                        key={idx}
                                        className="rounded-md border border-slate-200 bg-white px-3 py-2 text-sm text-slate-700"
                                    >
                                        {issue}
                                    </div>
                                ))
                            ) : (
                                <div className="rounded-md border border-emerald-200 bg-emerald-50 px-3 py-2 text-sm text-emerald-700">
                                    현재 눈에 띄는 파생 리스크 없음
                                </div>
                            )}
                        </div>
                    </div>
                </div>
            </div>
        </div>
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
    const [ismsData, setIsmsData] = useState<any>(null);

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
        // ISMS-P 데이터 로드
        fetch('/api/v1/isms').then(r => r.json()).then(data => {
            const checker = data?.checker_result || data;
            setIsmsData(checker);
        }).catch(() => {});
    }, []);

    const derivedSummary = useMemo(() => {
        const statuses = resources.map((r) => getDisplayStatus(r));
        const healthy = statuses.filter((s) => s === '정상').length;
        const warning = statuses.filter((s) => s === '경고').length;
        const danger = statuses.filter((s) => s === '위험').length;

        const totalHigh = resources.reduce((sum, r) => sum + getDerivedRisk(r).high, 0);
        const totalMedium = resources.reduce((sum, r) => sum + getDerivedRisk(r).medium, 0);

        const publicExposed = resources.filter((r) => {
            if (r.type === 'RDS INSTANCE') return !!r.publiclyAccessible;
            if (r.type === 'ALB') return r.scheme === 'internet-facing';
            return false;
        }).length;

        const unencrypted = resources.filter((r) => r.type === 'RDS INSTANCE' && r.storageEncrypted === false).length;

        const avgScore =
            resources.length > 0
                ? Math.round(resources.reduce((sum, r) => sum + getMockIsmsScore(r), 0) / resources.length)
                : 0;

        return {
            total: resources.length,
            healthy,
            warning,
            danger,
            totalHigh,
            totalMedium,
            publicExposed,
            unencrypted,
            avgScore,
        };
    }, [resources]);

    const priorityResources = useMemo(() => {
        return resources
            .filter((r) => {
                const risk = getDerivedRisk(r);
                const displayStatus = getDisplayStatus(r);
                return displayStatus !== '정상' || risk.high > 0 || risk.medium > 0;
            })
            .sort((a, b) => {
                const riskA = getDerivedRisk(a);
                const riskB = getDerivedRisk(b);
                return riskB.high * 10 + riskB.medium - (riskA.high * 10 + riskA.medium);
            });
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
                        <h2 className="text-2xl font-bold text-foreground">AWS 리소스 보안 대시보드</h2>
                        <p className="mt-1 text-sm text-muted-foreground">
                            실시간 리소스 인벤토리 · 보안 관점 파생 리스크 요약
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
                            {refreshing ? '재조회 중...' : '리소스 재스캔'}
                        </button>
                    </div>
                </div>

                <div className="mt-5 text-sm text-muted-foreground">
                    감지된 리소스 <span className="font-semibold text-foreground">{derivedSummary.total}개</span>
                    <span className="mx-2">·</span>
                    실데이터 기반 인벤토리 + 프론트 파생 리스크 시각화
                </div>
            </div>

            {/* Top security summary */}
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-5 gap-4">
                <SummaryCard
                    title="전체 리소스"
                    value={`${derivedSummary.total}개`}
                    sub={`정상 ${derivedSummary.healthy} · 경고 ${derivedSummary.warning} · 위험 ${derivedSummary.danger}`}
                    icon={<ShieldCheck size={18} className="text-emerald-600" />}
                />
                <SummaryCard
                    title="고위험 포인트"
                    value={`${derivedSummary.totalHigh}건`}
                    sub="실데이터 기반 파생 리스크"
                    icon={<AlertTriangle size={18} className="text-red-600" />}
                />
                <SummaryCard
                    title="중간 위험 포인트"
                    value={`${derivedSummary.totalMedium}건`}
                    sub="운영/구성 기반 주의 항목"
                    icon={<Search size={18} className="text-blue-600" />}
                />
                <SummaryCard
                    title="외부 노출 자산"
                    value={`${derivedSummary.publicExposed}개`}
                    sub="Public RDS / internet-facing ALB"
                    icon={<Globe size={18} className="text-amber-600" />}
                />
                <SummaryCard
                    title="평균 ISMS-P 준수율"
                    value={`${derivedSummary.avgScore}%`}
                    sub="임시 가데이터 · 추후 별도 API 연동"
                    icon={<ShieldAlert size={18} className="text-violet-600" />}
                />
            </div>

            {/* Priority risks — Accordion */}
            <AwsAccordion title="우선 확인이 필요한 자산" subtitle={`경고/위험 ${priorityResources.length}건`} defaultOpen={priorityResources.length > 0}>
                <div className="p-5">
                    {priorityResources.length > 0 ? (
                        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
                            {priorityResources.slice(0, 4).map((resource) => (
                                <PriorityRiskCard key={resource.id} resource={resource} />
                            ))}
                        </div>
                    ) : (
                        <div className="rounded-lg border border-emerald-200 bg-emerald-50 p-4 text-sm text-emerald-700">
                            현재 우선 확인이 필요한 주요 리스크 자산이 없습니다.
                        </div>
                    )}
                </div>
            </AwsAccordion>

            {/* Full inventory detail — Accordion */}
            <AwsAccordion title="전체 리소스 인벤토리" subtitle={`${resources.length}개 리소스`}>
                <div className="p-5 space-y-4">
                    {resources.map((resource) => (
                        <ResourceDetailCard key={resource.id} resource={resource} />
                    ))}
                </div>
            </AwsAccordion>

            {/* Inventory summary table — Accordion */}
            <AwsAccordion title="리소스 요약 테이블" subtitle="빠른 스캔용 테이블 뷰">

                <div className="overflow-x-auto">
                    <table className="w-full min-w-[980px] text-sm">
                        <thead className="bg-muted/30">
                            <tr className="border-b border-border text-left">
                                <th className="px-5 py-3 font-medium text-muted-foreground">리소스</th>
                                <th className="px-5 py-3 font-medium text-muted-foreground">유형</th>
                                <th className="px-5 py-3 font-medium text-muted-foreground">리전</th>
                                <th className="px-5 py-3 font-medium text-muted-foreground">상태</th>
                                <th className="px-5 py-3 font-medium text-muted-foreground">HIGH</th>
                                <th className="px-5 py-3 font-medium text-muted-foreground">MEDIUM</th>
                                <th className="px-5 py-3 font-medium text-muted-foreground">주요 이슈</th>
                            </tr>
                        </thead>
                        <tbody>
                            {resources.map((resource) => (
                                <ResourceTableRow key={resource.id} resource={resource} />
                            ))}
                        </tbody>
                    </table>
                </div>
            </AwsAccordion>

        </div>
    );
}