import { useState } from 'react';
import { ChevronDown, ChevronUp } from 'lucide-react';

interface LlmJudgment {
    judgment: 'TRUE_POSITIVE' | 'FALSE_POSITIVE' | 'UNCERTAIN';
    confidence: number;
    reasoning: string;
}

interface CrossAnalysisItem {
    id: string | number;
    category: string;
    severity: 'HIGH' | 'MEDIUM' | 'LOW';
    detectionCount: number;
    description: string;
    tools: string[];
    llmJudgment?: LlmJudgment;
}

interface StageCrossAnalysisProps {
    items: CrossAnalysisItem[];
    title?: string;
}

function getSeverityClass(severity: CrossAnalysisItem['severity']) {
    if (severity === 'HIGH') return 'bg-red-100 text-red-700 border-red-200';
    if (severity === 'MEDIUM') return 'bg-amber-100 text-amber-700 border-amber-200';
    return 'bg-blue-100 text-blue-700 border-blue-200';
}

function getJudgmentLabel(judgment: LlmJudgment['judgment']) {
    if (judgment === 'TRUE_POSITIVE') return '실제 취약점';
    if (judgment === 'FALSE_POSITIVE') return '오탐';
    return '검토 필요';
}

function getJudgmentClass(judgment: LlmJudgment['judgment']) {
    if (judgment === 'TRUE_POSITIVE') return 'text-green-700';
    if (judgment === 'FALSE_POSITIVE') return 'text-red-700';
    return 'text-blue-700';
}

function getDecisionBadge(item: CrossAnalysisItem) {
    if (item.detectionCount >= 2) {
        return {
            label: '동시 탐지',
            className: 'bg-red-50 text-red-600 border-red-200',
        };
    }

    return {
        label: '단독 탐지',
        className: 'bg-amber-50 text-amber-600 border-amber-200',
    };
}

export default function StageCrossAnalysis({
    items,
    title = '교차 검증 결과',
}: StageCrossAnalysisProps) {
    const [showAllCross, setShowAllCross] = useState(false);
    const [showAllLlm, setShowAllLlm] = useState(false);
    const [expandedRows, setExpandedRows] = useState<Record<string | number, boolean>>({});

    if (!items || items.length === 0) return null;

    const llmItems = items.filter((item) => item.llmJudgment);

    const truePositiveCount = llmItems.filter(
        (item) => item.llmJudgment?.judgment === 'TRUE_POSITIVE'
    ).length;

    const falsePositiveCount = llmItems.filter(
        (item) => item.llmJudgment?.judgment === 'FALSE_POSITIVE'
    ).length;

    const uncertainCount = llmItems.filter(
        (item) => item.llmJudgment?.judgment === 'UNCERTAIN'
    ).length;

    const toolA = items[0]?.tools?.[0] ?? 'Tool A';
    const toolB = items[0]?.tools?.[1] ?? 'Tool B';

    const visibleCrossItems = showAllCross ? items : items.slice(0, 2);
    const visibleLlmItems = showAllLlm ? llmItems : llmItems.slice(0, 2);

    const toggleRow = (id: string | number) => {
        setExpandedRows((prev) => ({
            ...prev,
            [id]: !prev[id],
        }));
    };

    return (
        <div className="space-y-4">
            {/* 1. 비교 결과 블록 */}
            <div className="bg-card rounded-lg border border-border shadow-sm p-4">
                <div className="flex items-center justify-between mb-3 gap-3">
                    <h3 className="text-sm font-semibold text-foreground">
                        {title} · {toolA.toUpperCase()} vs {toolB.toUpperCase()}
                    </h3>

                    {items.length > 2 && (
                        <button
                            type="button"
                            onClick={() => setShowAllCross((prev) => !prev)}
                            className="shrink-0 px-2.5 py-1 text-[11px] font-medium rounded-md border border-border bg-background hover:bg-muted transition-colors"
                        >
                            {showAllCross ? '접기' : `더보기 (${items.length - 2})`}
                        </button>
                    )}
                </div>

                <div className="rounded-md border border-border overflow-hidden">
                    {/* 헤더 */}
                    <div className="hidden md:grid grid-cols-[120px_1.4fr_110px_110px_90px_90px] bg-muted/60 text-xs font-semibold text-muted-foreground">
                        <div className="px-4 py-3">결과</div>
                        <div className="px-4 py-3">취약점 / 설명</div>
                        <div className="px-4 py-3 text-center">{toolA.toUpperCase()}</div>
                        <div className="px-4 py-3 text-center">{toolB.toUpperCase()}</div>
                        <div className="px-4 py-3 text-center">심각도</div>
                        <div className="px-4 py-3 text-center">상세</div>
                    </div>

                    {/* 행 */}
                    {visibleCrossItems.map((item, index) => {
                        const decision = getDecisionBadge(item);
                        const isExpanded = !!expandedRows[item.id];
                        const toolAFound = item.tools.includes(toolA);
                        const toolBFound = item.tools.includes(toolB);

                        return (
                            <div
                                key={item.id}
                                className={index !== visibleCrossItems.length - 1 ? 'border-t border-border' : ''}
                            >
                                {/* desktop */}
                                <div className="hidden md:grid grid-cols-[120px_1.4fr_110px_110px_90px_90px] items-center text-sm">
                                    <div className="px-4 py-3">
                                        <span
                                            className={`inline-flex px-3 py-1 rounded-md border text-xs font-semibold ${decision.className}`}
                                        >
                                            {decision.label}
                                        </span>
                                    </div>

                                    <div className="px-4 py-3 min-w-0">
                                        <div className="font-medium text-foreground">{item.category}</div>
                                        <div className="text-xs text-muted-foreground truncate mt-1">
                                            {item.description}
                                        </div>
                                    </div>

                                    <div className="px-4 py-3 text-center">
                                        <span
                                            className={`inline-flex min-w-[58px] justify-center px-2 py-1 rounded-md text-xs font-semibold border ${toolAFound
                                                ? 'bg-blue-50 text-blue-700 border-blue-200'
                                                : 'bg-slate-50 text-slate-400 border-slate-200'
                                                }`}
                                        >
                                            {toolAFound ? '탐지' : '-'}
                                        </span>
                                    </div>

                                    <div className="px-4 py-3 text-center">
                                        <span
                                            className={`inline-flex min-w-[58px] justify-center px-2 py-1 rounded-md text-xs font-semibold border ${toolBFound
                                                ? 'bg-blue-50 text-blue-700 border-blue-200'
                                                : 'bg-slate-50 text-slate-400 border-slate-200'
                                                }`}
                                        >
                                            {toolBFound ? '탐지' : '-'}
                                        </span>
                                    </div>

                                    <div className="px-4 py-3 text-center">
                                        <span
                                            className={`inline-flex px-2 py-1 rounded-md border text-xs font-medium ${getSeverityClass(
                                                item.severity
                                            )}`}
                                        >
                                            {item.severity}
                                        </span>
                                    </div>

                                    <div className="px-4 py-3 text-center">
                                        <button
                                            type="button"
                                            onClick={() => toggleRow(item.id)}
                                            className="inline-flex items-center gap-1 px-2 py-1 rounded-md border border-border text-xs font-medium hover:bg-muted transition-colors"
                                        >
                                            {isExpanded ? '접기' : '보기'}
                                            {isExpanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                                        </button>
                                    </div>
                                </div>

                                {/* mobile */}
                                <div className="md:hidden p-4 space-y-3">
                                    <div className="flex items-start justify-between gap-3">
                                        <div>
                                            <div className="font-medium text-foreground">{item.category}</div>
                                            <div className="text-xs text-muted-foreground mt-1">
                                                {item.description}
                                            </div>
                                        </div>

                                        <span
                                            className={`inline-flex px-2.5 py-1 rounded-md border text-[11px] font-semibold ${decision.className}`}
                                        >
                                            {decision.label}
                                        </span>
                                    </div>

                                    <div className="flex flex-wrap gap-2">
                                        <span
                                            className={`inline-flex px-2 py-1 rounded-md border text-xs font-semibold ${toolAFound
                                                ? 'bg-blue-50 text-blue-700 border-blue-200'
                                                : 'bg-slate-50 text-slate-400 border-slate-200'
                                                }`}
                                        >
                                            {toolA.toUpperCase()}: {toolAFound ? '탐지' : '-'}
                                        </span>

                                        <span
                                            className={`inline-flex px-2 py-1 rounded-md border text-xs font-semibold ${toolBFound
                                                ? 'bg-blue-50 text-blue-700 border-blue-200'
                                                : 'bg-slate-50 text-slate-400 border-slate-200'
                                                }`}
                                        >
                                            {toolB.toUpperCase()}: {toolBFound ? '탐지' : '-'}
                                        </span>

                                        <span
                                            className={`inline-flex px-2 py-1 rounded-md border text-xs font-medium ${getSeverityClass(
                                                item.severity
                                            )}`}
                                        >
                                            {item.severity}
                                        </span>
                                    </div>

                                    <div>
                                        <button
                                            type="button"
                                            onClick={() => toggleRow(item.id)}
                                            className="inline-flex items-center gap-1 px-2 py-1 rounded-md border border-border text-xs font-medium hover:bg-muted transition-colors"
                                        >
                                            {isExpanded ? '상세 접기' : '상세 보기'}
                                            {isExpanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                                        </button>
                                    </div>
                                </div>

                                {/* 공통 상세 */}
                                {isExpanded && (
                                    <div className="px-4 pb-4">
                                        <div className="rounded-md bg-muted/40 border border-border p-3">
                                            <div className="text-xs font-semibold text-foreground mb-2">
                                                상세 설명
                                            </div>
                                            <div className="text-sm text-muted-foreground leading-6">
                                                {item.description}
                                            </div>
                                        </div>
                                    </div>
                                )}
                            </div>
                        );
                    })}
                </div>
            </div>

            {/* 2. LLM 판정 결과 블록 */}
            {llmItems.length > 0 && (
                <div className="rounded-lg border border-border bg-white p-4 shadow-sm">
                    {/* 헤더 */}
                    <div className="flex items-center justify-between mb-4 gap-3">
                        <div className="flex items-center gap-2">
                            <span className="inline-flex px-2.5 py-1 rounded-md bg-blue-600 text-white text-xs font-semibold">
                                LLM 판정
                            </span>
                            <h4 className="text-sm font-semibold text-foreground">판정 결과 요약</h4>
                            {/* <span className="inline-flex px-2 py-1 rounded-md bg-purple-100 text-purple-700 text-xs font-semibold">
                                GPT·Gemini 일치율 100%
                            </span> */}
                        </div>

                        {llmItems.length > 2 && (
                            <button
                                type="button"
                                onClick={() => setShowAllLlm((prev) => !prev)}
                                className="shrink-0 px-2.5 py-1 text-[11px] font-medium rounded-md border border-green-200 bg-white hover:bg-green-50 transition-colors"
                            >
                                {showAllLlm ? '접기' : `더보기 (${llmItems.length - 2})`}
                            </button>
                        )}
                    </div>

                    {/* 요약 카드 */}
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mb-4">
                        <div className="rounded-lg border border-green-200 bg-white p-3 shadow-sm">
                            <div className="text-xs text-muted-foreground mb-1">실제 취약점</div>
                            <div className="text-2xl font-bold text-green-700">{truePositiveCount}</div>
                        </div>

                        <div className="rounded-lg border border-red-200 bg-white p-3 shadow-sm">
                            <div className="text-xs text-muted-foreground mb-1">오탐</div>
                            <div className="text-2xl font-bold text-red-600">{falsePositiveCount}</div>
                        </div>

                        <div className="rounded-lg border border-blue-200 bg-white p-3 shadow-sm">
                            <div className="text-xs text-muted-foreground mb-1">검토 필요</div>
                            <div className="text-2xl font-bold text-blue-700">{uncertainCount}</div>
                        </div>
                    </div>

                    {/* 항목 리스트 */}
                    <div className="space-y-3">
                        {visibleLlmItems.map((item) => (
                            <div
                                key={item.id}
                                className="rounded-lg border border-white/70 bg-white p-4 shadow-sm"
                            >
                                <div className="grid grid-cols-1 md:grid-cols-[120px_1fr] gap-4">
                                    <div>
                                        <div
                                            className={`text-sm font-bold ${getJudgmentClass(
                                                item.llmJudgment!.judgment
                                            )}`}
                                        >
                                            {getJudgmentLabel(item.llmJudgment!.judgment)}
                                        </div>
                                        <div className="mt-2">
                                            <span className="inline-flex px-2 py-1 rounded-md text-xs font-medium bg-slate-100 text-slate-700">
                                                신뢰도 {item.llmJudgment!.confidence}%
                                            </span>
                                        </div>
                                    </div>

                                    <div>
                                        <div className="text-sm font-semibold text-foreground mb-1">
                                            {item.category}
                                        </div>
                                        <div className="text-sm text-muted-foreground leading-6">
                                            {item.llmJudgment!.reasoning}
                                        </div>
                                        {/* <div className="mt-3 text-sm text-blue-700 font-medium">
                                            → 조치 필요 여부를 우선 검토하세요
                                        </div> */}
                                    </div>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            )}
        </div>
    );
}