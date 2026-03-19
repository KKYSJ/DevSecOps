interface StageIsmsDetailItem {
    id: string | number;
    code: string;
    title: string;
    status: 'satisfied' | 'unsatisfied' | 'review';
    description: string;
    gap?: string;
}

interface StageIsmsDetailProps {
    items: StageIsmsDetailItem[];
    title?: string;
}

function getStatusStyle(status: StageIsmsDetailItem['status']) {
    if (status === 'satisfied') {
        return {
            label: '충족',
            className: 'bg-emerald-50 text-emerald-700 border-emerald-200',
        };
    }

    if (status === 'unsatisfied') {
        return {
            label: '미충족',
            className: 'bg-red-50 text-red-700 border-red-200',
        };
    }

    return {
        label: '검토 필요',
        className: 'bg-amber-50 text-amber-700 border-amber-200',
    };
}

export default function StageIsmsDetail({
    items,
    title = '단계별 ISMS-P 상세',
}: StageIsmsDetailProps) {
    if (!items || items.length === 0) return null;

    return (
        <div className="bg-card rounded-lg border border-border shadow-sm p-4">
            <div className="mb-4">
                <h3 className="text-sm font-semibold text-foreground">{title}</h3>
                <p className="text-xs text-muted-foreground mt-1">
                    현재 단계에서 충족/미충족되는 ISMS-P 연관 항목 상세입니다.
                </p>
            </div>

            <div className="space-y-3">
                {items.map((item) => {
                    const status = getStatusStyle(item.status);

                    return (
                        <div
                            key={item.id}
                            className="rounded-lg border border-border bg-background p-4"
                        >
                            <div className="flex items-start justify-between gap-3 mb-2">
                                <div>
                                    <div className="text-xs text-muted-foreground">{item.code}</div>
                                    <div className="text-sm font-semibold text-foreground mt-1">
                                        {item.title}
                                    </div>
                                </div>

                                <span
                                    className={`inline-flex px-2.5 py-1 rounded-md border text-xs font-semibold ${status.className}`}
                                >
                                    {status.label}
                                </span>
                            </div>

                            <div className="text-sm text-muted-foreground leading-6">
                                {item.description}
                            </div>

                            {item.gap && (
                                <div className="mt-3 rounded-md border border-red-200 bg-red-50 px-3 py-2">
                                    <div className="text-xs font-semibold text-red-700 mb-1">보완 필요</div>
                                    <div className="text-xs text-red-700">{item.gap}</div>
                                </div>
                            )}
                        </div>
                    );
                })}
            </div>
        </div>
    );
}