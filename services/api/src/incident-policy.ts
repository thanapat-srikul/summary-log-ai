export type IncidentStatus = "new" | "acknowledged" | "investigating" | "resolved";

const nextStatus: Record<IncidentStatus, IncidentStatus | null> = {
  new: "acknowledged",
  acknowledged: "investigating",
  investigating: "resolved",
  resolved: null,
};

export function canTransition(from: IncidentStatus, to: IncidentStatus) {
  return nextStatus[from] === to;
}

export function shouldMerge(lastSeenAt: Date, observedAt: Date, windowMinutes = 10) {
  const delta = observedAt.getTime() - lastSeenAt.getTime();
  return delta >= 0 && delta <= windowMinutes * 60_000;
}

export function severityRank(severity: string) {
  return { Low: 0, Medium: 1, High: 2, Critical: 3 }[severity] ?? -1;
}
