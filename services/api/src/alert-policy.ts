export const ALERT_GROUP_WINDOW_MS = 5 * 60 * 1000;
export const ALERT_EMAIL_ITEM_LIMIT = 50;
export const ALERT_MAX_ATTEMPTS = 6;

export type AlertSeverity = "Medium" | "High" | "Critical";

export function alertWindow(value: Date) {
  const startMs = Math.floor(value.getTime() / ALERT_GROUP_WINDOW_MS) * ALERT_GROUP_WINDOW_MS;
  return { start: new Date(startMs), end: new Date(startMs + ALERT_GROUP_WINDOW_MS) };
}

export function severityRank(value: string) {
  return value === "Critical" ? 3 : value === "High" ? 2 : value === "Medium" ? 1 : 0;
}

export function highestSeverity(left: AlertSeverity | null, right: AlertSeverity) {
  return !left || severityRank(right) > severityRank(left) ? right : left;
}

export function severityMeetsMinimum(value: string, minimum: string) {
  return severityRank(value) >= severityRank(minimum || "High");
}

export function retryDelayMinutes(attempt: number) {
  return Math.min(60, 2 ** Math.max(1, attempt));
}
