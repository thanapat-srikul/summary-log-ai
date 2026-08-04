export type ConnEvent = {
  uid: string; ts: number; orig_h: string; orig_p: number; resp_h: string; resp_p: number;
  proto: string; service?: string | null; conn_state: string; duration?: number | null;
  orig_bytes: number; resp_bytes: number; orig_pkts: number; resp_pkts: number;
};

export type HostWindow = {
  connectionCount: number; uniqueDestinations: number; failedCount: number; byteCount: number;
  uncommonPortCount: number; maxDurationMs: number; maxFlowBytes: number;
};

export type RuleMatch = {
  code: string; points: number; label: string; actual: number; threshold: number; unit: string;
};

export type RuleResult = {
  score: number; severity: "Low" | "Medium" | "High" | "Critical"; codes: string[];
  reason: string; action: string; matches: RuleMatch[];
};

const standardPorts = new Set([20,21,22,25,53,67,68,80,110,123,143,161,389,443,445,465,587,636,993,995,1433,3306,3389,5432,6379,8080,8443]);

export function severityForScore(score: number): RuleResult["severity"] {
  if (score >= 90) return "Critical";
  if (score >= 70) return "High";
  if (score >= 45) return "Medium";
  return "Low";
}

export function evaluateRules(window: HostWindow, event: ConnEvent): RuleResult {
  let score = 0;
  const codes: string[] = [];
  const reasons: string[] = [];
  const actions = new Set<string>();
  const matches: RuleMatch[] = [];
  const add = (points: number, code: string, reason: string, action: string, label: string, actual: number, threshold: number, unit: string) => {
    score += points; codes.push(code); reasons.push(reason); actions.add(action);
    matches.push({ code, points, label, actual, threshold, unit });
  };

  if (window.connectionCount >= 100) add(25,"HIGH_CONNECTION_RATE","มีการเชื่อมต่ออย่างน้อย 100 ครั้งต่อนาที","ตรวจสอบ process และปลายทางที่อุปกรณ์ติดต่อ","Connections per minute",window.connectionCount,100,"connections");
  if (window.uniqueDestinations >= 25) add(25,"MANY_DESTINATIONS","ติดต่อปลายทางอย่างน้อย 25 แห่งในหนึ่งนาที","ตรวจสอบรูปแบบ port scan หรือ service discovery","Unique destinations",window.uniqueDestinations,25,"destinations");
  const failedRatio = window.failedCount / Math.max(1, window.connectionCount);
  if (window.failedCount >= 10 && failedRatio >= .5) add(30,"HIGH_FAILURE_RATIO","การเชื่อมต่อล้มเหลวอย่างน้อย 10 ครั้งและมากกว่าครึ่งหนึ่ง","ตรวจสอบ authentication และ firewall log","Failed connection ratio",failedRatio*100,50,"%");
  if (window.byteCount >= 100*1024*1024) add(25,"HIGH_TRANSFER_VOLUME","ถ่ายโอนข้อมูลรวมอย่างน้อย 100 MB ต่อนาที","ยืนยันชนิดข้อมูลและปลายทางที่รับส่งข้อมูล","Transfer per minute",window.byteCount,100*1024*1024,"bytes");
  if (window.uncommonPortCount > 0 || !standardPorts.has(event.resp_p)) add(10,"UNCOMMON_PORT","พบการเชื่อมต่อผ่านพอร์ตนอกกลุ่มมาตรฐาน","ยืนยันว่าบริการบนพอร์ตดังกล่าวได้รับอนุญาต","Uncommon destination port",event.resp_p,0,"port");
  if (window.maxDurationMs >= 300_000) add(10,"LONG_CONNECTION","พบการเชื่อมต่อนานอย่างน้อย 300 วินาที","ตรวจสอบ session ที่ค้างและ application log","Longest connection",window.maxDurationMs,300_000,"ms");
  if (window.maxFlowBytes >= 50*1024*1024) add(20,"LARGE_SINGLE_FLOW","Flow เดียวมีข้อมูลอย่างน้อย 50 MB","ตรวจสอบไฟล์หรือข้อมูลที่ถูกถ่ายโอน","Largest single flow",window.maxFlowBytes,50*1024*1024,"bytes");

  score = Math.min(100, score);
  return { score, severity: severityForScore(score), codes, matches,
    reason: reasons.join("; ") || "ไม่พบเงื่อนไขความเสี่ยงที่เกินเกณฑ์",
    action: [...actions].join("; ") || "ติดตามพฤติกรรมของอุปกรณ์ต่อไป" };
}

export function validateEvent(value: unknown): value is ConnEvent {
  if (!value || typeof value !== "object") return false;
  const row = value as Record<string, unknown>;
  return typeof row.uid === "string" && row.uid.length > 0 && row.uid.length <= 128
    && typeof row.ts === "number" && Number.isFinite(row.ts)
    && typeof row.orig_h === "string" && typeof row.resp_h === "string"
    && Number.isInteger(row.orig_p) && Number.isInteger(row.resp_p)
    && typeof row.proto === "string" && typeof row.conn_state === "string"
    && ["orig_bytes","resp_bytes","orig_pkts","resp_pkts"].every((key) => Number.isInteger(row[key]) && Number(row[key]) >= 0);
}
