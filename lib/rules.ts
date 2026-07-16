import type { ZeekConnEvent } from "./zeek";

export type HostWindow = { connectionCount:number; uniqueDestinations:number; byteCount:number; packetCount:number; failedCount:number; maxDurationMs:number; maxFlowBytes:number; uncommonPortCount:number };
export type Severity = "Low" | "Medium" | "High" | "Critical";
export type RuleResult = { score:number; severity:Severity; codes:string[]; reason:string; action:string };

const COMMON_PORTS = new Set([22, 53, 80, 123, 443]);
export function isUncommonPort(port:number) { return !COMMON_PORTS.has(port); }
export function severityForScore(score:number): Severity { if(score>=90)return "Critical"; if(score>=70)return "High"; if(score>=45)return "Medium"; return "Low"; }

export function evaluateRules(window:HostWindow, representative:ZeekConnEvent):RuleResult {
  let score=0; const codes:string[]=[]; const reasons:string[]=[]; const actions:string[]=[];
  const add=(points:number,code:string,reason:string,action:string)=>{score+=points;codes.push(code);reasons.push(reason);actions.push(action);};
  if(window.connectionCount>=100)add(25,"HIGH_CONNECTION_RATE","พบการเชื่อมต่ออย่างน้อย 100 ครั้งต่อนาที","ตรวจสอบ process และปลายทางที่อุปกรณ์ติดต่อ");
  if(window.uniqueDestinations>=25)add(25,"MANY_DESTINATIONS","ติดต่อปลายทางอย่างน้อย 25 แห่งในหนึ่งนาที","ตรวจสอบรูปแบบ port scan หรือ service discovery");
  const failureRatio=window.connectionCount?window.failedCount/window.connectionCount:0;
  if(window.failedCount>=10&&failureRatio>=.5)add(30,"HIGH_FAILURE_RATIO","การเชื่อมต่อล้มเหลวอย่างน้อย 10 ครั้งและคิดเป็นอย่างน้อย 50%","ตรวจสอบ authentication และ firewall log");
  if(window.byteCount>=100*1024*1024)add(25,"HIGH_TRANSFER_VOLUME","ปริมาณข้อมูลรวมอย่างน้อย 100 MB ต่อนาที","ตรวจสอบชนิดข้อมูลและยืนยันปลายทางที่รับส่งข้อมูล");
  if(window.uncommonPortCount>0||isUncommonPort(representative.resp_p))add(10,"UNCOMMON_PORT","พบการเชื่อมต่อผ่านพอร์ตนอกกลุ่มมาตรฐาน","ยืนยันว่าบริการบนพอร์ตดังกล่าวได้รับอนุญาต");
  if(window.maxDurationMs>=300_000)add(10,"LONG_CONNECTION","พบการเชื่อมต่อนานอย่างน้อย 300 วินาที","ตรวจสอบ session ที่ค้างและ application log");
  if(window.maxFlowBytes>=50*1024*1024)add(20,"LARGE_SINGLE_FLOW","Flow เดี่ยวมีปริมาณข้อมูลอย่างน้อย 50 MB","ตรวจสอบไฟล์หรือข้อมูลที่มีการถ่ายโอน");
  score=Math.min(100,score);
  return {score,severity:severityForScore(score),codes,reason:reasons.join("; ")||"ไม่พบเงื่อนไขความเสี่ยงที่เกินเกณฑ์",action:[...new Set(actions)].join("; ")||"ติดตามพฤติกรรมของอุปกรณ์ต่อไป"};
}

export function flowBytes(event:ZeekConnEvent){return event.orig_bytes+event.resp_bytes;}
export function flowPackets(event:ZeekConnEvent){return event.orig_pkts+event.resp_pkts;}
