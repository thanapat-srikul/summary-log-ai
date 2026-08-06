export type ConnEvent = {
  uid:string; ts:number; orig_h:string; orig_p:number; resp_h:string; resp_p:number; proto:string;
  service?:string|null; conn_state:string; duration?:number|null; orig_bytes:number; resp_bytes:number; orig_pkts:number; resp_pkts:number;
};

export type HostWindow = { connectionCount:number; uniqueDestinations:number; failedCount:number; byteCount:number; uncommonPortCount:number; maxDurationMs:number; maxFlowBytes:number };
export type RuleThreshold = { minimum?:number; count?:number; ratio?:number; ports?:number[] };
export type RuleConfig = { code:string; enabled:boolean; points:number; cooldownMinutes:number; threshold:RuleThreshold; scope:"default"|"source" };
export type BaselineThreshold = { value:number; status:"learning"|"ready"|"stale"|"insufficient_data"; sampleCount:number };
export type RuleMatch = { code:string; points:number; label:string; actual:number; threshold:number; unit:string; configuredThreshold:number; baselineThreshold:number|null; thresholdSource:"default"|"source"|"baseline"; cooldownMinutes:number; suppressed?:boolean };
export type RuleResult = { score:number; severity:"Low"|"Medium"|"High"|"Critical"; codes:string[]; reason:string; action:string; matches:RuleMatch[] };

const standardPorts=[20,21,22,25,53,67,68,80,110,123,143,161,389,443,445,465,587,636,993,995,1433,3306,3389,5432,6379,8080,8443];
export const RULE_DEFINITIONS:Record<string,Omit<RuleConfig,"scope"> & { label:string; description:string }>={
  HIGH_CONNECTION_RATE:{code:"HIGH_CONNECTION_RATE",enabled:true,points:25,cooldownMinutes:10,threshold:{minimum:100},label:"Connections per minute",description:"จำนวนการเชื่อมต่อจาก Source IP ในหนึ่งนาที"},
  MANY_DESTINATIONS:{code:"MANY_DESTINATIONS",enabled:true,points:25,cooldownMinutes:10,threshold:{minimum:25},label:"Unique destinations",description:"จำนวนปลายทางที่ Source IP ติดต่อในหนึ่งนาที"},
  HIGH_FAILURE_RATIO:{code:"HIGH_FAILURE_RATIO",enabled:true,points:30,cooldownMinutes:10,threshold:{count:10,ratio:.5},label:"Failed connection ratio",description:"จำนวนและสัดส่วนการเชื่อมต่อที่ล้มเหลว"},
  HIGH_TRANSFER_VOLUME:{code:"HIGH_TRANSFER_VOLUME",enabled:true,points:25,cooldownMinutes:10,threshold:{minimum:100*1024*1024},label:"Transfer per minute",description:"ปริมาณข้อมูลรวมต่อหนึ่งนาที"},
  UNCOMMON_PORT:{code:"UNCOMMON_PORT",enabled:true,points:10,cooldownMinutes:10,threshold:{ports:standardPorts},label:"Uncommon destination port",description:"พอร์ตปลายทางที่ไม่อยู่ในรายการมาตรฐาน"},
  LONG_CONNECTION:{code:"LONG_CONNECTION",enabled:true,points:10,cooldownMinutes:10,threshold:{minimum:300_000},label:"Longest connection",description:"ระยะเวลาการเชื่อมต่อสูงสุด"},
  LARGE_SINGLE_FLOW:{code:"LARGE_SINGLE_FLOW",enabled:true,points:20,cooldownMinutes:10,threshold:{minimum:50*1024*1024},label:"Largest single flow",description:"ขนาดข้อมูลของ Flow เดี่ยว"},
  INCIDENT_THRESHOLD:{code:"INCIDENT_THRESHOLD",enabled:true,points:0,cooldownMinutes:10,threshold:{minimum:45},label:"Incident threshold",description:"คะแนนขั้นต่ำสำหรับสร้าง Incident"},
};

export function defaultRuleConfigs():Record<string,RuleConfig>{return Object.fromEntries(Object.entries(RULE_DEFINITIONS).map(([code,row])=>[code,{code,enabled:row.enabled,points:row.points,cooldownMinutes:row.cooldownMinutes,threshold:structuredClone(row.threshold),scope:"default"}]))}
export function severityForScore(score:number):RuleResult["severity"]{if(score>=90)return"Critical";if(score>=70)return"High";if(score>=45)return"Medium";return"Low";}
function effective(configured:number,baseline?:BaselineThreshold){if(!baseline||baseline.status!=="ready")return{value:configured};return{value:Math.min(configured*4,Math.max(configured,baseline.value))};}

export function evaluateRules(window:HostWindow,event:ConnEvent,configs:Record<string,RuleConfig>=defaultRuleConfigs(),baselines:Record<string,BaselineThreshold>={}):RuleResult{
  let score=0;const codes:string[]=[];const reasons:string[]=[];const actions=new Set<string>();const matches:RuleMatch[]=[];
  const add=(code:string,actual:number,configuredThreshold:number,threshold:number,unit:string,reason:string,action:string,baseline:BaselineThreshold|undefined)=>{const config=configs[code]||defaultRuleConfigs()[code];if(!config.enabled)return;score+=config.points;codes.push(code);reasons.push(reason);actions.add(action);matches.push({code,points:config.points,label:RULE_DEFINITIONS[code].label,actual,threshold,unit,configuredThreshold,baselineThreshold:baseline?.status==="ready"?baseline.value:null,thresholdSource:threshold>configuredThreshold?"baseline":config.scope,cooldownMinutes:config.cooldownMinutes});};
  const c=configs.HIGH_CONNECTION_RATE||defaultRuleConfigs().HIGH_CONNECTION_RATE;const ct=Number(c.threshold.minimum??100);const ce=effective(ct,baselines.HIGH_CONNECTION_RATE);if(c.enabled&&window.connectionCount>=ce.value)add(c.code,window.connectionCount,ct,ce.value,"connections","มีการเชื่อมต่อสูงกว่าค่าปกติ","ตรวจสอบ process และปลายทางที่อุปกรณ์ติดต่อ",baselines[c.code]);
  const d=configs.MANY_DESTINATIONS||defaultRuleConfigs().MANY_DESTINATIONS;const dt=Number(d.threshold.minimum??25);const de=effective(dt,baselines.MANY_DESTINATIONS);if(d.enabled&&window.uniqueDestinations>=de.value)add(d.code,window.uniqueDestinations,dt,de.value,"destinations","ติดต่อปลายทางจำนวนมากผิดปกติ","ตรวจสอบรูปแบบ port scan หรือ service discovery",baselines[d.code]);
  const f=configs.HIGH_FAILURE_RATIO||defaultRuleConfigs().HIGH_FAILURE_RATIO;const fc=Number(f.threshold.count??10);const fr=Number(f.threshold.ratio??.5);const fe=effective(fc,baselines.HIGH_FAILURE_RATIO);const ratio=window.failedCount/Math.max(1,window.connectionCount);if(f.enabled&&window.failedCount>=fe.value&&ratio>=fr)add(f.code,ratio*100,fr*100,fr*100,"%","การเชื่อมต่อล้มเหลวสูงกว่าปกติ","ตรวจสอบ authentication และ firewall log",baselines[f.code]);
  const t=configs.HIGH_TRANSFER_VOLUME||defaultRuleConfigs().HIGH_TRANSFER_VOLUME;const tt=Number(t.threshold.minimum??100*1024*1024);const te=effective(tt,baselines.HIGH_TRANSFER_VOLUME);if(t.enabled&&window.byteCount>=te.value)add(t.code,window.byteCount,tt,te.value,"bytes","ถ่ายโอนข้อมูลรวมสูงกว่าปกติ","ยืนยันชนิดข้อมูลและปลายทางที่รับส่งข้อมูล",baselines[t.code]);
  const p=configs.UNCOMMON_PORT||defaultRuleConfigs().UNCOMMON_PORT;const ports=Array.isArray(p.threshold.ports)?p.threshold.ports:standardPorts;if(p.enabled&&(window.uncommonPortCount>0||!ports.includes(event.resp_p)))add(p.code,event.resp_p,0,0,"port","พบการเชื่อมต่อผ่านพอร์ตนอกกลุ่มมาตรฐาน","ยืนยันว่าบริการบนพอร์ตดังกล่าวได้รับอนุญาต",undefined);
  const l=configs.LONG_CONNECTION||defaultRuleConfigs().LONG_CONNECTION;const lt=Number(l.threshold.minimum??300_000);const le=effective(lt,baselines.LONG_CONNECTION);if(l.enabled&&window.maxDurationMs>=le.value)add(l.code,window.maxDurationMs,lt,le.value,"ms","พบการเชื่อมต่อนานผิดปกติ","ตรวจสอบ session ที่ค้างและ application log",baselines[l.code]);
  const g=configs.LARGE_SINGLE_FLOW||defaultRuleConfigs().LARGE_SINGLE_FLOW;const gt=Number(g.threshold.minimum??50*1024*1024);const ge=effective(gt,baselines.LARGE_SINGLE_FLOW);if(g.enabled&&window.maxFlowBytes>=ge.value)add(g.code,window.maxFlowBytes,gt,ge.value,"bytes","Flow เดียวมีข้อมูลขนาดใหญ่","ตรวจสอบไฟล์หรือข้อมูลที่ถูกถ่ายโอน",baselines[g.code]);
  score=Math.min(100,score);return{score,severity:severityForScore(score),codes,matches,reason:reasons.join("; ")||"ไม่พบเงื่อนไขความเสี่ยงที่เกินเกณฑ์",action:[...actions].join("; ")||"ติดตามพฤติกรรมของอุปกรณ์ต่อไป"};
}

export function incidentThreshold(configs:Record<string,RuleConfig>){return Number((configs.INCIDENT_THRESHOLD||defaultRuleConfigs().INCIDENT_THRESHOLD).threshold.minimum??45)}
export function validateEvent(value:unknown):value is ConnEvent{if(!value||typeof value!=="object")return false;const row=value as Record<string,unknown>;return typeof row.uid==="string"&&row.uid.length>0&&row.uid.length<=128&&typeof row.ts==="number"&&Number.isFinite(row.ts)&&typeof row.orig_h==="string"&&typeof row.resp_h==="string"&&Number.isInteger(row.orig_p)&&Number.isInteger(row.resp_p)&&typeof row.proto==="string"&&typeof row.conn_state==="string"&&["orig_bytes","resp_bytes","orig_pkts","resp_pkts"].every(key=>Number.isInteger(row[key])&&Number(row[key])>=0)}
