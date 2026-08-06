import { defaultRuleConfigs, RULE_DEFINITIONS, type RuleConfig, type RuleThreshold } from "./rules.js";

export type StoredRuleConfig={rule_code:string;source_id:string|null;enabled:boolean;points:number;cooldown_minutes:number;threshold:RuleThreshold};

export function mergeRuleConfigs(defaultRows:StoredRuleConfig[],sourceRows:StoredRuleConfig[]=[]):Record<string,RuleConfig>{
  const configs=defaultRuleConfigs();
  for(const row of [...defaultRows,...sourceRows]){
    if(!RULE_DEFINITIONS[row.rule_code])continue;
    configs[row.rule_code]={code:row.rule_code,enabled:row.enabled,points:Number(row.points),cooldownMinutes:Number(row.cooldown_minutes),threshold:row.threshold,scope:row.source_id?"source":"default"};
  }
  return configs;
}

export function validateRuleUpdate(code:string,value:unknown):{enabled:boolean;points:number;cooldownMinutes:number;threshold:RuleThreshold}|null{
  if(!RULE_DEFINITIONS[code]||!value||typeof value!=="object")return null;
  const row=value as Record<string,unknown>;const enabled=row.enabled!==false;const points=Number(row.points);const cooldownMinutes=Number(row.cooldownMinutes);const threshold=(row.threshold||{}) as RuleThreshold;
  if(!Number.isInteger(points)||points<0||points>100||!Number.isInteger(cooldownMinutes)||cooldownMinutes<1||cooldownMinutes>1440)return null;
  if(code==="UNCOMMON_PORT"){
    if(!Array.isArray(threshold.ports)||threshold.ports.some(port=>!Number.isInteger(Number(port))||Number(port)<1||Number(port)>65535))return null;
    return{enabled,points,cooldownMinutes,threshold:{ports:[...new Set(threshold.ports.map(Number))].sort((a,b)=>a-b)}};
  }
  if(code==="HIGH_FAILURE_RATIO"){
    const count=Number(threshold.count),ratio=Number(threshold.ratio);if(!Number.isFinite(count)||count<1||!Number.isFinite(ratio)||ratio<=0||ratio>1)return null;
    return{enabled,points,cooldownMinutes,threshold:{count,ratio}};
  }
  const minimum=Number(threshold.minimum);if(!Number.isFinite(minimum)||minimum<0||code==="INCIDENT_THRESHOLD"&&minimum>100)return null;
  return{enabled,points,cooldownMinutes,threshold:{minimum}};
}

export function robustSuggestedThreshold(p95:number,mad:number){return Math.max(0,Math.ceil(p95+3*mad));}
export function effectiveThreshold(configured:number,suggested:number,status:string){return status==="ready"?Math.min(configured*4,Math.max(configured,suggested)):configured;}
