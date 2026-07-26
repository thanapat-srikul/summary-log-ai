"use client";

import { FormEvent, useCallback, useEffect, useMemo, useState } from "react";

type User = { id:string; email:string; display_name?:string; displayName?:string; role:"admin"|"analyst"|"viewer"; active?:boolean };
type Source = { id:string; name:string; state?:string; active:boolean; last_seen_at?:string; spool_backlog:number; accepted?:number; rejected?:number };
type Incident = { id:string; detected_at:string; source_name:string; src_ip:string; dst_ip:string; dst_port:number; protocol:string; score:number; severity:"Medium"|"High"|"Critical"; status:string; reason:string; suggested_action:string };
type Snapshot = { generatedAt:number; cursor:number; totals:{flows:number;bytes:number;failed:number;anomalies:number;incidents:number}; timeline:Array<{bucketTs:number;flows:number;anomalies:number}>; severity:Record<string,number>; riskyHosts:Array<{ip:string;score:number;connections:number}>; incidents:Incident[]; sources:Source[] };
type Tab = "overview"|"incidents"|"sources"|"allowlist"|"users"|"settings";
const empty:Snapshot={generatedAt:0,cursor:0,totals:{flows:0,bytes:0,failed:0,anomalies:0,incidents:0},timeline:[],severity:{Critical:0,High:0,Medium:0},riskyHosts:[],incidents:[],sources:[]};
const nf=new Intl.NumberFormat("th-TH");
const bytes=(n:number)=>n>=1e9?`${(n/1e9).toFixed(2)} GB`:n>=1e6?`${(n/1e6).toFixed(1)} MB`:n>=1e3?`${(n/1e3).toFixed(1)} KB`:`${n} B`;

async function json(url:string, init?:RequestInit) {
  const headers:Record<string,string>={...(init?.headers as Record<string,string>|undefined)};
  if(init?.body!==undefined) headers["Content-Type"]="application/json";
  const response=await fetch(url,{...init,headers});
  const body=await response.json().catch(()=>({}));
  if(!response.ok) throw new Error(body.message||body.error||"request_failed");
  return body;
}

function AuthScreen({mode,onDone}:{mode:"setup"|"login";onDone:()=>void}) {
  const [error,setError]=useState("");
  const [busy,setBusy]=useState(false);
  async function submit(event:FormEvent<HTMLFormElement>) {
    event.preventDefault();setBusy(true);setError("");
    const data=Object.fromEntries(new FormData(event.currentTarget));
    try {
      await json(mode==="setup"?"/api/v1/setup":"/api/v1/auth/login",{method:"POST",body:JSON.stringify(data)});
      if(mode==="setup") await json("/api/v1/auth/login",{method:"POST",body:JSON.stringify({email:data.email,password:data.password})});
      onDone();
    } catch(e){setError(e instanceof Error?e.message:"เกิดข้อผิดพลาด");}finally{setBusy(false);}
  }
  return <main className="auth-page"><section className="auth-card"><a href="/" className="auth-brand"><span>SL</span><strong>Summary Log AI</strong></a><p className="console-kicker">{mode==="setup"?"FIRST-TIME SETUP":"SECURE CONSOLE"}</p><h1>{mode==="setup"?"ตั้งค่าระบบครั้งแรก":"เข้าสู่ระบบ"}</h1><p>{mode==="setup"?"สร้างองค์กรและบัญชีผู้ดูแลระบบ ข้อมูลทั้งหมดจะอยู่บนเซิร์ฟเวอร์นี้":"ใช้บัญชีที่ผู้ดูแลระบบสร้างให้"}</p><form onSubmit={submit}>
    {mode==="setup"&&<><label>ชื่อองค์กร<input name="organizationName" required maxLength={100}/></label><label>ชื่อผู้ดูแล<input name="displayName" required maxLength={100}/></label><label>เขตเวลา<input name="timezone" defaultValue="Asia/Bangkok" required/></label></>}
    <label>อีเมล<input name="email" type="email" required autoComplete="username"/></label><label>รหัสผ่าน<input name="password" type="password" minLength={12} required autoComplete={mode==="setup"?"new-password":"current-password"}/></label>
    {error&&<div className="form-error">{error}</div>}<button className="primary-action" disabled={busy}>{busy?"กำลังดำเนินการ…":mode==="setup"?"สร้างระบบ":"เข้าสู่ Console"}</button>
  </form><small>Summary Log AI v0.1.0 · Self-hosted</small></section></main>;
}

export default function ProductConsole(){
  const [phase,setPhase]=useState<"loading"|"setup"|"login"|"ready"|"unavailable">("loading");
  const [user,setUser]=useState<User|null>(null);
  const [csrf,setCsrf]=useState("");
  const [tab,setTab]=useState<Tab>("overview");
  const [snapshot,setSnapshot]=useState(empty);
  const [allowlist,setAllowlist]=useState<any[]>([]);
  const [users,setUsers]=useState<User[]>([]);
  const [settings,setSettings]=useState<any>({});
  const [secret,setSecret]=useState("");
  const [message,setMessage]=useState("");
  const mutate=useCallback((url:string,method:string,body?:unknown)=>json(url,{method,headers:{"x-csrf-token":csrf},body:body===undefined?undefined:JSON.stringify(body)}),[csrf]);
  const boot=useCallback(async()=>{
    try{
      const status=await json("/api/v1/setup/status");
      if(!status.configured){setPhase("setup");return;}
      const auth=await json("/api/v1/auth/me");
      setUser(auth.user);setCsrf(auth.csrfToken);setPhase("ready");
    }catch(e){setPhase(e instanceof Error&&e.message==="authentication_required"?"login":"unavailable");}
  },[]);
  const refresh=useCallback(async()=>{
    if(phase!=="ready")return;
    try{
      const [snap,a,u,s]=await Promise.all([json("/api/v1/dashboard/snapshot?minutes=15"),json("/api/v1/allowlist"),json("/api/v1/users"),json("/api/v1/settings")]);
      setSnapshot(snap);setAllowlist(a.entries);setUsers(u.users);setSettings(s.settings);
    }catch(e){if(e instanceof Error&&e.message==="authentication_required")setPhase("login");}
  },[phase]);
  useEffect(()=>{boot();},[boot]);
  useEffect(()=>{refresh();},[refresh]);
  useEffect(()=>{
    if(phase!=="ready")return;
    const stream=new EventSource(`/api/v1/stream?cursor=${snapshot.cursor}`);
    stream.addEventListener("update",()=>refresh());
    const timer=setInterval(refresh,15000);
    return()=>{stream.close();clearInterval(timer);};
  },[phase,refresh,snapshot.cursor]);
  const max=Math.max(1,...snapshot.timeline.map(x=>x.anomalies));
  const isAdmin=user?.role==="admin";
  const canWrite=user?.role!=="viewer";
  async function submitSource(e:FormEvent<HTMLFormElement>){e.preventDefault();const data=Object.fromEntries(new FormData(e.currentTarget));const out=await mutate("/api/v1/sources","POST",data);setSecret(`SOURCE_ID=${out.source.id}\nSUMMARY_LOG_INGEST_KEY=${out.apiKey}`);e.currentTarget.reset();refresh();}
  async function submitAllowlist(e:FormEvent<HTMLFormElement>){e.preventDefault();const data=Object.fromEntries(new FormData(e.currentTarget));await mutate("/api/v1/allowlist","POST",data);e.currentTarget.reset();refresh();}
  async function submitUser(e:FormEvent<HTMLFormElement>){e.preventDefault();await mutate("/api/v1/users","POST",Object.fromEntries(new FormData(e.currentTarget)));e.currentTarget.reset();refresh();}
  async function saveSettings(e:FormEvent<HTMLFormElement>){e.preventDefault();const data=Object.fromEntries(new FormData(e.currentTarget));await mutate("/api/v1/settings","PATCH",{...data,retentionDays:Number(data.retentionDays),smtpPort:Number(data.smtpPort),smtpSecure:data.smtpSecure==="on",alertRecipients:String(data.alertRecipients||"").split(",").map(x=>x.trim()).filter(Boolean)});setMessage("บันทึกการตั้งค่าแล้ว");refresh();}
  if(phase==="loading")return <main className="auth-page"><div className="console-loader">กำลังตรวจสอบระบบ…</div></main>;
  if(phase==="unavailable")return <main className="auth-page"><section className="auth-card"><a href="/" className="auth-brand"><span>SL</span><strong>Summary Log AI</strong></a><p className="console-kicker">SELF-HOSTED CONSOLE</p><h1>Console ต้องติดตั้งในระบบของคุณ</h1><p>หน้านี้เป็นเว็บไซต์สาธารณะ สำหรับใช้งาน Dashboard จริงให้ดาวน์โหลดชุดติดตั้ง Docker Compose และเปิด <code>/app</code> บนเซิร์ฟเวอร์ขององค์กร</p><a className="primary-action auth-action-link" href="/#install">ดูวิธีติดตั้ง</a></section></main>;
  if(phase==="setup"||phase==="login")return <AuthScreen mode={phase} onDone={boot}/>;
  return <main className="console-shell">
    <aside className="console-sidebar"><a href="/" className="console-brand"><span>SL</span><div><strong>Summary Log AI</strong><small>SELF-HOSTED v0.1.0</small></div></a><nav>
      {([["overview","ภาพรวม"],["incidents","Incidents"],["sources","Sources"],["allowlist","Allowlist"],["users","ผู้ใช้งาน"],["settings","ตั้งค่าระบบ"]] as [Tab,string][]).map(([key,label])=><button key={key} className={tab===key?"active":""} onClick={()=>setTab(key)}><i />{label}</button>)}
    </nav><div className="console-user"><span>{user?.displayName?.[0]||user?.email[0]}</span><div><strong>{user?.displayName||user?.email}</strong><small>{user?.role}</small></div><button onClick={async()=>{await mutate("/api/v1/auth/logout","POST");setPhase("login");}}>ออก</button></div></aside>
    <section className="console-main"><header><div><p className="console-kicker">SECURITY OPERATIONS</p><h1>{tab==="overview"?"ภาพรวมเครือข่าย":tab==="incidents"?"Incident queue":tab==="sources"?"Zeek Sources":tab==="allowlist"?"Allowlist":tab==="users"?"ผู้ใช้งาน":"ตั้งค่าระบบ"}</h1></div><div className="live-state"><i /> LIVE <span>{new Date(snapshot.generatedAt).toLocaleTimeString("th-TH")}</span></div></header>
      {tab==="overview"&&<div className="console-stack"><section className="console-kpi-grid"><Kpi label="Network flows" value={nf.format(snapshot.totals.flows)} note={bytes(snapshot.totals.bytes)}/><Kpi label="Failed" value={nf.format(snapshot.totals.failed)} note="connections"/><Kpi label="Anomalies" value={nf.format(snapshot.totals.anomalies)} note="rule matches" tone="amber"/><Kpi label="Incidents" value={nf.format(snapshot.totals.incidents)} note="all statuses" tone="red"/></section>
      <section className="console-grid"><article className="console-panel"><PanelHead kicker="ANOMALY ACTIVITY" title="เหตุการณ์ 15 นาทีล่าสุด"/><div className="console-bars">{(snapshot.timeline.length?snapshot.timeline:Array.from({length:15},(_,i)=>({bucketTs:i,flows:0,anomalies:0}))).map((x,i)=><div key={i}><i style={{height:`${Math.max(x.anomalies?5:1,x.anomalies/max*100)}%`}}/><span>{x.bucketTs>1000&&i%3===0?new Date(x.bucketTs).toLocaleTimeString("th-TH",{hour:"2-digit",minute:"2-digit"}):""}</span></div>)}</div></article>
      <article className="console-panel"><PanelHead kicker="SOURCE HEALTH" title="สถานะ Collector"/><div className="source-health">{snapshot.sources.map(s=><div key={s.id}><i className={s.state}/><strong>{s.name}</strong><span>{s.state||"offline"}</span><small>spool {s.spool_backlog||0}</small></div>)}{!snapshot.sources.length&&<Empty text="ยังไม่มี Source — เพิ่ม Source ในเมนู Sources"/>}</div></article></section>
      <article className="console-panel"><PanelHead kicker="PRIORITY QUEUE" title="Incident ล่าสุด"/><IncidentTable rows={snapshot.incidents.slice(0,8)} canWrite={canWrite} mutate={mutate} refresh={refresh}/></article></div>}
      {tab==="incidents"&&<article className="console-panel"><IncidentTable rows={snapshot.incidents} canWrite={canWrite} mutate={mutate} refresh={refresh}/></article>}
      {tab==="sources"&&<div className="console-stack">{isAdmin&&<article className="console-panel form-panel"><PanelHead kicker="NEW COLLECTOR" title="เพิ่ม Zeek Source"/><form className="inline-form" onSubmit={submitSource}><label>ชื่อ Source<input name="name" placeholder="เช่น Bangkok Gateway" required/></label><button className="primary-action">สร้าง Source และ API key</button></form>{secret&&<div className="one-time-secret"><b>คัดลอกตอนนี้ — ระบบจะไม่แสดงอีก</b><pre>{secret}</pre></div>}</article>}<section className="cards-grid">{snapshot.sources.map(s=><article className="source-admin-card" key={s.id}><div><i className={s.state}/><strong>{s.name}</strong></div><dl><div><dt>สถานะ</dt><dd>{s.state}</dd></div><div><dt>Spool</dt><dd>{s.spool_backlog||0}</dd></div></dl><small>{s.last_seen_at?`ล่าสุด ${new Date(s.last_seen_at).toLocaleString("th-TH")}`:"ยังไม่เคยรับข้อมูล"}</small>{isAdmin&&<button onClick={async()=>{const out=await mutate(`/api/v1/sources/${s.id}/rotate-key`,"POST");setSecret(`SOURCE_ID=${s.id}\nSUMMARY_LOG_INGEST_KEY=${out.apiKey}`);}}>ออก API key ใหม่</button>}</article>)}</section></div>}
      {tab==="allowlist"&&<div className="console-stack">{canWrite&&<article className="console-panel form-panel"><PanelHead kicker="TRUST POLICY" title="เพิ่ม Allowlist"/><form className="settings-grid" onSubmit={submitAllowlist}><label>Source<select name="sourceId"><option value="">ทุก Source</option>{snapshot.sources.map(s=><option key={s.id} value={s.id}>{s.name}</option>)}</select></label><label>IP / CIDR<input name="cidr" placeholder="192.168.1.0/24"/></label><label>Port<input name="port" type="number" min="1" max="65535"/></label><label>Protocol<select name="protocol"><option value="">ทั้งหมด</option><option>tcp</option><option>udp</option><option>icmp</option></select></label><label className="wide">คำอธิบาย<input name="description" required placeholder="เหตุผลที่อนุญาต"/></label><button className="primary-action">เพิ่ม Allowlist</button></form></article>}<article className="console-panel"><table><thead><tr><th>Source</th><th>CIDR</th><th>Port</th><th>Protocol</th><th>คำอธิบาย</th><th /></tr></thead><tbody>{allowlist.map(x=><tr key={x.id}><td>{x.source_name||"ทุก Source"}</td><td>{x.cidr||"—"}</td><td>{x.port||"—"}</td><td>{x.protocol||"—"}</td><td>{x.description}</td><td>{canWrite&&<button className="danger-link" onClick={async()=>{await mutate(`/api/v1/allowlist/${x.id}`,"DELETE");refresh();}}>ลบ</button>}</td></tr>)}</tbody></table>{!allowlist.length&&<Empty text="ยังไม่มี Allowlist"/>}</article></div>}
      {tab==="users"&&<div className="console-stack">{isAdmin&&<article className="console-panel form-panel"><PanelHead kicker="ACCESS CONTROL" title="สร้างบัญชีผู้ใช้"/><form className="settings-grid" onSubmit={submitUser}><label>ชื่อ<input name="displayName" required/></label><label>อีเมล<input name="email" type="email" required/></label><label>รหัสผ่านชั่วคราว<input name="password" type="password" minLength={12} required/></label><label>Role<select name="role"><option value="analyst">Analyst</option><option value="viewer">Viewer</option><option value="admin">Admin</option></select></label><button className="primary-action">สร้างบัญชี</button></form></article>}<article className="console-panel"><table><thead><tr><th>ชื่อ</th><th>อีเมล</th><th>Role</th><th>สถานะ</th></tr></thead><tbody>{users.map(x=><tr key={x.id}><td>{x.display_name}</td><td>{x.email}</td><td><span className="role-pill">{x.role}</span></td><td>{x.active===false?"ปิด":"ใช้งาน"}</td></tr>)}</tbody></table></article></div>}
      {tab==="settings"&&<article className="console-panel form-panel"><PanelHead kicker="SYSTEM & ALERTING" title="องค์กร การจัดเก็บ และ SMTP"/>{!isAdmin?<Empty text="เฉพาะ Admin เท่านั้นที่แก้การตั้งค่าได้"/>:<form className="settings-grid" onSubmit={saveSettings}><label>ชื่อองค์กร<input name="name" defaultValue={settings.name}/></label><label>Timezone<input name="timezone" defaultValue={settings.timezone}/></label><label>Retention (วัน)<input name="retentionDays" type="number" min="1" max="3650" defaultValue={settings.retention_days||30}/></label><label>SMTP Host<input name="smtpHost" defaultValue={settings.smtp_host||""}/></label><label>SMTP Port<input name="smtpPort" type="number" defaultValue={settings.smtp_port||465}/></label><label>SMTP Username<input name="smtpUsername" defaultValue={settings.smtp_username||""}/></label><label>SMTP Password<input name="smtpPassword" type="password" placeholder={settings.smtp_password_set?"ตั้งค่าไว้แล้ว":"กรอกรหัสผ่าน"}/></label><label>From<input name="smtpFrom" type="email" defaultValue={settings.smtp_from||""}/></label><label className="wide">ผู้รับ (คั่นด้วย comma)<input name="alertRecipients" defaultValue={(settings.alert_recipients||[]).join(", ")}/></label><label>แจ้งเตือนขั้นต่ำ<select name="alertMinSeverity" defaultValue={settings.alert_min_severity||"High"}><option>Medium</option><option>High</option><option>Critical</option></select></label><label>Cooldown (นาที)<input name="alertCooldownMinutes" type="number" min="1" defaultValue={settings.alert_cooldown_minutes||15}/></label><label className="check-label"><input name="smtpSecure" type="checkbox" defaultChecked={settings.smtp_secure!==false}/> ใช้ TLS</label><button className="primary-action">บันทึกการตั้งค่า</button>{message&&<span className="success-message">{message}</span>}</form>}</article>}
    </section>
  </main>;
}

function Kpi({label,value,note,tone=""}:{label:string;value:string;note:string;tone?:string}){return <article className={`console-kpi ${tone}`}><small>{label}</small><strong>{value}</strong><span>{note}</span></article>}
function PanelHead({kicker,title}:{kicker:string;title:string}){return <div className="console-panel-head"><div><small>{kicker}</small><h2>{title}</h2></div></div>}
function Empty({text}:{text:string}){return <div className="console-empty">{text}</div>}
function IncidentTable({rows,canWrite,mutate,refresh}:{rows:Incident[];canWrite:boolean;mutate:(u:string,m:string,b?:unknown)=>Promise<any>;refresh:()=>void}){return <div className="table-wrap"><table><thead><tr><th>เวลา</th><th>เส้นทาง</th><th>เหตุผล</th><th>Severity</th><th>Score</th><th>สถานะ</th></tr></thead><tbody>{rows.map(x=><tr key={x.id}><td>{new Date(x.detected_at).toLocaleString("th-TH")}</td><td><strong>{x.src_ip}</strong><small>→ {x.dst_ip}:{x.dst_port}/{x.protocol}</small></td><td className="reason-cell">{x.reason}</td><td><span className={`severity severity-${x.severity.toLowerCase()}`}>{x.severity}</span></td><td><b>{x.score}</b></td><td>{canWrite?<select value={x.status} onChange={async e=>{await mutate(`/api/v1/incidents/${x.id}`,"PATCH",{status:e.target.value});refresh();}}><option value="new">New</option><option value="acknowledged">Acknowledged</option><option value="investigating">Investigating</option><option value="resolved">Resolved</option></select>:x.status}</td></tr>)}</tbody></table>{!rows.length&&<Empty text="ยังไม่มี Incident ในระบบ"/>}</div>}
