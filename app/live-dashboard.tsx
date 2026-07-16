"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";

type Severity = "Critical" | "High" | "Medium" | "Low";
type Mode = "live" | "demo";
type View = "dashboard" | "incidents" | "sources";
type ConnectionState = "connecting" | "live" | "reconnecting" | "offline";

type ApiIncident = {
  id: string; detected_at: number; src_ip: string; dst_ip: string; dst_port: number;
  protocol: string; score: number; severity: Severity; reason: string; action: string;
  status: string; byte_count: number; packet_count: number;
};
type Snapshot = {
  generatedAt: number; cursor: number; window: string;
  totals: { flows: number; bytes: number; anomalies: number; highCritical: number; riskyHosts: number };
  timeline: Array<{ bucketTs: number; flows: number; anomalies: number }>;
  severity: Record<Severity, number>;
  riskyHosts: Array<{ ip: string; score: number; connections: number; lastSeenAt: number }>;
  incidents: ApiIncident[];
  sources: Array<{ id: string; name: string; lastSeenAt: number; state: "live" | "offline"; accepted: number; rejected: number; spoolBacklog: number }>;
};

const emptySnapshot: Snapshot = {
  generatedAt: 0, cursor: 0, window: "15m",
  totals: { flows: 0, bytes: 0, anomalies: 0, highCritical: 0, riskyHosts: 0 },
  timeline: [], severity: { Critical: 0, High: 0, Medium: 0, Low: 0 },
  riskyHosts: [], incidents: [], sources: [],
};

const demoSnapshot: Snapshot = {
  generatedAt: Date.now(), cursor: 0, window: "demo",
  totals: { flows: 128420, bytes: 4_820_000_000, anomalies: 247, highCritical: 61, riskyHosts: 34 },
  timeline: [18,24,21,42,35,61,48,77,52,86,63,71].map((anomalies, i) => ({ bucketTs: Date.now() - (11-i)*60000, flows: anomalies*17, anomalies })),
  severity: { Critical: 18, High: 43, Medium: 91, Low: 95 },
  riskyHosts: [
    { ip: "192.168.1.24", score: 94, connections: 15842, lastSeenAt: Date.now() },
    { ip: "192.168.1.71", score: 87, connections: 4218, lastSeenAt: Date.now() },
    { ip: "10.10.4.12", score: 82, connections: 1806, lastSeenAt: Date.now() },
    { ip: "192.168.2.89", score: 73, connections: 9320, lastSeenAt: Date.now() },
  ],
  incidents: [
    { id:"DEMO-0247", detected_at:Date.now()-120000, src_ip:"192.168.1.24", dst_ip:"10.0.0.8", dst_port:443, protocol:"tcp", score:94, severity:"Critical", reason:"Connection และปริมาณข้อมูลสูงผิดปกติในหนึ่งนาที", action:"ตรวจสอบ process ต้นทางและจำกัดการเชื่อมต่อชั่วคราว", status:"รอตรวจสอบ", byte_count:1_840_000_000, packet_count:15842 },
    { id:"DEMO-0246", detected_at:Date.now()-320000, src_ip:"192.168.1.71", dst_ip:"8.8.8.8", dst_port:53, protocol:"udp", score:87, severity:"High", reason:"ติดต่อปลายทางจำนวนมากในช่วงเวลาสั้น", action:"ตรวจสอบ DNS history และปลายทางของอุปกรณ์", status:"กำลังตรวจสอบ", byte_count:38_200_000, packet_count:4218 },
    { id:"DEMO-0245", detected_at:Date.now()-610000, src_ip:"10.10.4.12", dst_ip:"172.16.0.31", dst_port:22, protocol:"tcp", score:82, severity:"High", reason:"พบการเชื่อมต่อล้มเหลวซ้ำจากต้นทางเดียวกัน", action:"ตรวจสอบบัญชีผู้ใช้และ authentication log", status:"รอตรวจสอบ", byte_count:6_100_000, packet_count:1806 },
  ],
  sources: [],
};

const nf = new Intl.NumberFormat("th-TH");
const compact = new Intl.NumberFormat("th-TH", { notation: "compact", maximumFractionDigits: 1 });
function bytes(value: number) {
  if (value >= 1e9) return `${(value/1e9).toFixed(2)} GB`;
  if (value >= 1e6) return `${(value/1e6).toFixed(1)} MB`;
  if (value >= 1e3) return `${(value/1e3).toFixed(1)} KB`;
  return `${value} B`;
}
function clock(value: number) { return value ? new Date(value).toLocaleTimeString("th-TH", { hour:"2-digit", minute:"2-digit", second:"2-digit" }) : "—"; }
function age(value: number) {
  if (!value) return "ยังไม่เคยได้รับข้อมูล";
  const seconds = Math.max(0, Math.round((Date.now()-value)/1000));
  return seconds < 5 ? "เมื่อสักครู่" : seconds < 60 ? `${seconds} วินาทีที่แล้ว` : `${Math.floor(seconds/60)} นาทีที่แล้ว`;
}

function Badge({ severity }: { severity: Severity }) { return <span className={`severity severity-${severity.toLowerCase()}`}>{severity}</span>; }
function Kpi({ label, value, note, tone="" }: { label:string; value:string; note:string; tone?:string }) {
  return <article className={`kpi-card ${tone ? `kpi-${tone}` : ""}`}><div className="kpi-topline"><span>{label}</span><i /></div><strong>{value}</strong><small>{note}</small></article>;
}

function StatusStrip({ mode, state, snapshot }: { mode:Mode; state:ConnectionState; snapshot:Snapshot }) {
  const latest = snapshot.sources[0]?.lastSeenAt ?? 0;
  const label = mode === "demo" ? "Demo" : state === "live" ? "Live" : state === "reconnecting" ? "Reconnecting" : state === "connecting" ? "Connecting" : "Collector offline";
  return <section className={`notice-strip live-strip state-${state}`}>
    <div className="pulse-dot" />
    <div><strong>{label}</strong><span>{mode === "demo" ? "ข้อมูลตัวอย่าง ไม่รวมกับข้อมูลจริง" : `event ล่าสุด: ${age(latest)}`}</span></div>
    <span className="notice-source">{mode === "demo" ? "DEMO DATASET" : snapshot.sources[0]?.name ?? "รอ Python Collector"}</span>
  </section>;
}

function Dashboard({ snapshot, mode, state, openIncident }: { snapshot:Snapshot; mode:Mode; state:ConnectionState; openIncident:(row:ApiIncident)=>void }) {
  const maxAnomalies = Math.max(1, ...snapshot.timeline.map(row => row.anomalies));
  const totalSeverity = Object.values(snapshot.severity).reduce((a,b)=>a+b,0);
  return <div className="page-stack">
    <section className="page-heading"><div><p className="eyebrow"><span /> SECURITY OPERATIONS OVERVIEW</p><h1>ภาพรวมเครือข่าย</h1><p>สรุป Zeek conn.log แบบใกล้เคียงเวลาจริง โดยไม่จัดเก็บ Raw Log</p></div><div className="engine-badge"><span>{mode === "live" ? "RULE ENGINE" : "DEMO ENGINE"}</span><small>หน้าต่างวิเคราะห์ 1 นาที · เก็บผลสรุป 7 วัน</small></div></section>
    <StatusStrip mode={mode} state={state} snapshot={snapshot} />
    <section className="kpi-grid">
      <Kpi label="Network flows" value={nf.format(snapshot.totals.flows)} note={`ปริมาณข้อมูล ${bytes(snapshot.totals.bytes)}`} />
      <Kpi label="Anomalies" value={nf.format(snapshot.totals.anomalies)} note="เหตุการณ์ที่ผ่าน Rule Engine" tone="amber" />
      <Kpi label="High / Critical" value={nf.format(snapshot.totals.highCritical)} note="ควรตรวจสอบเพิ่มเติม" tone="red" />
      <Kpi label="Risky hosts" value={nf.format(snapshot.totals.riskyHosts)} note="Source IP ที่มีคะแนน ≥ 45" tone="violet" />
    </section>
    {mode === "live" && snapshot.totals.flows === 0 ? <section className="panel live-empty"><span>◎</span><h2>ยังไม่มีข้อมูลจริง</h2><p>เริ่ม Python Collector แล้วเพิ่มบรรทัดใน conn.log ข้อมูลจะปรากฏที่นี่ภายในประมาณ 1–2 วินาที</p></section> : null}
    <section className="dashboard-grid">
      <article className="panel timeline-panel"><div className="panel-heading"><div><span className="panel-kicker">ANOMALY ACTIVITY</span><h2>เหตุการณ์ตามช่วงเวลา</h2></div></div>
        <div className="chart-shell"><div className="chart-y"><span>{maxAnomalies}</span><span>{Math.round(maxAnomalies*.75)}</span><span>{Math.round(maxAnomalies*.5)}</span><span>{Math.round(maxAnomalies*.25)}</span><span>0</span></div><div className="bar-chart live-bars">
          {(snapshot.timeline.length ? snapshot.timeline.slice(-12) : Array.from({length:12},(_,i)=>({bucketTs:i,flows:0,anomalies:0}))).map((row,i)=><div className="bar-column" key={`${row.bucketTs}-${i}`}><div className="bar-track"><span style={{height:`${Math.max(row.anomalies ? 4 : 0,(row.anomalies/maxAnomalies)*100)}%`}} title={`${row.anomalies} anomalies`} /></div><small>{row.bucketTs > 1000 && i%2===0 ? clock(row.bucketTs).slice(0,5) : ""}</small></div>)}
        </div></div>
      </article>
      <article className="panel severity-panel"><div className="panel-heading"><div><span className="panel-kicker">RISK DISTRIBUTION</span><h2>ระดับความรุนแรง</h2></div></div><div className="severity-content"><div className="donut"><div><strong>{totalSeverity}</strong><span>Incidents</span></div></div><div className="severity-list">{(["Critical","High","Medium","Low"] as Severity[]).map(s=><div key={s}><span className={`swatch ${s.toLowerCase()}`} /><span>{s}</span><strong>{snapshot.severity[s]}</strong></div>)}</div></div></article>
    </section>
    <section className="dashboard-grid lower-grid">
      <article className="panel risky-panel"><div className="panel-heading"><div><span className="panel-kicker">TOP ENTITIES</span><h2>Host ที่มีความเสี่ยงสูง</h2></div></div><div className="risk-list">{snapshot.riskyHosts.slice(0,5).map((host,i)=><div className="risk-row" key={host.ip}><span className="rank">{String(i+1).padStart(2,"0")}</span><div><strong>{host.ip}</strong><small>{compact.format(host.connections)} connections</small></div><div className="risk-score"><span style={{width:`${host.score}%`}} /><b>{host.score}</b></div></div>)}{!snapshot.riskyHosts.length && <div className="empty-state">ยังไม่พบ Host ที่มีความเสี่ยง</div>}</div></article>
      <article className="panel incident-panel"><div className="panel-heading"><div><span className="panel-kicker">PRIORITY QUEUE</span><h2>Incident ล่าสุด</h2></div></div><div className="compact-incidents">{snapshot.incidents.slice(0,5).map(row=><button key={row.id} className="compact-incident" onClick={()=>openIncident(row)}><span className={`incident-signal signal-${row.severity.toLowerCase()}`} /><div><strong>{row.src_ip}</strong><small>{row.reason}</small></div><div className="compact-meta"><Badge severity={row.severity} /><time>{clock(row.detected_at)}</time></div></button>)}{!snapshot.incidents.length && <div className="empty-state">ยังไม่มี Incident</div>}</div></article>
    </section>
  </div>;
}

function Incidents({ snapshot, openIncident }: { snapshot:Snapshot; openIncident:(row:ApiIncident)=>void }) {
  const [query,setQuery] = useState(""); const [severity,setSeverity] = useState("All");
  const rows = snapshot.incidents.filter(row => (severity === "All" || row.severity === severity) && `${row.src_ip} ${row.dst_ip} ${row.reason}`.toLowerCase().includes(query.toLowerCase()));
  return <div className="page-stack"><section className="page-heading"><div><p className="eyebrow"><span /> INCIDENT QUEUE</p><h1>เหตุการณ์ที่ตรวจพบ</h1><p>กรองและเปิดดูเหตุผล หลักฐาน และคำแนะนำจาก Rule Engine</p></div></section><section className="panel table-panel"><div className="table-tools"><label className="search-box"><span>⌕</span><input value={query} onChange={e=>setQuery(e.target.value)} placeholder="ค้นหา IP หรือเหตุผล" /></label><label className="filter-label">Severity<select value={severity} onChange={e=>setSeverity(e.target.value)}><option>All</option><option>Critical</option><option>High</option><option>Medium</option></select></label></div><div className="table-scroll"><table><thead><tr><th>เวลา</th><th>เส้นทาง</th><th>Protocol</th><th>Score</th><th>Severity</th><th /></tr></thead><tbody>{rows.map(row=><tr key={row.id}><td>{clock(row.detected_at)}</td><td><div className="route-cell"><strong>{row.src_ip}</strong><i>→</i><span>{row.dst_ip}:{row.dst_port}</span></div></td><td><span className="protocol-pill">{row.protocol.toUpperCase()}</span></td><td>{row.score}</td><td><Badge severity={row.severity} /></td><td><button className="row-button" onClick={()=>openIncident(row)}>→</button></td></tr>)}</tbody></table>{!rows.length && <div className="empty-state">ไม่พบ Incident ตามตัวกรอง</div>}</div></section></div>;
}

function Sources({ snapshot }: { snapshot:Snapshot }) {
  return <div className="page-stack"><section className="page-heading"><div><p className="eyebrow"><span /> SOURCE HEALTH</p><h1>สถานะแหล่งข้อมูล</h1><p>ดู last seen และผลการรับข้อมูลของ Zeek Collector ในหน้าต่าง 15 นาที</p></div></section><section className="source-grid">{snapshot.sources.map(source=><article className="panel source-card" key={source.id}><div><span className={`source-state ${source.state}`} /> <strong>{source.name}</strong></div><dl><div><dt>สถานะ</dt><dd>{source.state === "live" ? "Live" : "Collector offline"}</dd></div><div><dt>Last seen</dt><dd>{age(source.lastSeenAt)}</dd></div><div><dt>Accepted</dt><dd>{nf.format(source.accepted)}</dd></div><div><dt>Rejected / duplicate</dt><dd>{nf.format(source.rejected)}</dd></div><div><dt>Spool backlog</dt><dd>{nf.format(source.spoolBacklog)}</dd></div></dl><p>Backlog จะถูกส่งซ้ำอัตโนมัติเมื่อเชื่อมต่อกลับมา</p></article>)}{!snapshot.sources.length && <section className="panel live-empty"><h2>ยังไม่พบ Collector</h2><p>ตั้งค่าไฟล์ collector/.env แล้วรัน zeek_collector.py เพื่อเริ่มส่งข้อมูล</p></section>}</section></div>;
}

function Drawer({ incident, close }: { incident:ApiIncident; close:()=>void }) {
  return <div className="drawer-backdrop" onMouseDown={e=>{if(e.target===e.currentTarget)close();}}><aside className="incident-drawer"><div className="drawer-header"><div><span>INCIDENT DETAIL</span><h2>{incident.id}</h2></div><button onClick={close}>×</button></div><div className="drawer-score"><div><span>Risk score</span><strong>{incident.score}</strong><small>/ 100</small></div><Badge severity={incident.severity} /></div><div className="route-visual"><div><small>SOURCE</small><strong>{incident.src_ip}</strong></div><span>→</span><div><small>DESTINATION</small><strong>{incident.dst_ip}:{incident.dst_port}</strong></div></div><section className="drawer-section"><span className="panel-kicker">REASON</span><h3>เหตุผลที่ถูกตรวจจับ</h3><p>{incident.reason}</p></section><div className="evidence-grid"><div><span>Protocol</span><strong>{incident.protocol.toUpperCase()}</strong></div><div><span>Packets</span><strong>{nf.format(incident.packet_count)}</strong></div><div><span>Bytes</span><strong>{bytes(incident.byte_count)}</strong></div><div><span>Status</span><strong>{incident.status}</strong></div></div><section className="drawer-section recommendation"><span className="panel-kicker">SUGGESTED ACTION</span><h3>แนวทางดำเนินการ</h3><p>{incident.action}</p></section><p className="drawer-disclaimer">ผลนี้มาจาก Rule Engine สำหรับห้องทดลอง ควรตรวจสอบหลักฐานเพิ่มเติมก่อนดำเนินการ</p></aside></div>;
}

export default function LiveDashboard() {
  const [mode,setMode] = useState<Mode>("live"); const [view,setView] = useState<View>("dashboard");
  const [live,setLive] = useState<Snapshot>(emptySnapshot); const [state,setState] = useState<ConnectionState>("connecting");
  const [selected,setSelected] = useState<ApiIncident|null>(null); const cursor = useRef(0); const reconnects = useRef(0); const timer = useRef<ReturnType<typeof setTimeout>|null>(null); const stream = useRef<EventSource|null>(null);
  const fetchSnapshot = useCallback(async()=>{ const response=await fetch("/api/snapshot?window=15m",{cache:"no-store"}); if(!response.ok) throw new Error("snapshot unavailable"); const next=await response.json() as Snapshot; cursor.current=next.cursor; setLive(next); return next; },[]);
  useEffect(()=>{ if(mode!=="live") { stream.current?.close(); if(timer.current) clearTimeout(timer.current); return; } let cancelled=false;
    const connect=async()=>{ if(cancelled)return; try{ setState(reconnects.current ? "reconnecting":"connecting"); await fetchSnapshot(); if(cancelled)return; const es=new EventSource(`/api/stream?cursor=${cursor.current}`); stream.current=es; es.addEventListener("open",()=>{reconnects.current=0;setState("live");}); es.addEventListener("update",()=>{void fetchSnapshot().catch(()=>setState("reconnecting"));}); es.addEventListener("reconnect",()=>es.close()); es.onerror=()=>{es.close(); if(cancelled)return; setState(live.sources.length ? "reconnecting":"offline"); const delay=Math.min(10000,1000*2**reconnects.current++); timer.current=setTimeout(connect,delay);}; }catch{ if(cancelled)return; setState("offline"); const delay=Math.min(10000,1000*2**reconnects.current++); timer.current=setTimeout(connect,delay); }}; void connect(); return()=>{cancelled=true;stream.current?.close();if(timer.current)clearTimeout(timer.current);};
  // The cursor is carried by the stream URL; state updates happen through fetchSnapshot.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  },[mode,fetchSnapshot]);
  const snapshot=mode==="demo"?demoSnapshot:live; const latest=useMemo(()=>snapshot.sources[0]?.lastSeenAt??0,[snapshot]);
  const displayState:ConnectionState=mode==="live"&&state==="live"&&!snapshot.sources.some(source=>source.state==="live")?"offline":state;
  return <div className="app-shell"><aside className="sidebar"><div className="brand"><div className="app-mark"><span className="mark-ring"/><span className="mark-dot"/></div><div><strong>SUMMARY LOG</strong><span>AI MONITOR</span></div></div><nav><button className={view==="dashboard"?"active":""} onClick={()=>setView("dashboard")}><b>OV</b><span>ภาพรวม</span></button><button className={view==="incidents"?"active":""} onClick={()=>setView("incidents")}><b>IN</b><span>เหตุการณ์</span><em>{snapshot.incidents.length}</em></button><button className={view==="sources"?"active":""} onClick={()=>setView("sources")}><b>SH</b><span>Source Health</span></button></nav><div className="mode-switch"><span>DATA MODE</span><div><button className={mode==="live"?"active":""} onClick={()=>setMode("live")}>Live</button><button className={mode==="demo"?"active":""} onClick={()=>setMode("demo")}>Demo</button></div><small>{mode==="live"?`ล่าสุด ${age(latest)}`:"ข้อมูลสาธิตเท่านั้น"}</small></div></aside><main><header className="mobile-header"><strong>SUMMARY LOG AI</strong><span className={`mobile-status state-${displayState}`}>{mode==="demo"?"Demo":displayState}</span></header><div className="mobile-nav"><button onClick={()=>setView("dashboard")}>ภาพรวม</button><button onClick={()=>setView("incidents")}>เหตุการณ์</button><button onClick={()=>setView("sources")}>Source Health</button><button onClick={()=>setMode(mode==="live"?"demo":"live")}>{mode==="live"?"Demo mode":"Live mode"}</button></div><div className="page-wrap">{view==="dashboard"&&<Dashboard snapshot={snapshot} mode={mode} state={displayState} openIncident={setSelected}/>} {view==="incidents"&&<Incidents snapshot={snapshot} openIncident={setSelected}/>} {view==="sources"&&<Sources snapshot={snapshot}/>}</div><footer><span>Summary Log AI · Zeek near-real-time lab monitor</span><span>Raw logs are not retained</span></footer></main>{selected&&<Drawer incident={selected} close={()=>setSelected(null)}/>}</div>;
}
