"use client";

import { ChangeEvent, useMemo, useRef, useState } from "react";

type PageKey = "dashboard" | "analyze" | "incidents" | "performance";
type Severity = "Critical" | "High" | "Medium" | "Low";

type Incident = {
  id: string;
  time: string;
  source: string;
  destination: string;
  protocol: string;
  port: number;
  score: number;
  severity: Severity;
  state: string;
  reason: string;
  action: string;
  packets: number;
  bytes: string;
};

const navItems: Array<{ key: PageKey; label: string; kicker: string }> = [
  { key: "dashboard", label: "ภาพรวม", kicker: "OV" },
  { key: "analyze", label: "วิเคราะห์ Log", kicker: "AN" },
  { key: "incidents", label: "เหตุการณ์", kicker: "IN" },
  { key: "performance", label: "ประสิทธิภาพโมเดล", kicker: "ML" },
];

const incidents: Incident[] = [
  {
    id: "INC-0247",
    time: "10:32:14",
    source: "192.168.1.24",
    destination: "10.0.0.8",
    protocol: "TCP",
    port: 443,
    score: 94,
    severity: "Critical",
    state: "รอตรวจสอบ",
    reason: "จำนวนการเชื่อมต่อและปริมาณข้อมูลสูงกว่าค่าปกติอย่างมาก",
    action: "ตรวจสอบ process ต้นทางและจำกัดการเชื่อมต่อชั่วคราว",
    packets: 15842,
    bytes: "1.84 GB",
  },
  {
    id: "INC-0246",
    time: "10:27:08",
    source: "192.168.1.71",
    destination: "8.8.8.8",
    protocol: "DNS",
    port: 53,
    score: 87,
    severity: "High",
    state: "กำลังตรวจสอบ",
    reason: "DNS query เพิ่มขึ้น 6.8 เท่าภายในช่วงเวลา 5 นาที",
    action: "ตรวจสอบโดเมนปลายทางและประวัติ DNS ของอุปกรณ์",
    packets: 4218,
    bytes: "38.2 MB",
  },
  {
    id: "INC-0245",
    time: "10:18:51",
    source: "10.10.4.12",
    destination: "172.16.0.31",
    protocol: "TCP",
    port: 22,
    score: 82,
    severity: "High",
    state: "รอตรวจสอบ",
    reason: "พบการเชื่อมต่อ SSH ล้มเหลวซ้ำจากต้นทางเดียวกัน",
    action: "ตรวจสอบบัญชีผู้ใช้และบันทึก authentication",
    packets: 1806,
    bytes: "6.1 MB",
  },
  {
    id: "INC-0244",
    time: "10:06:39",
    source: "192.168.2.89",
    destination: "10.0.0.12",
    protocol: "UDP",
    port: 1900,
    score: 73,
    severity: "High",
    state: "รอตรวจสอบ",
    reason: "ติดต่อปลายทางจำนวนมากในช่วงเวลาสั้น",
    action: "ตรวจสอบ traffic pattern และบริการ discovery",
    packets: 9320,
    bytes: "412 MB",
  },
  {
    id: "INC-0243",
    time: "09:54:22",
    source: "10.10.3.44",
    destination: "172.16.0.10",
    protocol: "HTTP",
    port: 80,
    score: 61,
    severity: "Medium",
    state: "ติดตามผล",
    reason: "Flow duration ยาวกว่าค่าเฉลี่ยของกลุ่มอุปกรณ์",
    action: "ติดตามการเชื่อมต่อและตรวจสอบ application log",
    packets: 2540,
    bytes: "92.4 MB",
  },
  {
    id: "INC-0242",
    time: "09:41:05",
    source: "192.168.1.116",
    destination: "10.0.0.22",
    protocol: "TCP",
    port: 3389,
    score: 58,
    severity: "Medium",
    state: "ยืนยันแล้ว",
    reason: "การใช้งาน RDP นอกช่วงเวลาปกติของอุปกรณ์",
    action: "ยืนยันผู้ใช้งานและตรวจสอบนโยบาย remote access",
    packets: 760,
    bytes: "18.8 MB",
  },
];

const timeline = [18, 24, 21, 42, 35, 61, 48, 77, 52, 86, 63, 71];
const timeLabels = ["08:00", "", "08:30", "", "09:00", "", "09:30", "", "10:00", "", "10:30", "11:00"];

function severityFromScore(score: number): Severity {
  if (score >= 90) return "Critical";
  if (score >= 70) return "High";
  if (score >= 45) return "Medium";
  return "Low";
}

function formatNumber(value: number) {
  return new Intl.NumberFormat("th-TH").format(value);
}

function AppMark() {
  return (
    <div className="app-mark" aria-hidden="true">
      <span className="mark-ring" />
      <span className="mark-dot" />
    </div>
  );
}

function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`severity severity-${severity.toLowerCase()}`}>{severity}</span>;
}

function KpiCard({ label, value, note, tone }: { label: string; value: string; note: string; tone?: string }) {
  return (
    <article className={`kpi-card ${tone ? `kpi-${tone}` : ""}`}>
      <div className="kpi-topline">
        <span>{label}</span>
        <i aria-hidden="true" />
      </div>
      <strong>{value}</strong>
      <small>{note}</small>
    </article>
  );
}

function Dashboard({ onSelectIncident }: { onSelectIncident: (incident: Incident) => void }) {
  return (
    <div className="page-stack">
      <section className="page-heading dashboard-heading">
        <div>
          <p className="eyebrow"><span /> Security operations overview</p>
          <h1>ภาพรวมเครือข่าย</h1>
          <p>คัดกรองเหตุการณ์ที่ควรตรวจสอบจาก Network Flow ล่าสุด</p>
        </div>
        <div className="heading-actions">
          <button className="secondary-button">7 วันที่ผ่านมา</button>
          <button className="primary-button">+ วิเคราะห์ Log ใหม่</button>
        </div>
      </section>

      <section className="notice-strip">
        <div className="pulse-dot" />
        <div><strong>ระบบกำลังเฝ้าระวัง</strong><span>ข้อมูลตัวอย่างอัปเดตเมื่อ 2 นาทีที่แล้ว</span></div>
        <span className="notice-source">CIC-IDS2017 · Demo dataset</span>
      </section>

      <section className="kpi-grid">
        <KpiCard label="Network flows" value="128,420" note="+8.2% จากช่วงก่อนหน้า" />
        <KpiCard label="Anomalies" value="247" note="0.19% ของข้อมูลทั้งหมด" tone="amber" />
        <KpiCard label="High / Critical" value="61" note="ต้องตรวจสอบเพิ่มเติม" tone="red" />
        <KpiCard label="Risky hosts" value="34" note="12 host พบครั้งแรก" tone="violet" />
      </section>

      <section className="dashboard-grid">
        <article className="panel timeline-panel">
          <div className="panel-heading">
            <div><span className="panel-kicker">ANOMALY ACTIVITY</span><h2>เหตุการณ์ตามช่วงเวลา</h2></div>
            <div className="legend"><span /> Anomaly detected</div>
          </div>
          <div className="chart-shell" aria-label="กราฟจำนวนเหตุการณ์ผิดปกติตามเวลา">
            <div className="chart-y"><span>100</span><span>75</span><span>50</span><span>25</span><span>0</span></div>
            <div className="bar-chart">
              {timeline.map((value, index) => (
                <div className="bar-column" key={`${value}-${index}`}>
                  <div className="bar-track"><span style={{ height: `${value}%` }} title={`${value} เหตุการณ์`} /></div>
                  <small>{timeLabels[index]}</small>
                </div>
              ))}
            </div>
          </div>
        </article>

        <article className="panel severity-panel">
          <div className="panel-heading"><div><span className="panel-kicker">RISK DISTRIBUTION</span><h2>ระดับความรุนแรง</h2></div></div>
          <div className="severity-content">
            <div className="donut" aria-label="247 เหตุการณ์ผิดปกติ"><div><strong>247</strong><span>เหตุการณ์</span></div></div>
            <div className="severity-list">
              <div><span className="swatch critical" /><span>Critical</span><strong>18</strong></div>
              <div><span className="swatch high" /><span>High</span><strong>43</strong></div>
              <div><span className="swatch medium" /><span>Medium</span><strong>91</strong></div>
              <div><span className="swatch low" /><span>Low</span><strong>95</strong></div>
            </div>
          </div>
        </article>
      </section>

      <section className="dashboard-grid lower-grid">
        <article className="panel risky-panel">
          <div className="panel-heading"><div><span className="panel-kicker">TOP ENTITIES</span><h2>Host ที่มีความเสี่ยงสูง</h2></div><button className="text-button">ดูทั้งหมด →</button></div>
          <div className="risk-list">
            {[
              ["192.168.1.24", 94, "15.8K connections"],
              ["192.168.1.71", 87, "4.2K DNS queries"],
              ["10.10.4.12", 82, "1.8K failed logins"],
              ["192.168.2.89", 73, "9.3K packets"],
            ].map(([ip, score, detail], index) => (
              <div className="risk-row" key={String(ip)}>
                <span className="rank">0{index + 1}</span>
                <div><strong>{ip}</strong><small>{detail}</small></div>
                <div className="risk-score"><span style={{ width: `${score}%` }} /><b>{score}</b></div>
              </div>
            ))}
          </div>
        </article>

        <article className="panel incident-panel">
          <div className="panel-heading"><div><span className="panel-kicker">PRIORITY QUEUE</span><h2>เหตุการณ์ล่าสุด</h2></div><button className="text-button">ดูทั้งหมด →</button></div>
          <div className="compact-incidents">
            {incidents.slice(0, 4).map((incident) => (
              <button key={incident.id} className="compact-incident" onClick={() => onSelectIncident(incident)}>
                <span className={`incident-signal signal-${incident.severity.toLowerCase()}`} />
                <div><strong>{incident.source}</strong><small>{incident.reason}</small></div>
                <div className="compact-meta"><SeverityBadge severity={incident.severity} /><time>{incident.time}</time></div>
              </button>
            ))}
          </div>
        </article>
      </section>
    </div>
  );
}

function AnalyzePage() {
  const fileRef = useRef<HTMLInputElement>(null);
  const [fileName, setFileName] = useState("");
  const [analysis, setAnalysis] = useState<{ rows: number; columns: number; anomalies: number; score: number } | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  function analyzeFile(file?: File) {
    if (!file) return;
    setFileName(file.name);
    setError("");
    setAnalysis(null);
    setBusy(true);
    const reader = new FileReader();
    reader.onload = () => {
      const text = String(reader.result ?? "").trim();
      const lines = text.split(/\r?\n/).filter(Boolean);
      if (lines.length < 2) {
        setError("ไฟล์ไม่มีข้อมูลเพียงพอสำหรับการวิเคราะห์");
        setBusy(false);
        return;
      }
      const columns = lines[0].split(",").length;
      const rows = lines.length - 1;
      const anomalies = Math.max(1, Math.round(rows * 0.019));
      setAnalysis({ rows, columns, anomalies, score: Math.min(96, 62 + (columns % 25)) });
      setBusy(false);
    };
    reader.onerror = () => {
      setError("ไม่สามารถอ่านไฟล์นี้ได้ กรุณาลองใหม่อีกครั้ง");
      setBusy(false);
    };
    reader.readAsText(file);
  }

  function onFileChange(event: ChangeEvent<HTMLInputElement>) {
    analyzeFile(event.target.files?.[0]);
  }

  return (
    <div className="page-stack">
      <section className="page-heading">
        <div><p className="eyebrow"><span /> Analysis workspace</p><h1>วิเคราะห์ Log</h1><p>นำเข้าข้อมูล Network Flow เพื่อตรวจสอบรูปแบบผิดปกติ</p></div>
        <div className="engine-badge"><span>DEMO ENGINE</span><small>Rule prototype · ยังไม่ใช่ผลตรวจจริง</small></div>
      </section>

      <section className="analyze-layout">
        <article className="panel upload-panel">
          <div className="upload-icon"><span>↑</span></div>
          <h2>เลือกไฟล์ Log สำหรับวิเคราะห์</h2>
          <p>รองรับ CSV, JSON, Zeek conn.log และ Suricata eve.json</p>
          <input ref={fileRef} className="visually-hidden" type="file" accept=".csv,.json,.log,text/csv,application/json" onChange={onFileChange} />
          <button className="primary-button large-button" onClick={() => fileRef.current?.click()}>{busy ? "กำลังประมวลผล…" : "เลือกไฟล์จากเครื่อง"}</button>
          <small className="upload-note">ขนาดสูงสุดที่แนะนำ 50 MB · ข้อมูลจะประมวลผลในเบราว์เซอร์</small>
          {fileName && <div className="selected-file"><span>CSV</span><div><strong>{fileName}</strong><small>{busy ? "กำลังตรวจสอบโครงสร้างข้อมูล" : "อ่านไฟล์เรียบร้อย"}</small></div></div>}
          {error && <div className="error-note">{error}</div>}
        </article>

        <aside className="panel pipeline-panel">
          <span className="panel-kicker">ANALYSIS PIPELINE</span>
          <h2>ขั้นตอนการประมวลผล</h2>
          <ol className="pipeline-list">
            <li className="done"><b>01</b><div><strong>ตรวจสอบไฟล์</strong><span>รูปแบบและคอลัมน์ที่จำเป็น</span></div></li>
            <li className={analysis ? "done" : ""}><b>02</b><div><strong>เตรียมข้อมูล</strong><span>NaN, Infinity และประเภทข้อมูล</span></div></li>
            <li className={analysis ? "done" : ""}><b>03</b><div><strong>สกัด Feature</strong><span>Flow, Packet, Bytes และ Protocol</span></div></li>
            <li className={analysis ? "done" : ""}><b>04</b><div><strong>ประเมินความเสี่ยง</strong><span>คะแนนและระดับ Severity</span></div></li>
          </ol>
        </aside>
      </section>

      {analysis ? (
        <section className="panel result-panel">
          <div className="panel-heading"><div><span className="panel-kicker">IMPORT COMPLETE</span><h2>ผลการตรวจสอบไฟล์เบื้องต้น</h2></div><span className="success-pill">พร้อมใช้งาน</span></div>
          <div className="result-grid">
            <div><span>จำนวนรายการ</span><strong>{formatNumber(analysis.rows)}</strong></div>
            <div><span>จำนวนคอลัมน์</span><strong>{analysis.columns}</strong></div>
            <div><span>เหตุการณ์ต้องสงสัย</span><strong>{analysis.anomalies}</strong></div>
            <div><span>คะแนนสูงสุด</span><strong>{analysis.score}<small>/100</small></strong></div>
          </div>
          <div className="demo-disclaimer">ผลนี้ใช้ Rule Demo สำหรับทดสอบหน้าจอเท่านั้น ขั้นต่อไปคือเชื่อม Random Forest/XGBoost ที่ผ่านการประเมินแล้ว</div>
        </section>
      ) : (
        <section className="sample-card">
          <div><span className="sample-tag">SAMPLE DATA</span><h3>ยังไม่มีไฟล์ทดสอบ?</h3><p>ใช้โครงสร้าง CIC-IDS2017 เพื่อดูผลลัพธ์ตัวอย่างของระบบได้</p></div>
          <button className="secondary-button" onClick={() => setAnalysis({ rows: 28460, columns: 79, anomalies: 542, score: 94 })}>ใช้ข้อมูลตัวอย่าง</button>
        </section>
      )}
    </div>
  );
}

function IncidentsPage({ onSelectIncident }: { onSelectIncident: (incident: Incident) => void }) {
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("All");
  const filtered = useMemo(() => incidents.filter((incident) => {
    const matchesText = `${incident.id} ${incident.source} ${incident.destination} ${incident.protocol}`.toLowerCase().includes(query.toLowerCase());
    return matchesText && (severity === "All" || incident.severity === severity);
  }), [query, severity]);

  return (
    <div className="page-stack">
      <section className="page-heading">
        <div><p className="eyebrow"><span /> Incident queue</p><h1>เหตุการณ์ที่ตรวจพบ</h1><p>จัดลำดับ ตรวจสอบ และติดตามเหตุการณ์จากคะแนนความเสี่ยง</p></div>
        <button className="secondary-button">ส่งออก CSV</button>
      </section>
      <section className="incident-summary-row">
        <div><span>ทั้งหมด</span><strong>247</strong></div><div className="red"><span>Critical</span><strong>18</strong></div><div className="orange"><span>High</span><strong>43</strong></div><div><span>รอตรวจสอบ</span><strong>86</strong></div>
      </section>
      <section className="panel table-panel">
        <div className="table-tools">
          <label className="search-box"><span>⌕</span><input aria-label="ค้นหาเหตุการณ์" placeholder="ค้นหา Incident, IP หรือ Protocol" value={query} onChange={(event) => setQuery(event.target.value)} /></label>
          <label className="filter-label">Severity<select value={severity} onChange={(event) => setSeverity(event.target.value)}><option value="All">ทั้งหมด</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option></select></label>
        </div>
        <div className="table-scroll">
          <table>
            <thead><tr><th>Incident</th><th>เวลา</th><th>Source → Destination</th><th>Protocol</th><th>Score</th><th>Severity</th><th>สถานะ</th><th /></tr></thead>
            <tbody>
              {filtered.map((incident) => (
                <tr key={incident.id}>
                  <td><strong>{incident.id}</strong></td><td>{incident.time}</td>
                  <td><div className="route-cell"><span>{incident.source}</span><i>→</i><span>{incident.destination}</span></div></td>
                  <td><span className="protocol-pill">{incident.protocol}</span></td>
                  <td><div className="score-cell"><span><i style={{ width: `${incident.score}%` }} /></span><strong>{incident.score}</strong></div></td>
                  <td><SeverityBadge severity={incident.severity} /></td><td>{incident.state}</td>
                  <td><button className="row-button" onClick={() => onSelectIncident(incident)} aria-label={`ดูรายละเอียด ${incident.id}`}>→</button></td>
                </tr>
              ))}
            </tbody>
          </table>
          {!filtered.length && <div className="empty-state">ไม่พบเหตุการณ์ที่ตรงกับตัวกรอง</div>}
        </div>
      </section>
    </div>
  );
}

function PerformancePage() {
  return (
    <div className="page-stack">
      <section className="page-heading"><div><p className="eyebrow"><span /> Model evaluation</p><h1>ประสิทธิภาพโมเดล</h1><p>ผลทดสอบตัวอย่างบนชุดข้อมูลที่แยกจากชุดฝึก</p></div><div className="model-selector"><span>ACTIVE MODEL</span><strong>Random Forest v0.1</strong></div></section>
      <section className="metric-grid">
        {[['Accuracy','96.8','ภาพรวมทุกคลาส'],['Precision','94.2','ความแม่นยำเมื่อแจ้งเตือน'],['Recall','92.7','เหตุผิดปกติที่ตรวจพบ'],['F1-score','93.4','สมดุล Precision / Recall']].map(([label, value, note], index) => (
          <article className={index === 2 ? "metric-card focus" : "metric-card"} key={label}><span>{label}</span><strong>{value}<small>%</small></strong><p>{note}</p><div><i style={{ width: `${value}%` }} /></div></article>
        ))}
      </section>
      <section className="performance-grid">
        <article className="panel confusion-panel">
          <div className="panel-heading"><div><span className="panel-kicker">CONFUSION MATRIX</span><h2>ผลการจำแนก</h2></div><span className="dataset-pill">Test set · 25,684 flows</span></div>
          <div className="matrix-wrap">
            <div className="matrix-label vertical">ค่าจริง</div>
            <div className="matrix">
              <div className="matrix-axis"><span>ทำนาย Normal</span><span>ทำนาย Anomaly</span></div>
              <div className="matrix-row"><small>Normal</small><div className="matrix-cell strong"><strong>23,480</strong><span>True Negative</span></div><div className="matrix-cell"><strong>286</strong><span>False Positive</span></div></div>
              <div className="matrix-row"><small>Anomaly</small><div className="matrix-cell"><strong>141</strong><span>False Negative</span></div><div className="matrix-cell strong accent"><strong>1,777</strong><span>True Positive</span></div></div>
            </div>
          </div>
        </article>
        <article className="panel model-compare">
          <div className="panel-heading"><div><span className="panel-kicker">MODEL COMPARISON</span><h2>เปรียบเทียบโมเดล</h2></div></div>
          {[
            ["Random Forest", "93.4", "1.8s"],
            ["XGBoost", "94.1", "2.6s"],
            ["Isolation Forest", "87.6", "1.2s"],
          ].map(([name, score, speed], index) => (
            <div className="model-row" key={name}><span className={`model-index m${index}`}>0{index + 1}</span><div><strong>{name}</strong><small>F1-score</small></div><b>{score}%</b><span>{speed}</span></div>
          ))}
          <div className="model-note"><strong>คำแนะนำ</strong><p>ใช้ XGBoost เป็นตัวจำแนกหลัก และ Isolation Forest เป็นคะแนนเสริมสำหรับเหตุการณ์รูปแบบใหม่</p></div>
        </article>
      </section>
      <section className="data-note"><span>i</span><p><strong>ข้อมูลสำหรับการสาธิต</strong> ตัวเลขประสิทธิภาพในหน้านี้เป็นข้อมูลตัวอย่าง ต้องแทนที่ด้วยผลจากการ train/test จริงก่อนนำไปอ้างอิงในรายงาน</p></section>
    </div>
  );
}

function IncidentDrawer({ incident, onClose }: { incident: Incident; onClose: () => void }) {
  return (
    <div className="drawer-backdrop" role="presentation" onMouseDown={(event) => { if (event.currentTarget === event.target) onClose(); }}>
      <aside className="incident-drawer" role="dialog" aria-modal="true" aria-labelledby="incident-title">
        <div className="drawer-header"><div><span>{incident.id}</span><h2 id="incident-title">รายละเอียดเหตุการณ์</h2></div><button aria-label="ปิดรายละเอียด" onClick={onClose}>×</button></div>
        <div className="drawer-score"><div><span>Risk score</span><strong>{incident.score}</strong><small>/100</small></div><SeverityBadge severity={incident.severity} /></div>
        <div className="route-visual"><div><small>SOURCE</small><strong>{incident.source}</strong></div><span>→</span><div><small>DESTINATION</small><strong>{incident.destination}:{incident.port}</strong></div></div>
        <section className="drawer-section"><span className="panel-kicker">INCIDENT SUMMARY</span><h3>เหตุผลที่ตรวจพบ</h3><p>{incident.reason}</p></section>
        <div className="evidence-grid"><div><span>Protocol</span><strong>{incident.protocol}</strong></div><div><span>Packets</span><strong>{formatNumber(incident.packets)}</strong></div><div><span>Transfer</span><strong>{incident.bytes}</strong></div><div><span>Detected</span><strong>{incident.time}</strong></div></div>
        <section className="drawer-section recommendation"><span className="panel-kicker">SUGGESTED ACTION</span><h3>คำแนะนำเบื้องต้น</h3><p>{incident.action}</p></section>
        <div className="drawer-disclaimer">ระบบนี้ช่วยจัดลำดับเหตุการณ์ ไม่ได้ยืนยันว่าเป็นการโจมตี กรุณาตรวจสอบหลักฐานเพิ่มเติม</div>
        <div className="drawer-actions"><button className="secondary-button" onClick={onClose}>ปิด</button><button className="primary-button">เริ่มตรวจสอบ</button></div>
      </aside>
    </div>
  );
}

export default function Home() {
  const [page, setPage] = useState<PageKey>("dashboard");
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div className="brand"><AppMark /><div><strong>Summary Log</strong><span>AI-assisted monitoring</span></div></div>
        <nav aria-label="เมนูหลัก">
          <span className="nav-label">WORKSPACE</span>
          {navItems.map((item) => <button key={item.key} className={page === item.key ? "active" : ""} onClick={() => setPage(item.key)}><span>{item.kicker}</span>{item.label}{item.key === "incidents" && <b>18</b>}</button>)}
        </nav>
        <div className="sidebar-foot">
          <div className="system-health"><span /><div><strong>System healthy</strong><small>Demo environment</small></div></div>
          <div className="profile"><div>SL</div><span><strong>Security Lab</strong><small>Administrator</small></span><button aria-label="เปิดเมนูผู้ใช้">···</button></div>
        </div>
      </aside>

      <section className="main-area">
        <header className="mobile-header"><div className="brand"><AppMark /><strong>Summary Log</strong></div><span className="mobile-status">DEMO</span></header>
        <nav className="mobile-nav" aria-label="เมนูบนมือถือ">{navItems.map((item) => <button key={item.key} className={page === item.key ? "active" : ""} onClick={() => setPage(item.key)}>{item.label}</button>)}</nav>
        <div className="page-wrap">
          {page === "dashboard" && <Dashboard onSelectIncident={setSelectedIncident} />}
          {page === "analyze" && <AnalyzePage />}
          {page === "incidents" && <IncidentsPage onSelectIncident={setSelectedIncident} />}
          {page === "performance" && <PerformancePage />}
        </div>
        <footer><span>Summary Log AI · Prototype</span><span>Decision-support system — human review required</span></footer>
      </section>
      {selectedIncident && <IncidentDrawer incident={selectedIncident} onClose={() => setSelectedIncident(null)} />}
    </main>
  );
}
