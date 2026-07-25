const capabilities = [
  ["Near real-time", "เห็นการเปลี่ยนแปลงจาก Zeek conn.log ภายในเป้าหมาย 2–5 วินาที"],
  ["Privacy by design", "ไม่จัดเก็บ Raw Log เก็บเฉพาะสรุปราย minute และ Incident"],
  ["Operational workflow", "จัดลำดับความเสี่ยง ติดตามสถานะ และส่ง Email แจ้งเตือน"],
  ["Self-hosted", "ข้อมูลและบัญชีผู้ใช้ทั้งหมดอยู่ในระบบขององค์กรคุณ"],
];

export default function Home() {
  return <main className="landing">
    <nav className="landing-nav">
      <a className="landing-brand" href="#"><span>SL</span><strong>Summary Log AI</strong></a>
      <div><a href="#architecture">สถาปัตยกรรม</a><a href="#install">การติดตั้ง</a><a href="/demo">ดูตัวอย่าง</a><a className="landing-cta small" href="/app">เปิด Console</a></div>
    </nav>
    <section className="landing-hero">
      <div>
        <p className="landing-kicker"><i /> ZEEK NETWORK MONITORING</p>
        <h1>เปลี่ยน Network Log<br/>ให้เป็นภาพที่ทีมคุณ<br/><em>ตัดสินใจได้ทันที</em></h1>
        <p className="landing-lead">ระบบวิเคราะห์ Zeek conn.log แบบ Self-hosted สำหรับทีมดูแลระบบ มองเห็นเหตุการณ์ผิดปกติ จัดการ Incident และรับการแจ้งเตือน โดยไม่ส่ง Raw Log ออกจากองค์กร</p>
        <div className="landing-actions"><a className="landing-cta" href="/app">เริ่มตั้งค่าระบบ</a><a className="landing-secondary" href="/demo">สำรวจ Dashboard ตัวอย่าง →</a></div>
        <div className="landing-proof"><span>Apache-2.0</span><span>Linux + Docker</span><span>PostgreSQL</span><span>Zeek conn.log</span></div>
      </div>
      <div className="hero-console" aria-label="ตัวอย่างสถานะระบบ">
        <div className="console-top"><div><b /><b /><b /></div><span>summary-log / live</span><i>LIVE</i></div>
        <div className="console-status"><span className="radar"><i /></span><div><small>SYSTEM STATUS</small><strong>All sensors operational</strong></div><time>2s ago</time></div>
        <div className="console-kpis"><div><small>FLOWS / 15M</small><strong>128,420</strong><span>↑ 8.4%</span></div><div><small>ACTIVE INCIDENTS</small><strong>24</strong><span className="warn">6 high</span></div></div>
        <div className="console-chart"><div className="chart-head"><span>ANOMALY ACTIVITY</span><small>Last 15 minutes</small></div><div className="spark">{[18,25,22,38,30,62,45,78,48,84,60,72,52,90,66].map((v,i)=><i key={i} style={{height:`${v}%`}} />)}</div></div>
        <div className="console-alert"><b>CRITICAL</b><div><strong>192.168.1.24</strong><span>High transfer volume + uncommon port</span></div><em>94</em></div>
      </div>
    </section>
    <section className="landing-capabilities">{capabilities.map(([title,text],i)=><article key={title}><span>0{i+1}</span><h2>{title}</h2><p>{text}</p></article>)}</section>
    <section id="architecture" className="landing-section">
      <p className="landing-kicker"><i /> HOW IT WORKS</p><h2>ติดตั้งใกล้ Zeek แล้วให้ข้อมูลไหลเข้าหาคุณ</h2>
      <div className="architecture-flow">{["Zeek conn.log","Python Collector","Secure API","Rule Engine","Dashboard & Email"].map((item,i)=><div key={item}><b>{String(i+1).padStart(2,"0")}</b><strong>{item}</strong>{i<4&&<span>→</span>}</div>)}</div>
    </section>
    <section id="install" className="landing-install"><div><p className="landing-kicker"><i /> GET STARTED</p><h2>เริ่มระบบด้วย Docker Compose</h2><p>สร้างไฟล์ตั้งค่า เปิดบริการ แล้วเข้า Setup Wizard เพื่อสร้าง Admin และ Source แรก คู่มือทั้งหมดรวมอยู่ในชุดติดตั้ง</p></div><pre><code><span>$</span> cp .env.selfhost.example .env{"\n"}<span>$</span> docker compose up -d{"\n"}<span>✓</span> Summary Log AI is ready</code></pre></section>
    <footer className="landing-footer"><span>Summary Log AI v0.1.0</span><span>Self-hosted Zeek monitoring · No raw log storage</span></footer>
  </main>;
}
