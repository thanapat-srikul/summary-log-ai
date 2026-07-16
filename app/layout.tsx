import type { Metadata } from "next";
import { headers } from "next/headers";
import "./globals.css";

export async function generateMetadata():Promise<Metadata>{
  const requestHeaders=await headers();
  const host=requestHeaders.get("x-forwarded-host")??requestHeaders.get("host")??"localhost:3000";
  const protocol=requestHeaders.get("x-forwarded-proto")??(host.startsWith("localhost")?"http":"https");
  const origin=`${protocol}://${host}`;
  const title="Summary Log AI — Zeek File Analyzer";
  const description="อ่านและสรุป Zeek conn.log เป็น Dashboard และ Incident ภายในเบราว์เซอร์ โดยไม่ส่ง Raw Log ออกจากเครื่อง";
  return{metadataBase:new URL(origin),title,description,openGraph:{title,description,type:"website",images:[{url:`${origin}/og.png`,width:1792,height:920,alt:"Summary Log AI Zeek file analysis dashboard"}]},twitter:{card:"summary_large_image",title,description,images:[`${origin}/og.png`]}};
}

export default function RootLayout({children}:Readonly<{children:React.ReactNode}>){return<html lang="th"><body>{children}<a className="global-demo-link" href="/demo">ดู Dashboard ตัวอย่าง</a></body></html>;}
