import type { Metadata } from "next";
import { headers } from "next/headers";
import "./globals.css";
import "./product.css";

export async function generateMetadata(): Promise<Metadata> {
  const requestHeaders = await headers();
  const host = requestHeaders.get("x-forwarded-host") ?? requestHeaders.get("host") ?? "localhost:3000";
  const protocol = requestHeaders.get("x-forwarded-proto") ?? (host.startsWith("localhost") ? "http" : "https");
  const origin = `${protocol}://${host}`;
  const title = "Summary Log AI — Self-hosted Zeek Monitoring";
  const description = "เปลี่ยน Zeek conn.log ให้เป็น Dashboard, Incident และ Email Alert แบบใกล้เคียงเวลาจริง โดยไม่เก็บ Raw Log";
  return {
    metadataBase: new URL(origin), title, description,
    openGraph: { title, description, type: "website", images: [{ url: `${origin}/og.png`, width: 1792, height: 920, alt: "Summary Log AI dashboard" }] },
    twitter: { card: "summary_large_image", title, description, images: [`${origin}/og.png`] },
  };
}

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="th"><body>{children}</body></html>;
}
