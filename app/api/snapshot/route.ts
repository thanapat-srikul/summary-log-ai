import { getSnapshot } from "../../../lib/live-store";
import { runtimeBindings } from "../../../lib/runtime";

export async function GET(request: Request) {
  const { DB } = runtimeBindings();
  if (!DB) return Response.json({ error: "database unavailable" }, { status: 503 });
  const url = new URL(request.url);
  const window = url.searchParams.get("window");
  if (window && !["15m", "1h", "24h"].includes(window)) return Response.json({ error: "invalid window" }, { status: 400 });
  try {
    return Response.json(await getSnapshot(DB, window), { headers: { "cache-control": "no-store" } });
  } catch (error) {
    console.error("snapshot failed", error instanceof Error ? error.message : "unknown error");
    return Response.json({ error: "snapshot unavailable" }, { status: 500 });
  }
}
