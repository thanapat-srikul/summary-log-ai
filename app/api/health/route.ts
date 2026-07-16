import { getHealth } from "../../../lib/live-store";
import { runtimeBindings } from "../../../lib/runtime";

export async function GET() {
  const { DB } = runtimeBindings();
  if (!DB) return Response.json({ status: "unavailable", error: "database unavailable" }, { status: 503 });
  try {
    return Response.json(await getHealth(DB), { headers: { "cache-control": "no-store" } });
  } catch {
    return Response.json({ status: "unavailable", error: "health unavailable" }, { status: 500 });
  }
}
