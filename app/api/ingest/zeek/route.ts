import { runtimeBindings } from "../../../../lib/runtime";
import { authorizeIngest } from "../../../../lib/security";
import { validateIngestPayload } from "../../../../lib/zeek";
import { ingestEvents } from "../../../../lib/live-store";

const MAX_BODY_BYTES = 1024 * 1024;

export async function POST(request: Request) {
  const { DB, INGEST_API_KEY } = runtimeBindings();
  if (!DB) return Response.json({ error: "database unavailable" }, { status: 503 });
  if (!INGEST_API_KEY) return Response.json({ error: "ingest is not configured" }, { status: 503 });
  if (!authorizeIngest(request.headers.get("authorization"), INGEST_API_KEY)) {
    return Response.json({ error: "unauthorized" }, { status: 401 });
  }
  const declaredLength = Number(request.headers.get("content-length") ?? 0);
  if (declaredLength > MAX_BODY_BYTES) return Response.json({ error: "request body is too large" }, { status: 413 });

  let text: string;
  try {
    text = await request.text();
  } catch {
    return Response.json({ error: "request body could not be read" }, { status: 400 });
  }
  if (new TextEncoder().encode(text).byteLength > MAX_BODY_BYTES) return Response.json({ error: "request body is too large" }, { status: 413 });

  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    return Response.json({ error: "invalid JSON" }, { status: 400 });
  }
  const validation = validateIngestPayload(body);
  if (!validation.sourceId || !validation.sentAt || validation.errors.length) {
    return Response.json({ error: "invalid payload", details: validation.errors }, { status: 400 });
  }
  try {
    const result = await ingestEvents(DB, validation.sourceId, validation.events, validation.rejected, validation.spoolBacklog);
    return Response.json(result, { status: 202 });
  } catch (error) {
    console.error("zeek ingest failed", error instanceof Error ? error.message : "unknown error");
    return Response.json({ error: "ingest failed" }, { status: 500 });
  }
}
