import { latestCursor } from "../../../lib/live-store";
import { runtimeBindings } from "../../../lib/runtime";

const encoder = new TextEncoder();
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export async function GET(request: Request) {
  const { DB } = runtimeBindings();
  if (!DB) return Response.json({ error: "database unavailable" }, { status: 503 });
  const url = new URL(request.url);
  let cursor = Math.max(0, Number(url.searchParams.get("cursor") ?? 0) || 0);
  let cancelled = false;
  request.signal.addEventListener("abort", () => { cancelled = true; });

  const stream = new ReadableStream({
    async start(controller) {
      controller.enqueue(encoder.encode("retry: 1000\n\n"));
      try {
        for (let tick = 0; tick < 45 && !cancelled; tick += 1) {
          const nextCursor = await latestCursor(DB);
          if (nextCursor > cursor) {
            cursor = nextCursor;
            controller.enqueue(encoder.encode(`event: update\ndata: ${JSON.stringify({ cursor })}\n\n`));
          }
          if (tick % 15 === 0) controller.enqueue(encoder.encode(`event: heartbeat\ndata: ${JSON.stringify({ at: Date.now() })}\n\n`));
          await sleep(1000);
        }
        if (!cancelled) controller.enqueue(encoder.encode("event: reconnect\ndata: {}\n\n"));
      } catch {
        if (!cancelled) controller.enqueue(encoder.encode("event: reconnect\ndata: {}\n\n"));
      } finally {
        if (!cancelled) controller.close();
      }
    },
    cancel() { cancelled = true; },
  });
  return new Response(stream, {
    headers: {
      "content-type": "text/event-stream; charset=utf-8",
      "cache-control": "no-cache, no-transform",
      connection: "keep-alive",
      "x-accel-buffering": "no",
    },
  });
}
