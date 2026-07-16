import { env } from "cloudflare:workers";

export type RuntimeBindings = {
  DB: D1Database;
  INGEST_API_KEY?: string;
};

export function runtimeBindings(): RuntimeBindings {
  return env as unknown as RuntimeBindings;
}
