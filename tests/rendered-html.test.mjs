import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("ships the product landing, self-hosted console and production metadata", async () => {
  const [page, consolePage, consoleComponent, layout, css] = await Promise.all([
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/app/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/product-console.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/layout.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/product.css", import.meta.url), "utf8"),
  ]);
  assert.match(page, /Self-hosted/);
  assert.match(page, /Docker Compose/);
  assert.match(consolePage, /ProductConsole/);
  assert.match(consoleComponent, /\/api\/v1\/setup/);
  assert.match(consoleComponent, /EventSource/);
  assert.match(consoleComponent, /Allowlist/);
  assert.match(layout, /Self-hosted Zeek Monitoring/);
  assert.match(css, /\.console-shell/);
  assert.doesNotMatch(page + layout, /codex-preview|react-loading-skeleton/);
});
