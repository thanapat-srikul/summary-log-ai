import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import test from "node:test";

test("ships the live dashboard and metadata without starter artifacts", async () => {
  const [page, dashboard, layout, packageJson] = await Promise.all([
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/live-dashboard.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/layout.tsx", import.meta.url), "utf8"),
    readFile(new URL("../package.json", import.meta.url), "utf8"),
  ]);
  assert.match(page, /LiveDashboard/);
  assert.match(dashboard, /EventSource/);
  assert.match(dashboard, /\/api\/snapshot\?window=15m/);
  assert.match(dashboard, /Collector offline/);
  assert.match(dashboard, /ข้อมูลตัวอย่าง ไม่รวมกับข้อมูลจริง/);
  assert.match(dashboard, /Source Health/);
  assert.match(layout, /summary_large_image/);
  assert.doesNotMatch(packageJson, /react-loading-skeleton/);
  await assert.rejects(access(new URL("../app/_sites-preview/SkeletonPreview.tsx", import.meta.url)));
  await access(new URL("../public/og.png", import.meta.url));
});
