import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import test from "node:test";

test("ships the file analysis dashboard and metadata without starter artifacts", async () => {
  const [page, dashboard, layout, packageJson] = await Promise.all([
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/live-dashboard.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/layout.tsx", import.meta.url), "utf8"),
    readFile(new URL("../package.json", import.meta.url), "utf8"),
  ]);
  assert.match(page, /FileAnalyzerV2/);
  const fileDashboard = await readFile(new URL("../app/file-analyzer-v2.tsx", import.meta.url), "utf8");
  assert.match(fileDashboard, /ZEEK FILE ANALYSIS/);
  assert.match(fileDashboard, /LOCAL PROCESSING/);
  assert.match(fileDashboard, /parseZeek/);
  assert.match(fileDashboard, /Export CSV/);
  assert.match(fileDashboard, /multiple/);
  assert.match(fileDashboard, /ThresholdPanel/);
  const demoDashboard = await readFile(new URL("../app/demo/demo-dashboard.tsx", import.meta.url), "utf8");
  assert.match(demoDashboard, /DEMO DASHBOARD/);
  assert.match(demoDashboard, /ตัวอย่าง Incident/);
  assert.match(layout, /\/demo/);
  assert.doesNotMatch(page, /LiveDashboard|EventSource/);
  assert.match(layout, /summary_large_image/);
  assert.doesNotMatch(packageJson, /react-loading-skeleton/);
  await assert.rejects(access(new URL("../app/_sites-preview/SkeletonPreview.tsx", import.meta.url)));
  await access(new URL("../public/og.png", import.meta.url));
});
