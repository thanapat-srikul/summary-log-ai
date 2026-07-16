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
  assert.match(page, /FileDashboard/);
  const fileDashboard = await readFile(new URL("../app/file-dashboard.tsx", import.meta.url), "utf8");
  assert.match(fileDashboard, /ZEEK FILE ANALYSIS/);
  assert.match(fileDashboard, /ไม่ส่ง Raw Log ออกจากเครื่อง/);
  assert.match(fileDashboard, /parseZeek/);
  assert.doesNotMatch(page, /LiveDashboard|EventSource/);
  assert.match(layout, /summary_large_image/);
  assert.doesNotMatch(packageJson, /react-loading-skeleton/);
  await assert.rejects(access(new URL("../app/_sites-preview/SkeletonPreview.tsx", import.meta.url)));
  await access(new URL("../public/og.png", import.meta.url));
});
