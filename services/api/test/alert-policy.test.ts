import assert from "node:assert/strict";
import test from "node:test";
import { ALERT_EMAIL_ITEM_LIMIT, ALERT_MAX_ATTEMPTS, alertWindow, highestSeverity, retryDelayMinutes, severityMeetsMinimum } from "../src/alert-policy.js";

test("five minute grouping windows are stable", () => {
  const window = alertWindow(new Date("2026-08-06T03:07:42.000Z"));
  assert.equal(window.start.toISOString(), "2026-08-06T03:05:00.000Z");
  assert.equal(window.end.toISOString(), "2026-08-06T03:10:00.000Z");
});

test("High default includes High and Critical but not Medium", () => {
  assert.equal(severityMeetsMinimum("Medium", "High"), false);
  assert.equal(severityMeetsMinimum("High", "High"), true);
  assert.equal(severityMeetsMinimum("Critical", "High"), true);
  assert.equal(highestSeverity("High", "Critical"), "Critical");
});

test("retry backoff is bounded", () => {
  assert.equal(ALERT_EMAIL_ITEM_LIMIT, 50);
  assert.equal(ALERT_MAX_ATTEMPTS, 6);
  assert.equal(retryDelayMinutes(1), 2);
  assert.equal(retryDelayMinutes(6), 60);
});
