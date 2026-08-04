import assert from "node:assert/strict";
import test from "node:test";
import { canTransition, severityRank, shouldMerge } from "../src/incident-policy.js";

test("workflow only accepts the next normal status", () => {
  assert.equal(canTransition("new", "acknowledged"), true);
  assert.equal(canTransition("new", "investigating"), false);
  assert.equal(canTransition("acknowledged", "investigating"), true);
  assert.equal(canTransition("investigating", "resolved"), true);
  assert.equal(canTransition("resolved", "new"), false);
});

test("merge window is inclusive and rejects old or out-of-order events", () => {
  const last = new Date("2026-08-04T00:00:00Z");
  assert.equal(shouldMerge(last, new Date("2026-08-04T00:10:00Z")), true);
  assert.equal(shouldMerge(last, new Date("2026-08-04T00:10:00.001Z")), false);
  assert.equal(shouldMerge(last, new Date("2026-08-03T23:59:59Z")), false);
});

test("severity rank is stable", () => {
  assert.ok(severityRank("Critical") > severityRank("High"));
  assert.ok(severityRank("High") > severityRank("Medium"));
});
