import assert from "node:assert/strict";
import test from "node:test";
import { evaluateRules, severityForScore, validateEvent, type ConnEvent } from "../src/rules.js";

const event: ConnEvent = {
  uid: "C1", ts: 1_700_000_000, orig_h: "192.168.1.10", orig_p: 50000,
  resp_h: "10.0.0.5", resp_p: 443, proto: "tcp", service: "ssl", conn_state: "SF",
  duration: 1, orig_bytes: 100, resp_bytes: 200, orig_pkts: 2, resp_pkts: 3,
};

test("severity boundaries are stable", () => {
  assert.equal(severityForScore(44), "Low");
  assert.equal(severityForScore(45), "Medium");
  assert.equal(severityForScore(70), "High");
  assert.equal(severityForScore(90), "Critical");
});

test("rule scores are capped and include all triggered codes", () => {
  const result = evaluateRules({
    connectionCount: 150, uniqueDestinations: 40, failedCount: 100,
    byteCount: 200 * 1024 * 1024, uncommonPortCount: 1,
    maxDurationMs: 400_000, maxFlowBytes: 60 * 1024 * 1024,
  }, { ...event, resp_p: 65000 });
  assert.equal(result.score, 100);
  assert.equal(result.severity, "Critical");
  assert.equal(result.codes.length, 7);
  assert.equal(result.matches.length, 7);
  assert.equal(result.matches.reduce((sum, match) => sum + match.points, 0), 145);
  assert.equal(result.matches[0].actual, 150);
});

test("normal traffic remains low", () => {
  const result = evaluateRules({
    connectionCount: 3, uniqueDestinations: 2, failedCount: 0, byteCount: 1000,
    uncommonPortCount: 0, maxDurationMs: 1000, maxFlowBytes: 1000,
  }, event);
  assert.equal(result.score, 0);
  assert.equal(result.severity, "Low");
});

test("event validation rejects malformed input", () => {
  assert.equal(validateEvent(event), true);
  assert.equal(validateEvent({ ...event, uid: "", orig_bytes: -1 }), false);
});
