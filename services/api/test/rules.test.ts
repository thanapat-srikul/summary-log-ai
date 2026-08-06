import assert from "node:assert/strict";
import test from "node:test";
import { defaultRuleConfigs, evaluateRules, severityForScore, validateEvent, type ConnEvent } from "../src/rules.js";

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

test("source thresholds and disabled rules change evaluation", () => {
  const configs = defaultRuleConfigs();
  configs.HIGH_CONNECTION_RATE = { ...configs.HIGH_CONNECTION_RATE, scope: "source", threshold: { minimum: 200 } };
  configs.UNCOMMON_PORT = { ...configs.UNCOMMON_PORT, enabled: false, scope: "source" };
  const result = evaluateRules({
    connectionCount: 150, uniqueDestinations: 0, failedCount: 0, byteCount: 0,
    uncommonPortCount: 1, maxDurationMs: 0, maxFlowBytes: 0,
  }, { ...event, resp_p: 65000 }, configs);
  assert.equal(result.score, 0);
  assert.deepEqual(result.codes, []);
});

test("ready baseline raises threshold and records its origin", () => {
  const configs = defaultRuleConfigs();
  const below = evaluateRules({
    connectionCount: 150, uniqueDestinations: 0, failedCount: 0, byteCount: 0,
    uncommonPortCount: 0, maxDurationMs: 0, maxFlowBytes: 0,
  }, event, configs, { HIGH_CONNECTION_RATE: { value: 180, status: "ready", sampleCount: 500 } });
  assert.equal(below.score, 0);
  const triggered = evaluateRules({
    connectionCount: 200, uniqueDestinations: 0, failedCount: 0, byteCount: 0,
    uncommonPortCount: 0, maxDurationMs: 0, maxFlowBytes: 0,
  }, event, configs, { HIGH_CONNECTION_RATE: { value: 180, status: "ready", sampleCount: 500 } });
  assert.equal(triggered.matches[0].threshold, 180);
  assert.equal(triggered.matches[0].thresholdSource, "baseline");
});

test("event validation rejects malformed input", () => {
  assert.equal(validateEvent(event), true);
  assert.equal(validateEvent({ ...event, uid: "", orig_bytes: -1 }), false);
});
