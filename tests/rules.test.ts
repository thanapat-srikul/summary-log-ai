import assert from "node:assert/strict";
import test from "node:test";
import { evaluateRules, severityForScore } from "../lib/rules";
import type { ZeekConnEvent } from "../lib/zeek";

const event:ZeekConnEvent={uid:"C1",ts:1,orig_h:"10.0.0.1",orig_p:50000,resp_h:"10.0.0.2",resp_p:443,proto:"tcp",service:"ssl",conn_state:"SF",duration:1,orig_bytes:1,resp_bytes:1,orig_pkts:1,resp_pkts:1};
test("rule engine applies every threshold and caps risk at 100",()=>{const result=evaluateRules({connectionCount:100,uniqueDestinations:25,byteCount:100*1024*1024,packetCount:1,failedCount:50,maxDurationMs:300000,maxFlowBytes:50*1024*1024,uncommonPortCount:1},event);assert.equal(result.score,100);assert.equal(result.severity,"Critical");assert.equal(result.codes.length,7);});
test("failure rule requires both count and ratio",()=>{const result=evaluateRules({connectionCount:100,uniqueDestinations:0,byteCount:0,packetCount:0,failedCount:49,maxDurationMs:0,maxFlowBytes:0,uncommonPortCount:0},event);assert.equal(result.codes.includes("HIGH_FAILURE_RATIO"),false);});
test("severity boundaries match the plan",()=>assert.deepEqual([44,45,69,70,89,90].map(severityForScore),["Low","Medium","Medium","High","High","Critical"]));
