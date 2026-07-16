import assert from "node:assert/strict";
import test from "node:test";
import { parseZeek } from "../app/file-dashboard";

test("reads Zeek JSON lines",()=>{const input=JSON.stringify({ts:1784160000,uid:"C1","id.orig_h":"192.168.1.2","id.orig_p":50000,"id.resp_h":"10.0.0.8","id.resp_p":443,proto:"tcp",conn_state:"SF",orig_bytes:10,resp_bytes:20,orig_pkts:1,resp_pkts:2});const result=parseZeek(input);assert.equal(result.flows.length,1);assert.equal(result.flows[0].respH,"10.0.0.8");assert.equal(result.rejected,0);});

test("reads Zeek TSV headers and skips invalid rows",()=>{const input=["#separator \\x09","#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tconn_state\torig_bytes\tresp_bytes\torig_pkts\tresp_pkts","1784160000\tC2\t192.168.1.3\t51000\t8.8.8.8\t53\tudp\tSF\t20\t40\t1\t1","invalid"].join("\n");const result=parseZeek(input);assert.equal(result.flows.length,1);assert.equal(result.flows[0].proto,"udp");assert.equal(result.rejected,1);});
