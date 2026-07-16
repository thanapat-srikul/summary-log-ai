import assert from "node:assert/strict";
import test from "node:test";
import { normalizeZeekEvent, validateIngestPayload } from "../lib/zeek";

const now=1_784_160_000_000;
const row={ts:now/1000,uid:"C123","id.orig_h":"192.168.1.2","id.orig_p":50000,"id.resp_h":"10.0.0.8","id.resp_p":443,proto:"TCP",service:"ssl",conn_state:"SF",duration:"-",orig_bytes:10,resp_bytes:20,orig_pkts:1,resp_pkts:2};
test("normalizes dotted Zeek fields and empty values",()=>{const event=normalizeZeekEvent(row,now);assert.equal(event?.orig_h,"192.168.1.2");assert.equal(event?.proto,"tcp");assert.equal(event?.duration,null);});
test("rejects future timestamps and batches above 100",()=>{assert.equal(normalizeZeekEvent({...row,ts:(now+11*60000)/1000},now),null);const result=validateIngestPayload({sourceId:"lab-1",sentAt:new Date(now).toISOString(),events:Array.from({length:101},()=>row)},now);assert.match(result.errors[0],/between 1 and 100/);});
