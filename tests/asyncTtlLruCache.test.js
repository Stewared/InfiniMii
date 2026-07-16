import assert from "node:assert/strict";
import test from "node:test";

import { AsyncTtlLruCache } from "../asyncTtlLruCache.js";

test("coalesces concurrent loads and starts TTL after resolution", async () => {
    let now = 100;
    let resolveLoad;
    let loads = 0;
    const cache = new AsyncTtlLruCache({ ttlMs: 50, maximumEntries: 4, now: () => now });
    const loader = () => {
        loads += 1;
        return new Promise(resolve => { resolveLoad = resolve; });
    };

    const first = cache.get("mii", loader);
    const second = cache.get("mii", loader);
    await Promise.resolve();
    assert.equal(loads, 1);
    now = 1000;
    resolveLoad({ id: "mii" });
    assert.deepEqual(await first, { id: "mii" });
    assert.deepEqual(await second, { id: "mii" });

    now = 1049;
    assert.deepEqual(await cache.get("mii", () => assert.fail("cache should still be valid")), { id: "mii" });
    now = 1050;
    assert.deepEqual(await cache.get("mii", async () => ({ id: "refreshed" })), { id: "refreshed" });
});

test("evicts the least recently used resolved entry", async () => {
    let now = 0;
    let loads = 0;
    const cache = new AsyncTtlLruCache({ ttlMs: 100, maximumEntries: 2, now: () => now });
    const load = key => cache.get(key, async () => { loads += 1; return key; });

    await load("a");
    await load("b");
    await load("a");
    await load("c");
    assert.equal(cache.size, 2);
    await load("b");
    assert.equal(loads, 4);
});

test("does not cache loader failures", async () => {
    const cache = new AsyncTtlLruCache({ ttlMs: 100, maximumEntries: 2 });
    await assert.rejects(cache.get("bad", async () => { throw new Error("failed"); }), /failed/);
    assert.equal(await cache.get("bad", async () => "recovered"), "recovered");
});

test("supports synchronous cache probes and writes", () => {
    let now = 10;
    const cache = new AsyncTtlLruCache({ ttlMs: 5, maximumEntries: 2, now: () => now });
    assert.deepEqual(cache.getIfPresent("page"), { hit: false, value: undefined });
    cache.set("page", "html");
    assert.deepEqual(cache.getIfPresent("page"), { hit: true, value: "html" });
    now = 15;
    assert.deepEqual(cache.getIfPresent("page"), { hit: false, value: undefined });
});
