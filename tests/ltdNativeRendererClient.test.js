import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
    LTD_NATIVE_RENDER_ORCHESTRATOR_ABI_VERSION,
    LTD_NATIVE_RENDER_ORCHESTRATOR_CONTRACT_SHA256,
    LTD_NATIVE_RUNTIME_PROTOCOL,
    LTD_NATIVE_RUNTIME_PROTOCOL_VERSION,
    NativeLtdRuntimeError,
    NativeLtdRuntimePool
} from "../ltdNativeRendererClient.js";


const VALID_RENDER_ORCHESTRATOR = Object.freeze({
    linked: true,
    abi_matches: true,
    abi_version: LTD_NATIVE_RENDER_ORCHESTRATOR_ABI_VERSION,
    contract_matches: true,
    contract_sha256: LTD_NATIVE_RENDER_ORCHESTRATOR_CONTRACT_SHA256,
    activation_ready: true
});

const INVALID_RENDER_ORCHESTRATORS = Object.freeze([
    ["unlinked", { ...VALID_RENDER_ORCHESTRATOR, linked: false }],
    ["ABI mismatch flag", { ...VALID_RENDER_ORCHESTRATOR, abi_matches: false }],
    ["wrong ABI", { ...VALID_RENDER_ORCHESTRATOR, abi_version: 3 }],
    ["contract mismatch flag", { ...VALID_RENDER_ORCHESTRATOR, contract_matches: false }],
    ["wrong contract", { ...VALID_RENDER_ORCHESTRATOR, contract_sha256: "0".repeat(64) }],
    ["inactive orchestrator", { ...VALID_RENDER_ORCHESTRATOR, activation_ready: false }]
]);


async function makeRuntimeFixture(t, body, {
    activationReady = true,
    readinessOrchestrator = VALID_RENDER_ORCHESTRATOR
} = {}) {
    const directory = await fs.promises.mkdtemp(path.join(os.tmpdir(), "ltd-native-client-test-"));
    t.after(() => fs.promises.rm(directory, {
        recursive: true,
        force: true,
        maxRetries: 10,
        retryDelay: 25
    }));
    const script = path.join(directory, "runtime.cjs");
    const source = `
const readline = require("node:readline");
const protocol = ${JSON.stringify(LTD_NATIVE_RUNTIME_PROTOCOL)};
const version = ${LTD_NATIVE_RUNTIME_PROTOCOL_VERSION};
function send(request, ok, result, error) {
    process.stdout.write(JSON.stringify({
        protocol,
        version,
        request_id: request.request_id,
        op: request.op,
        ok,
        ...(ok ? { result } : { error })
    }) + "\\n");
}
const lines = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
lines.on("line", line => {
    const request = JSON.parse(line);
    if (request.op === "hello") {
        send(request, true, {
            native_process_id: process.pid,
            process_model: "persistent-stdin-stdout-jsonl",
            runtime_version: "test-v1"
        });
        return;
    }
    if (request.op === "readiness") {
        send(request, true, {
            protocol_ready: true,
            activation_ready: ${activationReady === true},
            render_modules: {
                render_orchestrator: ${JSON.stringify(readinessOrchestrator)}
            }
        });
        return;
    }
    ${body}
});
`;
    await fs.promises.writeFile(script, source, "utf8");
    return { directory, script };
}


function makePool(fixture, options = {}) {
    return new NativeLtdRuntimePool({
        command: process.execPath,
        commandArgs: [fixture.script],
        cwd: process.cwd(),
        maxWorkers: 1,
        ...options
    });
}


test("native LTD runtime pool validates its handshake and reuses a process", async t => {
    const fixture = await makeRuntimeFixture(t, `
        send(request, true, { pid: process.pid, value: request.value });
    `);
    const pool = makePool(fixture);
    t.after(() => pool.close());
    const first = await pool.run({ op: "render_ltd", value: 1 }, { timeoutMs: 2_000 });
    const second = await pool.run({ op: "render_ltd", value: 2 }, { timeoutMs: 2_000 });
    assert.equal(first.value, 1);
    assert.equal(second.value, 2);
    assert.equal(second.pid, first.pid);
});


for (const [label, readinessOrchestrator] of INVALID_RENDER_ORCHESTRATORS) {
    test(`native LTD runtime rejects readiness with ${label}`, async t => {
        const fixture = await makeRuntimeFixture(
            t,
            "send(request, true, {});",
            { readinessOrchestrator }
        );
        const pool = makePool(fixture);
        t.after(() => pool.close());
        await assert.rejects(
            pool.run({ op: "parse_ltd" }, { timeoutMs: 2_000 }),
            error => error instanceof NativeLtdRuntimeError
                && error.code === "NATIVE_RUNTIME_PROTOCOL_ERROR"
                && error.workerUnavailable === true
        );
    });
}


test("native LTD runtime returns structured request failures without retiring a healthy process", async t => {
    const fixture = await makeRuntimeFixture(t, `
        if (request.reject === true) {
            send(request, false, null, { code: "INVALID_RENDER", message: "invalid render request" });
        } else {
            send(request, true, { pid: process.pid });
        }
    `);
    const pool = makePool(fixture);
    t.after(() => pool.close());
    await assert.rejects(
        pool.run({ op: "render_ltd", reject: true }, { timeoutMs: 2_000 }),
        error => error instanceof NativeLtdRuntimeError
            && error.code === "INVALID_RENDER"
            && error.workerUnavailable === false
    );
    const recovered = await pool.run({ op: "render_ltd" }, { timeoutMs: 2_000 });
    assert.ok(Number.isInteger(recovered.pid));
});


test("native LTD runtime protocol mismatch and timeout fail closed", async t => {
    const badFixture = await makeRuntimeFixture(t, `
        process.stdout.write(JSON.stringify({
            protocol: "wrong",
            version,
            request_id: request.request_id,
            op: request.op,
            ok: true,
            result: {}
        }) + "\\n");
    `);
    const badPool = makePool(badFixture);
    t.after(() => badPool.close());
    await assert.rejects(
        badPool.run({ op: "render_ltd" }, { timeoutMs: 1_000 }),
        error => error instanceof NativeLtdRuntimeError
            && error.code === "NATIVE_RUNTIME_PROTOCOL_ERROR"
            && error.workerUnavailable === true
    );

    const stalledFixture = await makeRuntimeFixture(t, "// Deliberately never answer.");
    const stalledPool = makePool(stalledFixture);
    t.after(() => stalledPool.close());
    await assert.rejects(
        stalledPool.run({ op: "render_ltd" }, { timeoutMs: 50 }),
        error => error instanceof NativeLtdRuntimeError
            && error.code === "NATIVE_RUNTIME_REQUEST_TIMEOUT"
            && error.workerUnavailable === true
    );
});


test("native LTD runtime enforces the 64 KiB request boundary", async t => {
    const fixture = await makeRuntimeFixture(t, "send(request, true, {});");
    const pool = makePool(fixture);
    t.after(() => pool.close());
    await assert.rejects(
        pool.run({ op: "render_ltd", oversized: "x".repeat(70 * 1024) }),
        error => error instanceof NativeLtdRuntimeError
            && error.code === "NATIVE_RUNTIME_REQUEST_TOO_LARGE"
    );
});


test("each native runtime worker rejects rendering when its own readiness is false", async t => {
    const fixture = await makeRuntimeFixture(
        t,
        "send(request, true, { should_not_run: true });",
        { activationReady: false }
    );
    const pool = makePool(fixture);
    t.after(() => pool.close());
    await assert.rejects(
        pool.run({ op: "render_ltd" }, { timeoutMs: 2_000 }),
        error => error instanceof NativeLtdRuntimeError
            && error.code === "NATIVE_RUNTIME_NOT_READY"
            && error.workerUnavailable === true
    );
    const parserResult = await pool.run({ op: "parse_ltd" }, { timeoutMs: 2_000 });
    assert.equal(parserResult.should_not_run, true);
});
