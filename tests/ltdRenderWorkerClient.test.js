import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";

import {
    LTD_RENDER_WORKER_PROTOCOL,
    LTD_RENDER_WORKER_PROTOCOL_VERSION,
    PersistentRenderWorkerError,
    PersistentRenderWorkerPool
} from "../ltdRenderWorkerClient.js";

const execFileAsync = promisify(execFile);

async function makeWorkerFixture(t, body) {
    const directory = await fs.promises.mkdtemp(path.join(os.tmpdir(), "ltd-worker-client-test-"));
    t.after(() => fs.promises.rm(directory, {
        recursive: true,
        force: true,
        maxRetries: 10,
        retryDelay: 25
    }));
    const script = path.join(directory, "worker.cjs");
    await fs.promises.writeFile(script, body, "utf8");
    return { directory, script };
}


function fixtureSource(responseBody) {
    return `
const readline = require("node:readline");
const protocol = ${JSON.stringify(LTD_RENDER_WORKER_PROTOCOL)};
const version = ${LTD_RENDER_WORKER_PROTOCOL_VERSION};
process.stdout.write(JSON.stringify({ protocol, protocol_version: version, kind: "ready", native: false }) + "\\n");
const lines = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
lines.on("line", requestLine => {
    const request = JSON.parse(requestLine);
    ${responseBody}
});
`;
}


test("persistent render worker pool reuses a protocol-checked worker", async t => {
    const fixture = await makeWorkerFixture(t, fixtureSource(`
        process.stdout.write(JSON.stringify({
            protocol,
            protocol_version: version,
            request_id: request.request_id,
            code: 0,
            stdout: String(process.pid),
            stderr: "",
            elapsed_ms: 1.25,
            restart_required: false
        }) + "\\n");
    `));
    const pool = new PersistentRenderWorkerPool({
        command: process.execPath,
        workerScript: fixture.script,
        cwd: process.cwd(),
        maxWorkers: 1
    });
    t.after(() => pool.close());
    const first = await pool.run({ value: 1 }, { timeoutMs: 2_000 });
    const second = await pool.run({ value: 2 }, { timeoutMs: 2_000 });
    assert.equal(first.code, 0);
    assert.equal(first.persistentWorker, true);
    assert.equal(second.stdout, first.stdout, "the same warm process should serve both requests");
});


test("restart_required retires a worker before the next request", async t => {
    const fixture = await makeWorkerFixture(t, fixtureSource(`
        process.stdout.write(JSON.stringify({
            protocol,
            protocol_version: version,
            request_id: request.request_id,
            code: 1,
            stdout: String(process.pid),
            stderr: "cache family changed",
            elapsed_ms: 1,
            restart_required: true
        }) + "\\n");
    `));
    const pool = new PersistentRenderWorkerPool({
        command: process.execPath,
        workerScript: fixture.script,
        cwd: process.cwd(),
        maxWorkers: 1
    });
    t.after(() => pool.close());
    const first = await pool.run({}, { timeoutMs: 2_000 });
    const second = await pool.run({}, { timeoutMs: 2_000 });
    assert.notEqual(second.stdout, first.stdout, "a restart-required process must not be reused");
});


test("an in-flight worker response keeps a short-lived caller alive, then releases it", async t => {
    const fixture = await makeWorkerFixture(t, fixtureSource(`
        setTimeout(() => process.stdout.write(JSON.stringify({
            protocol,
            protocol_version: version,
            request_id: request.request_id,
            code: 0,
            stdout: "delayed response consumed",
            stderr: "",
            elapsed_ms: 150,
            restart_required: false
        }) + "\\n"), 150);
    `));
    const runner = path.join(fixture.directory, "runner.mjs");
    const clientUrl = pathToFileURL(path.resolve("ltdRenderWorkerClient.js")).href;
    await fs.promises.writeFile(runner, `
        import { PersistentRenderWorkerPool } from ${JSON.stringify(clientUrl)};
        const pool = new PersistentRenderWorkerPool({
            command: process.execPath,
            workerScript: ${JSON.stringify(fixture.script)},
            cwd: process.cwd(),
            maxWorkers: 1
        });
        const result = await pool.run({}, { timeoutMs: 2_000 });
        process.stdout.write(result.stdout);
    `, "utf8");
    const started = Date.now();
    const result = await execFileAsync(process.execPath, [runner], {
        cwd: process.cwd(),
        timeout: 5_000,
        windowsHide: true
    });
    assert.equal(result.stderr, "");
    assert.equal(result.stdout, "delayed response consumed");
    assert.ok(Date.now() - started >= 100, "the caller exited before the delayed response");
});


test("protocol mismatch and request timeout fail closed", async t => {
    const badHandshake = await makeWorkerFixture(t, `
        process.stdout.write(JSON.stringify({ protocol: "wrong", protocol_version: 1, kind: "ready", native: false }) + "\\n");
        process.stdin.resume();
    `);
    const badPool = new PersistentRenderWorkerPool({
        command: process.execPath,
        workerScript: badHandshake.script,
        cwd: process.cwd(),
        maxWorkers: 1,
        startupTimeoutMs: 1_000
    });
    t.after(() => badPool.close());
    await assert.rejects(
        badPool.run({}, { timeoutMs: 1_000 }),
        error => error instanceof PersistentRenderWorkerError
            && error.code === "WORKER_PROTOCOL_ERROR"
            && error.workerUnavailable === true
    );

    const stalled = await makeWorkerFixture(t, fixtureSource("// Deliberately never answer."));
    const stalledPool = new PersistentRenderWorkerPool({
        command: process.execPath,
        workerScript: stalled.script,
        cwd: process.cwd(),
        maxWorkers: 1
    });
    t.after(() => stalledPool.close());
    await assert.rejects(
        stalledPool.run({}, { timeoutMs: 50 }),
        error => error instanceof PersistentRenderWorkerError
            && error.code === "WORKER_REQUEST_TIMEOUT"
    );
});
