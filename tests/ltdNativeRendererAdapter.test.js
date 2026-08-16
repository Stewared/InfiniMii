import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
    closeNativeLtdRuntimePools,
    resolveNativeLtdRuntimeConfiguration,
    tryNativeLtdRender
} from "../ltdNativeRendererAdapter.js";
import {
    LTD_NATIVE_RENDER_ORCHESTRATOR_ABI_VERSION,
    LTD_NATIVE_RENDER_ORCHESTRATOR_CONTRACT_SHA256
} from "../ltdNativeRendererClient.js";


const HASH = crypto.createHash("sha256").update("fixture").digest("hex");
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


async function makeRendererFixture(t, {
    activationReady,
    readinessOrchestrator = VALID_RENDER_ORCHESTRATOR,
    adapterReadinessOrchestrator = readinessOrchestrator,
    renderOrchestrator = VALID_RENDER_ORCHESTRATOR,
    renderBody = ""
}) {
    const root = await fs.promises.mkdtemp(path.join(os.tmpdir(), "native-ltd-adapter-test-"));
    t.after(async () => {
        closeNativeLtdRuntimePools();
        await fs.promises.rm(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 25 });
    });
    for (const directory of [
        ["native_runtime", "build"],
        ["native_runtime", "generated"],
        ["renderer", "assets", "models"],
        ["renderer", "assets", "face_sprite_mips"],
        ["renderer", "assets", "texture_mips"],
        ["renderer", "assets", "animations"]
    ]) await fs.promises.mkdir(path.join(root, ...directory), { recursive: true });
    await Promise.all([
        fs.promises.writeFile(path.join(root, "native_runtime", "generated", "native_parts_catalog.bin"), "catalog"),
        fs.promises.writeFile(path.join(root, "renderer", "assets", "animations", "IconPose.json"), "{}")
    ]);
    const runtime = path.join(root, "native_runtime", "build", "ltd_native_runtime.exe");
    const protocol = "infinimii.ltd-native-runtime";
    const source = `
const readline = require("node:readline");
const handshakeOrchestrator = ${JSON.stringify(readinessOrchestrator)};
const adapterOrchestrator = ${JSON.stringify(adapterReadinessOrchestrator)};
const renderOrchestrator = ${JSON.stringify(renderOrchestrator)};
let readinessCalls = 0;
function send(request, ok, result, error) {
    process.stdout.write(JSON.stringify({
        protocol: ${JSON.stringify(protocol)}, version: 1,
        request_id: request.request_id, op: request.op, ok,
        ...(ok ? { result } : { error })
    }) + "\\n");
}
readline.createInterface({ input: process.stdin, crlfDelay: Infinity }).on("line", line => {
    const request = JSON.parse(line);
    if (request.op === "hello") return send(request, true, {
        native_process_id: process.pid,
        process_model: "persistent-stdin-stdout-jsonl",
        runtime_version: "fixture-v1"
    });
    if (request.op === "readiness") {
        const orchestrator = readinessCalls++ === 0
            ? handshakeOrchestrator
            : adapterOrchestrator;
        return send(request, true, {
            protocol_ready: true,
            activation_ready: ${activationReady === true},
            render_modules: { render_orchestrator: orchestrator }
        });
    }
    ${renderBody}
});
`;
    // The adapter launches this through process.execPath in tests by replacing
    // the executable configuration after its filesystem contract is checked.
    await fs.promises.writeFile(runtime, source);
    const ltdPath = path.join(root, "source.ltd");
    const outputDirectory = path.join(root, "output");
    await Promise.all([
        fs.promises.writeFile(ltdPath, "ltd"),
        fs.promises.mkdir(outputDirectory)
    ]);
    const config = resolveNativeLtdRuntimeConfiguration(root);
    return {
        root,
        runtime,
        config: Object.freeze({
            ...config,
            executable: process.execPath,
            commandArgs: Object.freeze([runtime])
        }),
        ltdPath,
        outputDirectory,
        request: {
            ltdPath,
            outputDirectory,
            size: 128,
            view: "portrait",
            presentationContextKind: "none",
            presentationContextSha256: HASH
        },
    };
}


test("native adapter stays inactive when the runtime readiness gate is false", async t => {
    const fixture = await makeRendererFixture(t, { activationReady: false });
    const result = await tryNativeLtdRender(fixture.config, fixture.request, { timeoutMs: 2_000 });
    assert.deepEqual(result, { activated: false, reason: "not-ready" });
});


for (const [label, adapterReadinessOrchestrator] of INVALID_RENDER_ORCHESTRATORS) {
    test(`native adapter rejects explicit readiness with ${label}`, async t => {
        const fixture = await makeRendererFixture(t, {
            activationReady: true,
            adapterReadinessOrchestrator
        });
        const result = await tryNativeLtdRender(
            fixture.config,
            fixture.request,
            { timeoutMs: 2_000 }
        );
        assert.deepEqual(result, { activated: false, reason: "not-ready" });
    });
}


test("native adapter accepts only a report bound to its exact request", async t => {
    const report = {
        input_sha256: HASH,
        presentation_context: { kind: "none", sha256: HASH },
        outputs: [{
            path: "mii.png",
            view: "appearance_bust_portrait",
            size: [128, 128],
            supersampling: { portable_profile: "native-resolution-v1", raster_size: [128, 128] },
            sha256: HASH
        }]
    };
    const fixture = await makeRendererFixture(t, {
        activationReady: true,
        renderBody: `
        const fs = require("node:fs");
        const path = require("node:path");
        const crypto = require("node:crypto");
        const outputPath = path.resolve(request.output_dir, "mii.png");
        const reportPath = path.resolve(request.output_dir, "render_report.json");
        const outputBytes = Buffer.from("native-png-fixture");
        const report = ${JSON.stringify(report)};
        report.outputs[0].sha256 = crypto.createHash("sha256").update(outputBytes).digest("hex");
        const reportBytes = Buffer.from(JSON.stringify(report) + "\\n");
        fs.writeFileSync(outputPath, outputBytes);
        fs.writeFileSync(reportPath, reportBytes);
        send(request, true, {
            activation_ready: true,
            modules: { render_orchestrator: renderOrchestrator },
            pixels_produced: true,
            png_produced: true,
            files_written: true,
            transaction_cleanup_complete: true,
            input_sha256: ${JSON.stringify(HASH)},
            output_path: outputPath,
            output_sha256: report.outputs[0].sha256,
            report_path: reportPath,
            report_sha256: crypto.createHash("sha256").update(reportBytes).digest("hex"),
            render_report: report
        });`
    });
    const accepted = await tryNativeLtdRender(fixture.config, fixture.request, { timeoutMs: 2_000 });
    assert.equal(accepted.activated, true, JSON.stringify({
        reason: accepted.reason,
        errorCode: accepted.error?.code,
        errorMessage: accepted.error?.message,
        diagnostics: accepted.error?.diagnostics
    }));

    closeNativeLtdRuntimePools();
    const tampered = {
        ...fixture.request,
        presentationContextSha256: "0".repeat(64)
    };
    const rejected = await tryNativeLtdRender(fixture.config, tampered, { timeoutMs: 2_000 });
    assert.equal(rejected.activated, false);
    assert.equal(rejected.reason, "invalid-result");
});


for (const [label, renderOrchestrator] of INVALID_RENDER_ORCHESTRATORS) {
    test(`native adapter rejects an activated result with ${label}`, async t => {
        const fixture = await makeRendererFixture(t, {
            activationReady: true,
            renderOrchestrator,
            renderBody: `
            const fs = require("node:fs");
            const path = require("node:path");
            const crypto = require("node:crypto");
            const outputPath = path.resolve(request.output_dir, "mii.png");
            const reportPath = path.resolve(request.output_dir, "render_report.json");
            const outputBytes = Buffer.from("native-png-fixture");
            const outputSha = crypto.createHash("sha256").update(outputBytes).digest("hex");
            const report = {
                input_sha256: ${JSON.stringify(HASH)},
                presentation_context: { kind: "none", sha256: ${JSON.stringify(HASH)} },
                outputs: [{
                    path: "mii.png", view: "appearance_bust_portrait", size: [128, 128],
                    supersampling: { portable_profile: "native-resolution-v1", raster_size: [128, 128] },
                    sha256: outputSha
                }]
            };
            const reportBytes = Buffer.from(JSON.stringify(report) + "\\n");
            fs.writeFileSync(outputPath, outputBytes);
            fs.writeFileSync(reportPath, reportBytes);
            send(request, true, {
                activation_ready: true,
                modules: { render_orchestrator: renderOrchestrator },
                pixels_produced: true,
                png_produced: true,
                files_written: true,
                transaction_cleanup_complete: true,
                input_sha256: ${JSON.stringify(HASH)},
                output_path: outputPath,
                output_sha256: outputSha,
                report_path: reportPath,
                report_sha256: crypto.createHash("sha256").update(reportBytes).digest("hex"),
                render_report: report
            });`
        });
        const result = await tryNativeLtdRender(
            fixture.config,
            fixture.request,
            { timeoutMs: 2_000 }
        );
        assert.equal(result.activated, false);
        assert.equal(result.reason, "invalid-result");
    });
}


test("native adapter rejects claimed activation when published bytes do not match", async t => {
    const fixture = await makeRendererFixture(t, {
        activationReady: true,
        renderBody: `
        const fs = require("node:fs");
        const path = require("node:path");
        const outputPath = path.resolve(request.output_dir, "mii.png");
        const reportPath = path.resolve(request.output_dir, "render_report.json");
        const report = {
            input_sha256: ${JSON.stringify(HASH)},
            presentation_context: { kind: "none", sha256: ${JSON.stringify(HASH)} },
            outputs: [{
                path: "mii.png", view: "appearance_bust_portrait", size: [128, 128],
                supersampling: { portable_profile: "native-resolution-v1", raster_size: [128, 128] },
                sha256: ${JSON.stringify(HASH)}
            }]
        };
        fs.writeFileSync(outputPath, "different output bytes");
        fs.writeFileSync(reportPath, JSON.stringify(report) + "\\n");
        send(request, true, {
            activation_ready: true, pixels_produced: true, png_produced: true,
            modules: { render_orchestrator: renderOrchestrator },
            files_written: true, input_sha256: ${JSON.stringify(HASH)},
            transaction_cleanup_complete: true,
            output_path: outputPath, output_sha256: ${JSON.stringify(HASH)},
            report_path: reportPath, report_sha256: ${JSON.stringify(HASH)},
            render_report: report
        });`
    });
    const result = await tryNativeLtdRender(fixture.config, fixture.request, { timeoutMs: 2_000 });
    assert.equal(result.activated, false);
    assert.equal(result.reason, "invalid-result");
});


for (const mutation of [
    "files-written-false",
    "cleanup-incomplete",
    "missing-report",
    "wrong-report-hash",
    "different-report-body"
]) {
    test(`native adapter rejects ${mutation}`, async t => {
        const fixture = await makeRendererFixture(t, {
            activationReady: true,
            renderBody: `
            const fs = require("node:fs");
            const path = require("node:path");
            const crypto = require("node:crypto");
            const outputPath = path.resolve(request.output_dir, "mii.png");
            const reportPath = path.resolve(request.output_dir, "render_report.json");
            const outputBytes = Buffer.from("valid native output");
            const outputSha = crypto.createHash("sha256").update(outputBytes).digest("hex");
            const responseReport = {
                input_sha256: ${JSON.stringify(HASH)},
                presentation_context: { kind: "none", sha256: ${JSON.stringify(HASH)} },
                outputs: [{
                    path: "mii.png", view: "appearance_bust_portrait", size: [128, 128],
                    supersampling: { portable_profile: "native-resolution-v1", raster_size: [128, 128] },
                    sha256: outputSha
                }]
            };
            const storedReport = ${JSON.stringify(mutation)} === "different-report-body"
                ? { ...responseReport, unexpected: true }
                : responseReport;
            const reportBytes = Buffer.from(JSON.stringify(storedReport) + "\\n");
            fs.writeFileSync(outputPath, outputBytes);
            if (${JSON.stringify(mutation)} !== "missing-report") fs.writeFileSync(reportPath, reportBytes);
            send(request, true, {
                activation_ready: true, pixels_produced: true, png_produced: true,
                modules: { render_orchestrator: renderOrchestrator },
                files_written: ${JSON.stringify(mutation)} !== "files-written-false",
                transaction_cleanup_complete: ${JSON.stringify(mutation)} !== "cleanup-incomplete",
                input_sha256: ${JSON.stringify(HASH)},
                output_path: outputPath, output_sha256: outputSha,
                report_path: reportPath,
                report_sha256: ${JSON.stringify(mutation)} === "wrong-report-hash"
                    ? ${JSON.stringify(HASH)}
                    : crypto.createHash("sha256").update(reportBytes).digest("hex"),
                render_report: responseReport
            });`
        });
        const result = await tryNativeLtdRender(fixture.config, fixture.request, { timeoutMs: 2_000 });
        assert.equal(result.activated, false);
        assert.equal(result.reason, "invalid-result");
    });
}
