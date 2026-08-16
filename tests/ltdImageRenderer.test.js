import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import sharp from "sharp";

import {
    LtdRenderError,
    classifyRendererFailure,
    createRenderSlotLimiter,
    executeRenderAttemptWithRetry,
    getConfiguredLtdRendererRevision,
    loadFavoriteShirtPolicyContract,
    loadReferenceOutfitMipManifestContract,
    renderLtdImage,
    resetWorkerWorkspaceForColdFallback,
    resolveLtdRendererConfiguration,
    sanitizeChildDiagnostics,
    validateRenderReportBinding,
    validateTransparentRgbaPng
} from "../ltdImageRenderer.js";
import {
    getLtdPresentationContextSha256,
    LTD_PRESENTATION_CONTEXT_KIND
} from "../ltdPresentationContext.js";
import {
    DEFAULT_LTD_RENDERER_ASSET_ROOT,
    DEFAULT_LTD_RENDERER_ROOT,
    INFINIMII_ROOT,
    resolveLtdRuntimePaths
} from "../ltdRuntimePaths.js";

const RENDER_ENV_KEYS = [
    "LTD_RENDERER_ROOT",
    "LTD_RENDERER_ASSET_ROOT",
    "LTD_RENDERER_PYTHON",
    "LTD_RENDERER_PERSISTENT_WORKER"
];

function preserveRendererEnvironment(t) {
    const previous = Object.fromEntries(RENDER_ENV_KEYS.map(key => [key, process.env[key]]));
    t.after(() => {
        for (const key of RENDER_ENV_KEYS) {
            if (previous[key] === undefined) delete process.env[key];
            else process.env[key] = previous[key];
        }
    });
}

function assertRendererError(code, deterministic) {
    return error => error instanceof LtdRenderError
        && error.code === code
        && error.deterministic === deterministic;
}

test("LTD runtime paths default to the same-folder repository drop", () => {
    const paths = resolveLtdRuntimePaths({});
    assert.equal(paths.rendererRoot, DEFAULT_LTD_RENDERER_ROOT);
    assert.equal(paths.assetRoot, DEFAULT_LTD_RENDERER_ASSET_ROOT);
    assert.equal(
        paths.rendererRoot,
        path.join(INFINIMII_ROOT, "ltd-renderer", "dcmp")
    );
    assert.equal(
        paths.assetRoot,
        path.join(INFINIMII_ROOT, "ltd-renderer", "ltdDemo_converted_assets")
    );
});

test("renderer configuration fails closed when configured runtime directories are absent", t => {
    preserveRendererEnvironment(t);
    process.env.LTD_RENDERER_ROOT = "missing-ltd-test/renderer";
    process.env.LTD_RENDERER_ASSET_ROOT = "missing-ltd-test/assets";

    assert.throws(
        () => resolveLtdRendererConfiguration(),
        assertRendererError("LTD_RENDERER_NOT_CONFIGURED", false)
    );
});

test("persistent-worker fallback resets only its exact owned render workspace", async t => {
    const workspace = await fs.promises.mkdtemp(path.join(os.tmpdir(), "infinimii-ltd-render-test-"));
    t.after(() => fs.promises.rm(workspace, { recursive: true, force: true }));
    const input = path.join(workspace, "input.ltd");
    const activeParts = path.join(workspace, "active_parts.json");
    const output = path.join(workspace, "output");
    await fs.promises.mkdir(output);
    await Promise.all([
        fs.promises.writeFile(input, "input"),
        fs.promises.writeFile(activeParts, "active"),
        fs.promises.writeFile(path.join(output, "partial.png"), "partial")
    ]);
    await resetWorkerWorkspaceForColdFallback({
        input,
        build_active_parts: activeParts,
        output_dir: output
    });
    assert.equal(fs.existsSync(input), true);
    assert.equal(fs.existsSync(activeParts), false);
    assert.deepEqual(await fs.promises.readdir(output), []);

    await assert.rejects(
        resetWorkerWorkspaceForColdFallback({
            input,
            build_active_parts: path.join(workspace, "unexpected.json"),
            output_dir: output
        }),
        assertRendererError("RENDER_CLEANUP_FAILED", false)
    );
});

test("renderer configuration requires the audited scripts and capability ledger", async t => {
    preserveRendererEnvironment(t);
    const tempDirectory = await fs.promises.mkdtemp(path.join(os.tmpdir(), "infinimii-render-config-"));
    t.after(() => fs.promises.rm(tempDirectory, { recursive: true, force: true }));
    const root = path.join(tempDirectory, "renderer-root");
    const assetRoot = path.join(tempDirectory, "assets");
    await Promise.all([
        fs.promises.mkdir(path.join(root, "tools"), { recursive: true }),
        fs.promises.mkdir(path.join(root, "renderer"), { recursive: true }),
        fs.promises.mkdir(path.join(root, "manifests"), { recursive: true }),
        fs.promises.mkdir(assetRoot, { recursive: true })
    ]);
    process.env.LTD_RENDERER_ROOT = path.relative(INFINIMII_ROOT, root);
    process.env.LTD_RENDERER_ASSET_ROOT = path.relative(INFINIMII_ROOT, assetRoot);

    assert.throws(
        () => resolveLtdRendererConfiguration(),
        assertRendererError("LTD_RENDERER_NOT_CONFIGURED", false)
    );

    await Promise.all([
        fs.promises.writeFile(path.join(root, "tools", "build_mii_active_parts.py"), "# fixture\n"),
        fs.promises.writeFile(path.join(root, "renderer", "render_mii.py"), "# fixture\n"),
        fs.promises.writeFile(path.join(root, "renderer", "classic_bridge_resource_bundles.json"), "{}\n"),
        fs.promises.writeFile(path.join(root, "renderer", "classic_bridge_portrait_framing.json"), "{}\n"),
        fs.promises.writeFile(path.join(root, "renderer", "screen_space_face_shadow_source.json"), "{}\n"),
        fs.promises.writeFile(path.join(root, "manifests", "render_asset_byml_metadata.jsonl"), "{}\n")
    ]);
    const configuration = resolveLtdRendererConfiguration();
    assert.equal(configuration.root, path.resolve(root));
    assert.equal(configuration.assetRoot, path.resolve(assetRoot));
    assert.equal(configuration.python, "python");
    assert.equal(configuration.persistentWorkerEnabled, false, "legacy renderer roots can fall back cold");

    const firstRevision = getConfiguredLtdRendererRevision();
    assert.match(firstRevision, /^[0-9a-f]{64}$/);
    assert.equal(getConfiguredLtdRendererRevision(), firstRevision);

    process.env.LTD_RENDERER_PERSISTENT_WORKER = "invalid";
    assert.throws(
        () => resolveLtdRendererConfiguration(),
        assertRendererError("LTD_RENDERER_NOT_CONFIGURED", false)
    );
    process.env.LTD_RENDERER_PERSISTENT_WORKER = "0";
    assert.equal(resolveLtdRendererConfiguration().persistentWorkerEnabled, false);

    const secondRoot = path.join(tempDirectory, "renderer-root-2");
    await fs.promises.cp(root, secondRoot, { recursive: true });
    await fs.promises.appendFile(
        path.join(secondRoot, "renderer", "classic_bridge_portrait_framing.json"),
        " "
    );
    process.env.LTD_RENDERER_ROOT = secondRoot;
    assert.notEqual(
        getConfiguredLtdRendererRevision(),
        firstRevision,
        "the portrait framing contract participates in a fresh process identity"
    );

    const thirdRoot = path.join(tempDirectory, "renderer-root-3");
    await fs.promises.cp(root, thirdRoot, { recursive: true });
    await fs.promises.appendFile(
        path.join(thirdRoot, "renderer", "screen_space_face_shadow_source.json"),
        " "
    );
    process.env.LTD_RENDERER_ROOT = thirdRoot;
    assert.notEqual(
        getConfiguredLtdRendererRevision(),
        firstRevision,
        "the screen-space face-shadow source contract participates in a fresh process identity"
    );

    const nativeSourceRoot = path.join(tempDirectory, "renderer-root-native-source");
    await fs.promises.cp(root, nativeSourceRoot, { recursive: true });
    await fs.promises.writeFile(
        path.join(nativeSourceRoot, "renderer", "native_raster_kernel.c"),
        "/* exact native renderer fixture */\n"
    );
    process.env.LTD_RENDERER_ROOT = nativeSourceRoot;
    assert.notEqual(
        getConfiguredLtdRendererRevision(),
        firstRevision,
        "native renderer source participates in a fresh process identity"
    );

    const nativeBinaryRoot = path.join(tempDirectory, "renderer-root-native-binary");
    await fs.promises.cp(root, nativeBinaryRoot, { recursive: true });
    await fs.promises.writeFile(
        path.join(nativeBinaryRoot, "renderer", "_native_raster_kernel.fixture.pyd"),
        "compiled fixture bytes"
    );
    process.env.LTD_RENDERER_ROOT = nativeBinaryRoot;
    assert.notEqual(
        getConfiguredLtdRendererRevision(),
        firstRevision,
        "a loaded-platform native renderer artifact participates in a fresh process identity"
    );

    process.env.LTD_RENDERER_ROOT = root;
    await fs.promises.writeFile(path.join(root, "renderer", "new_dependency.py"), "# dependency\n");
    assert.equal(getConfiguredLtdRendererRevision(), firstRevision, "a process keeps one renderer identity until restart");
    await fs.promises.appendFile(configuration.capabilityLedger, " ");
    assert.equal(getConfiguredLtdRendererRevision(), firstRevision);
});

test("deployment build gate requires every production native LTD backend", async () => {
    const source = await fs.promises.readFile(
        new URL("../scripts/buildNativeLtdRenderer.js", import.meta.url),
        "utf8"
    );
    for (const builder of [
        "build_native_current_draw.py",
        "build_native_face_target.py",
        "build_native_raster_kernel.py"
    ]) {
        assert.match(source, new RegExp(builder.replaceAll(".", "\\.")));
    }
    for (const backend of [
        "native_current_draw",
        "native_face_target",
        "native_raster_kernel"
    ]) {
        assert.match(
            source,
            new RegExp(`assert ${backend}\\.BACKEND_AVAILABLE`),
            `${backend} must fail deployment closed when its extension is unavailable`
        );
    }
    assert.match(source, /native_runtime["'],\s*["']build\.ps1/);
    assert.match(source, /process\.platform === ["']win32["']/);
    assert.match(source, /ltd_native_runtime\.exe/);
    assert.match(source, /["']--probe["']/);
    assert.match(source, /readiness\?\.activation_ready !== true/);
    assert.match(source, /readiness\?\.capabilities\?\.native_render !== true/);
    assert.match(source, /readiness\?\.capabilities\?\.native_png !== true/);
});

test("renderer revision binds every manifest-listed reference-outfit mip byte", async t => {
    preserveRendererEnvironment(t);
    const tempDirectory = await fs.promises.mkdtemp(path.join(os.tmpdir(), "infinimii-mip-revision-"));
    t.after(() => fs.promises.rm(tempDirectory, { recursive: true, force: true }));
    const assetRoot = path.join(tempDirectory, "assets");
    await fs.promises.mkdir(assetRoot);

    const makeRoot = async (root, mipBytes) => {
        const mipDirectory = path.join(
            root,
            "renderer",
            "assets",
            "reference_outfit_texture_mips",
            "FixtureTexture"
        );
        await Promise.all([
            fs.promises.mkdir(path.join(root, "tools"), { recursive: true }),
            fs.promises.mkdir(path.join(root, "manifests"), { recursive: true }),
            fs.promises.mkdir(mipDirectory, { recursive: true })
        ]);
        await Promise.all([
            fs.promises.writeFile(path.join(root, "tools", "build_mii_active_parts.py"), "# fixture\n"),
            fs.promises.writeFile(path.join(root, "renderer", "render_mii.py"), "# fixture\n"),
            fs.promises.writeFile(path.join(root, "renderer", "classic_bridge_resource_bundles.json"), "{}\n"),
            fs.promises.writeFile(path.join(root, "renderer", "classic_bridge_portrait_framing.json"), "{}\n"),
            fs.promises.writeFile(path.join(root, "manifests", "render_asset_byml_metadata.jsonl"), "{}\n"),
            fs.promises.writeFile(path.join(mipDirectory, "mip_00.png"), mipBytes)
        ]);
        const manifest = {
            schema_version: 1,
            texture_count: 1,
            mip_level_count: 1,
            textures: [{
                name: "FixtureTexture",
                mip_count: 1,
                levels: [{
                    level: 0,
                    path: "renderer/assets/reference_outfit_texture_mips/FixtureTexture/mip_00.png",
                    byte_length: mipBytes.length,
                    sha256: crypto.createHash("sha256").update(mipBytes).digest("hex")
                }]
            }]
        };
        await fs.promises.writeFile(
            path.join(root, "renderer", "reference_outfit_texture_mips.json"),
            `${JSON.stringify(manifest, null, 2)}\n`
        );
    };

    const firstRoot = path.join(tempDirectory, "renderer-root-a");
    await makeRoot(firstRoot, Buffer.from("first exact mip"));
    process.env.LTD_RENDERER_ROOT = firstRoot;
    process.env.LTD_RENDERER_ASSET_ROOT = assetRoot;
    const firstRevision = getConfiguredLtdRendererRevision();

    const staleRoot = path.join(tempDirectory, "renderer-root-stale");
    await fs.promises.cp(firstRoot, staleRoot, { recursive: true });
    await fs.promises.writeFile(
        path.join(
            staleRoot,
            "renderer",
            "assets",
            "reference_outfit_texture_mips",
            "FixtureTexture",
            "mip_00.png"
        ),
        "stale changed mip"
    );
    process.env.LTD_RENDERER_ROOT = staleRoot;
    assert.throws(
        () => getConfiguredLtdRendererRevision(),
        assertRendererError("LTD_RENDERER_NOT_CONFIGURED", false),
        "a mip mutation without a matching ledger update must fail closed"
    );

    const freshRoot = path.join(tempDirectory, "renderer-root-fresh");
    await makeRoot(freshRoot, Buffer.from("new exact mip"));
    process.env.LTD_RENDERER_ROOT = freshRoot;
    assert.notEqual(
        getConfiguredLtdRendererRevision(),
        firstRevision,
        "new ledger-bound mip bytes must produce a fresh renderer revision"
    );
});

test("unsupported renderer options are rejected before configuration or execution", async t => {
    preserveRendererEnvironment(t);
    delete process.env.LTD_RENDERER_ROOT;
    delete process.env.LTD_RENDERER_ASSET_ROOT;

    await assert.rejects(
        renderLtdImage(Buffer.from([0]), { expression: "smile" }),
        assertRendererError("UNSUPPORTED_RENDER_OPTIONS", true)
    );
    for (const size of [127, 1025, "128px", 128.5]) {
        await assert.rejects(
            renderLtdImage(Buffer.from([0]), { size }),
            assertRendererError("UNSUPPORTED_RENDER_OPTIONS", true),
            `size ${size} should fail closed`
        );
    }
});

test("valid options do not bypass missing renderer configuration", async t => {
    preserveRendererEnvironment(t);
    process.env.LTD_RENDERER_ROOT = "missing-ltd-test/renderer";
    process.env.LTD_RENDERER_ASSET_ROOT = "missing-ltd-test/assets";

    await assert.rejects(
        renderLtdImage(Buffer.from([0]), { size: 128, fullBody: false }),
        assertRendererError("LTD_RENDERER_NOT_CONFIGURED", false)
    );
});

test("explicit classic-bridge fail-closed boundaries are deterministic", () => {
    for (const stderr of [
        "ValueError: wrinkle_upper requires a separate faceline target not supported by classic bridge",
        "ValueError: wrinkle_upper is unresolved; classic bridge fails closed",
        "ValueError: extended_faceline_color_unimplemented: faceline_color=112",
        "ValueError: classic_faceline_wrinkle_selection_unimplemented: WrinkleUpper09"
    ]) {
        const error = classifyRendererFailure({ stdout: "", stderr });
        assert.ok(error instanceof LtdRenderError);
        assert.equal(error.code, "UNSUPPORTED_LTD_RENDER_PATH");
        assert.equal(error.deterministic, true);
        assert.equal(error.status, 422);
    }

    for (const stderr of [
        "RuntimeError: classic_faceline_wrinkle_selection evidence hash mismatch",
        "FileNotFoundError: classic_faceline_wrinkle_selection ledger is missing"
    ]) {
        const error = classifyRendererFailure({ code: 1, stdout: "", stderr });
        assert.equal(error.code, "RENDER_FAILED");
        assert.equal(error.deterministic, false);
    }
});

test("explicit CharInfoEx domain failures are invalid LTD input", () => {
    for (const stderr of [
        "glass_lens_material_mode must be 0, 1, or 2, got 3",
        "classic capability requires char_info.glass_lens_material_mode=0, got 3"
    ]) {
        const error = classifyRendererFailure({ stdout: "", stderr });
        assert.equal(error.code, "INVALID_LTD");
        assert.equal(error.deterministic, true);
        assert.equal(error.status, 400);
    }
});

test("valid values outside a classic capability remain deterministic 422 gaps", () => {
    for (const mode of [1, 2]) {
        const error = classifyRendererFailure({
            stdout: "",
            stderr: `ValueError: classic capability requires char_info.glass_lens_material_mode=0, got ${mode}`
        });
        assert.equal(error.code, "UNSUPPORTED_LTD_RESOURCE_SIGNATURE");
        assert.equal(error.deterministic, true);
        assert.equal(error.status, 422);
    }
});

test("component-catalog misses remain deterministic resource gaps", () => {
    for (const stderr of [
        "ValueError: classic-bridge composition has unstaged components: model:MiiHairAllLegacy999",
        "ValueError: classic-bridge model role is not composable: hair",
        "ValueError: classic-bridge face-texture role is not composable: mouth"
    ]) {
        const error = classifyRendererFailure({ stdout: "", stderr });
        assert.equal(error.code, "UNSUPPORTED_LTD_RESOURCE_SIGNATURE");
        assert.equal(error.deterministic, true);
        assert.equal(error.status, 422);
    }
});

test("observed exact bridge capability rejections are deterministic 422 failures", () => {
    const cases = [
        ["classic-bridge composition lacks a required active base component", "UNSUPPORTED_LTD_RESOURCE_SIGNATURE"],
        ["classic-bridge selector is outside the exact component domain: ear", "UNSUPPORTED_LTD_RESOURCE_SIGNATURE"],
        ["classic resource bundle has no source-backed resource-signature capability", "UNSUPPORTED_LTD_RESOURCE_SIGNATURE"],
        ["classic-bridge composition enables an unsupported optional component", "UNSUPPORTED_LTD_RENDER_PATH"],
        ["classic-bridge generated faceline layers lack an exact contract", "UNSUPPORTED_LTD_RENDER_PATH"]
    ];
    for (const [stderr, code] of cases) {
        const error = classifyRendererFailure({ code: 1, stdout: "", stderr });
        assert.equal(error.code, code);
        assert.equal(error.deterministic, true);
        assert.equal(error.status, 422);
    }

    const missingBfres = classifyRendererFailure({
        code: 1,
        stdout: "",
        stderr: "RuntimeError: selected BFRES resource is missing from the deployed asset root"
    });
    assert.equal(missingBfres.code, "RENDER_FAILED");
    assert.equal(missingBfres.deterministic, false);
    assert.equal(missingBfres.status, 503);
});

test("non-deterministic child diagnostics are bounded and redact render workspaces", () => {
    const workspace = path.join(os.tmpdir(), "infinimii-ltd-render-secret123");
    const error = classifyRendererFailure({
        code: 7,
        stdout: "renderer started",
        stderr: `Traceback at ${path.join(workspace, "input.ltd")}\nRuntimeError: driver reset`
    }, { sensitivePaths: [workspace] });
    assert.equal(error.code, "RENDER_FAILED");
    assert.equal(error.deterministic, false);
    assert.match(error.diagnostics, /exitCode=7/);
    assert.match(error.diagnostics, /driver reset/);
    assert.doesNotMatch(error.diagnostics, /secret123/);
    assert.ok(error.diagnostics.length <= 16 * 1024);
    assert.match(sanitizeChildDiagnostics({ code: 2, stderr: "failure" }), /exitCode=2/);
});

test("the native image contract accepts a canonical hard-edged foreground", async () => {
    const rgb = await sharp({
        create: { width: 2, height: 2, channels: 3, background: { r: 1, g: 2, b: 3 } }
    }).png().toBuffer();
    await assert.rejects(
        validateTransparentRgbaPng(rgb, 2, { rasterProfile: "native-resolution-v1" }),
        assertRendererError("RENDER_OUTPUT_NOT_TRANSPARENT", false)
    );

    const opaqueRgba = await sharp(Buffer.from([
        1, 2, 3, 255, 1, 2, 3, 255,
        1, 2, 3, 255, 1, 2, 3, 255
    ]), { raw: { width: 2, height: 2, channels: 4 } }).png().toBuffer();
    await assert.rejects(
        validateTransparentRgbaPng(opaqueRgba, 2, { rasterProfile: "native-resolution-v1" }),
        assertRendererError("RENDER_OUTPUT_NOT_TRANSPARENT", false)
    );

    const fullyTransparentMagenta = await sharp(Buffer.from([
        255, 0, 255, 0, 255, 0, 255, 0,
        255, 0, 255, 0, 255, 0, 255, 0
    ]), { raw: { width: 2, height: 2, channels: 4 } }).png().toBuffer();
    await assert.rejects(
        validateTransparentRgbaPng(fullyTransparentMagenta, 2, { rasterProfile: "native-resolution-v1" }),
        assertRendererError("RENDER_OUTPUT_NOT_TRANSPARENT", false)
    );

    const hiddenRgbMatte = await sharp(Buffer.from([
        255, 0, 255, 0, 1, 2, 3, 128,
        1, 2, 3, 255, 1, 2, 3, 255
    ]), { raw: { width: 2, height: 2, channels: 4 } }).png().toBuffer();
    await assert.rejects(
        validateTransparentRgbaPng(hiddenRgbMatte, 2, { rasterProfile: "native-resolution-v1" }),
        assertRendererError("RENDER_OUTPUT_NOT_TRANSPARENT", false)
    );

    const hardEdgeOnly = await sharp(Buffer.from([
        0, 0, 0, 0, 1, 2, 3, 255,
        1, 2, 3, 255, 1, 2, 3, 255
    ]), { raw: { width: 2, height: 2, channels: 4 } }).png().toBuffer();
    const hardEdgeMetadata = await validateTransparentRgbaPng(hardEdgeOnly, 2, {
        rasterProfile: "native-resolution-v1"
    });
    assert.equal(hardEdgeMetadata.hasAlpha, true);
    assert.equal(hardEdgeMetadata.channels, 4);

    const fullyTransparentBlack = await sharp(Buffer.alloc(2 * 2 * 4), {
        raw: { width: 2, height: 2, channels: 4 }
    }).png().toBuffer();
    await assert.rejects(
        validateTransparentRgbaPng(fullyTransparentBlack, 2, {
            rasterProfile: "native-resolution-v1"
        }),
        assertRendererError("RENDER_OUTPUT_NOT_TRANSPARENT", false)
    );

    const transparentRgba = await sharp(Buffer.from([
        0, 0, 0, 0, 1, 2, 3, 128,
        1, 2, 3, 255, 1, 2, 3, 255
    ]), { raw: { width: 2, height: 2, channels: 4 } }).png().toBuffer();
    const metadata = await validateTransparentRgbaPng(transparentRgba, 2, {
        rasterProfile: "native-resolution-v1"
    });
    assert.equal(metadata.hasAlpha, true);
    assert.equal(metadata.channels, 4);
});

test("the SSAA image contract still requires partially covered edge pixels", async () => {
    const hardEdgeOnly = await sharp(Buffer.from([
        0, 0, 0, 0, 1, 2, 3, 255,
        1, 2, 3, 255, 1, 2, 3, 255
    ]), { raw: { width: 2, height: 2, channels: 4 } }).png().toBuffer();
    await assert.rejects(
        validateTransparentRgbaPng(hardEdgeOnly, 2, {
            rasterProfile: "research-2x-lanczos"
        }),
        assertRendererError("RENDER_OUTPUT_NOT_TRANSPARENT", false)
    );

    const antiAliased = await sharp(Buffer.from([
        0, 0, 0, 0, 1, 2, 3, 128,
        1, 2, 3, 255, 1, 2, 3, 255
    ]), { raw: { width: 2, height: 2, channels: 4 } }).png().toBuffer();
    const metadata = await validateTransparentRgbaPng(antiAliased, 2, {
        rasterProfile: "research-2x-lanczos"
    });
    assert.equal(metadata.hasAlpha, true);
    assert.equal(metadata.channels, 4);
});

test("render-slot handoff cannot be stolen by a fresh entrant", async () => {
    const limiter = createRenderSlotLimiter(2);
    await limiter.acquire();
    await limiter.acquire();
    assert.equal(limiter.activeCount, 2);

    let thirdAcquired = false;
    const third = limiter.acquire().then(() => { thirdAcquired = true; });
    assert.equal(limiter.queuedCount, 1);
    limiter.release();
    const fourth = limiter.acquire();
    assert.equal(limiter.activeCount, 2);
    assert.equal(limiter.queuedCount, 1, "fresh entrant must queue behind the transferred token");
    await third;
    assert.equal(thirdAcquired, true);
    assert.equal(limiter.activeCount, 2);

    limiter.release();
    await fourth;
    assert.equal(limiter.activeCount, 2);
    limiter.release();
    limiter.release();
    assert.equal(limiter.activeCount, 0);
});

const REPORT_LTD_SHA256 = "a".repeat(64);
const REPORT_OUTPUT_SHA256 = "b".repeat(64);
const LEGACY_HEADWEAR_REPORT_CASES = Object.freeze({
    34: Object.freeze({
        presentationKind: "simple_knit",
        resource: "ClothHeadwearHatSimpleKnit",
        shape: "SimpleKnit__mt_Body",
        submittedTriangles: 720
    }),
    57: Object.freeze({
        presentationKind: "simple_cap",
        resource: "ClothHeadwearHatSimpleCap",
        shape: "SimpleCap__mt_Body",
        submittedTriangles: 882
    })
});

function reportPresentationContext(sourceHairType) {
    if (sourceHairType == null) return null;
    return {
        schemaVersion: 1,
        kind: LTD_PRESENTATION_CONTEXT_KIND,
        ltdSha256: REPORT_LTD_SHA256,
        canonicalHairType: 45,
        sourceHairType
    };
}

function legacyHeadwearReport(sourceHairType) {
    const expected = LEGACY_HEADWEAR_REPORT_CASES[sourceHairType];
    return {
        source_hair_type: sourceHairType,
        presentation_kind: expected.presentationKind,
        resource: expected.resource,
        model: expected.resource,
        model_index: 0,
        shape: expected.shape,
        gameall_program: 96
    };
}

function renderReportFixture(sourceHairType = null) {
    const context = reportPresentationContext(sourceHairType);
    const contextSha256 = getLtdPresentationContextSha256(context);
    const active = context !== null;
    const expected = active ? LEGACY_HEADWEAR_REPORT_CASES[sourceHairType] : null;
    const drawKey = active ? `legacy_headwear:${expected.shape}` : null;
    return {
        input_sha256: REPORT_LTD_SHA256,
        resource_support: {
            classic_bridge: {
                capability_key: "checked-capability",
                resource_signature: { sha256: "c".repeat(64) },
                legacy_headwear_presentation: active
                    ? legacyHeadwearReport(sourceHairType)
                    : { status: "inactive_no_source_context" }
            }
        },
        presentation_context: {
            kind: context?.kind || "none",
            sha256: contextSha256,
            for_hat: active,
            source_hair_type: context?.sourceHairType ?? null,
            canonical_hair_type: 45,
            favorite_color: null,
            favorite_color_rgb_hex: null,
            favorite_shirt: {
                status: "inactive_no_source_context",
                policy: "infinimii-favorite-shirt-v1",
                title_exact: false
            }
        },
        hair_attachment_state: {
            model_selections: active
                ? [{
                    logical_name: "hair",
                    resource: "MiiHairAllLegacy045",
                    model_name: "MiiHairAllLegacyHat045",
                    model_index: 1,
                    for_hat: true
                }]
                : [],
            legacy_headwear: active ? legacyHeadwearReport(sourceHairType) : null
        },
        active_material_path: {
            presentation_outfit: {
                favorite_shirt: {
                    status: "inactive_no_source_context",
                    policy: "infinimii-favorite-shirt-v1",
                    title_exact: false
                },
                tops: {
                    resource: "ClothTopsTshirtLong",
                    material: "mt_Body",
                    gameall_program: 984,
                    normal: "ClothTopsTshirtLongTexDefault_Body_Nrm (unchanged)",
                    material_information: "ClothTopsTshirtLongTexDefault_Body_Mic (unchanged)",
                    serialized_alpha_mask: "inactive in selected GameAll 984; not sampled",
                    presentation_variation_used_for_policy: false
                }
            },
            ...(active ? {
                legacy_headwear: {
                    ...legacyHeadwearReport(sourceHairType),
                    loaded: true,
                    rendered: true,
                    draw_key: drawKey
                }
            } : {})
        },
        outputs: [{
            path: "mii.png",
            view: "appearance_bust_portrait",
            size: [512, 512],
            supersampling: {
                raster_size: [512, 512],
                portable_profile: "native-resolution-v1"
            },
            submitted_triangles: active ? { [drawKey]: expected.submittedTriangles } : {},
            sha256: REPORT_OUTPUT_SHA256
        }]
    };
}

function renderReportBinding(sourceHairType = null) {
    const presentationContext = reportPresentationContext(sourceHairType);
    return {
        ltdSha256: REPORT_LTD_SHA256,
        outputSha256: REPORT_OUTPUT_SHA256,
        imageName: "mii.png",
        reportView: "appearance_bust_portrait",
        size: 512,
        presentationContext,
        presentationContextSha256: getLtdPresentationContextSha256(presentationContext),
        presentationContextKind: presentationContext?.kind || "none",
        supersampleFactor: 1
    };
}

const FAVORITE_SHIRT_RGB = Object.freeze([
    "D21E14", "FF6E19", "FFD820", "78D220", "007830", "0A48B4",
    "3CAAE0", "F55A7D", "7328AD", "483818", "E0E0E0", "181814"
]);
const FAVORITE_SHIRT_VARIATIONS = Object.freeze([8, 3, 4, 10, 11, 16, 14, 6, 15, 1, 0, 0]);
const FAVORITE_SHIRT_LABELS = Object.freeze([
    "red", "orange", "yellow", "lime", "green", "blue",
    "cyan", "pink", "purple", "ochre_brown", "neutral", "neutral"
]);
const FAVORITE_SHIRT_BNTX_SHA256 = Object.freeze([
    "c2ed4aac0d0972d38355fadba9c15359400d29776e3a5907ca7f217f00089a2d",
    "cf4cc1ae2acb5a7c9f50e818acb0a6c006484aad27951ea798227498a1714763",
    "4f685b12832a90c65e3734cdc05ed942ffdd661e9bcff3e22e846c87183b28fc",
    "f0358240b1289669695f0072fef71c4e10d7ac3d7513ac1b96937a7d6f28a187",
    "4b36a8555b9c6530030e267ba518a19e23785c499c946a2689520ad7bd1cae2a",
    "bb54fcfc2da30887aa46eb470f0b6a31b78234fe0d98c59fdfb8685332d7a625",
    "0264bc00e2d1bdde38aa4db4f190079412eb9fa8be6f51a4eb3c357a8cc4b513",
    "a59b571ded674196b11be0f23bd9669d43400e1933a363b4180f13408b55e81a",
    "1ab172b87e1990b7b955035ebd4bb1dbfa41d50abdffb91c021e937fd17efec9",
    "bf448f669de9dd39643054df15ce3ccc8035601982bfea455a1fe3d219555585",
    "80c0522aeba44f45e11cfde3e09a78ebf4747ef31ca1e1085f0410fcaa7e52cc",
    "ff95b41731b36aebc85d952362ba638aba1785035c3902d14a29a48a355ec461",
    "736e01a204bb49fe72c0ecd54892974ef5db11166f29f2d38a4d9b520f7571c6",
    "c2434cfed5bf7813902bc3ebdf5a13ec7333412b380ba59f7b386d0d24cc29a3",
    "06c903b5495adb70715323a4bfccbf8b05d33f878d0a88fe2b92ed7b5382dbf1",
    "c6d54342d952d98c73860e344e8fd7efbe9d4863aadb031db72a9a3820733d5a",
    "cb6fc6efe2981b47c84bcbb84269394412b876d2781ed6f99ff4db8b1b8b8c36"
]);

function favoriteShirtPolicyDocument() {
    return {
        schema_version: 2,
        policy: "infinimii-favorite-shirt-v1",
        description: "Test copy of the canonical InfiniMii favorite-shirt policy.",
        title_exact: false,
        title_exact_boundary: {
            authored_shirt_family_and_loading_mechanism: true,
            favorite_color_to_suffix_projection: false
        },
        mapping_basis: "curated_named_authored_variant_with_neutral_fallback",
        source_boundary: {
            source_field: "general.favoriteColor",
            context_is_ltd_sha256_bound: true,
            share_mii_contains_favorite_color: false,
            presentation_profile_variation_used: false,
            reference_image_values_used: false
        },
        shirt_albedo: {
            mode: "select_authored_character_color_albedo",
            authored_albedo_variation_used: true,
            texture_name_pattern: "ClothTopsTshirtLongTexDefault_Body_Alb.{variation:02d}",
            source_rgb_used: true,
            source_alpha_preserved: true,
            alpha_sampler_active: false,
            normal_texture_unchanged: "ClothTopsTshirtLongTexDefault_Body_Nrm",
            material_information_texture_unchanged: "ClothTopsTshirtLongTexDefault_Body_Mic"
        },
        favorite_color_rgb_hex: [...FAVORITE_SHIRT_RGB],
        favorite_color_to_authored_variation: [...FAVORITE_SHIRT_VARIATIONS],
        favorite_color_to_authored_variant_label: [...FAVORITE_SHIRT_LABELS],
        authored_variation_bntx_sha256: [...FAVORITE_SHIRT_BNTX_SHA256]
    };
}

async function favoriteShirtPolicyContractFixture(t, mutate = null) {
    const root = await fs.promises.mkdtemp(path.join(os.tmpdir(), "infinimii-shirt-policy-"));
    t.after(() => fs.promises.rm(root, { recursive: true, force: true }));
    const rendererDirectory = path.join(root, "renderer");
    await fs.promises.mkdir(rendererDirectory);
    const document = favoriteShirtPolicyDocument();
    if (mutate) mutate(document);
    await fs.promises.writeFile(
        path.join(rendererDirectory, "infinimii_favorite_shirt_policy.json"),
        `${JSON.stringify(document, null, 2)}\n`
    );
    return loadFavoriteShirtPolicyContract(root);
}

async function referenceOutfitMipManifestContractFixture(t) {
    const root = await fs.promises.mkdtemp(path.join(os.tmpdir(), "infinimii-shirt-mips-"));
    t.after(() => fs.promises.rm(root, { recursive: true, force: true }));
    const cacheRoot = path.join(root, "renderer", "assets", "reference_outfit_texture_mips");
    await fs.promises.mkdir(cacheRoot, { recursive: true });
    const textures = [];
    for (let variation = 0; variation < 17; variation += 1) {
        const name = `ClothTopsTshirtLongTexDefault_Body_Alb.${String(variation).padStart(2, "0")}`;
        const directory = path.join(cacheRoot, name);
        const bytes = Buffer.from([variation]);
        const levelSha256 = crypto.createHash("sha256").update(bytes).digest("hex");
        await fs.promises.mkdir(directory);
        await fs.promises.writeFile(path.join(directory, "mip_00.png"), bytes);
        textures.push({
            name,
            semantic_role: "albedo",
            source: `../ltdDemo_converted_assets/decompressed/1/Tex/${name}.bntx`,
            source_byte_length: 1,
            source_sha256: FAVORITE_SHIRT_BNTX_SHA256[variation],
            width: 1,
            height: 1,
            mip_count: 1,
            format: "ASTC_6x6_SRGB",
            native_channels: "R,G,B,1",
            sampler: {
                material_sampler: "_a0",
                shader_sampler: "_a0",
                min_filter: "linear",
                mag_filter: "linear",
                mipmap_filter: "linear",
                wrap_u: "clamp",
                wrap_v: "clamp",
                wrap_w: "clamp",
                max_anisotropic: 2,
                compare_function: "never",
                min_lod: 0.0,
                max_lod: 13.0,
                lod_bias: 0.0
            },
            binding_evidence: {
                state: "renderer/reference_outfit_material_state.json",
                resource: "ClothTopsTshirtLong",
                model: "ClothTopsTshirtLong",
                material: "mt_Body",
                serialized_texture_ref: "Dummy_Alb",
                runtime_texture_substitution: name,
                selected_program_sampler_status: "active_compiled_material_sampler"
            },
            levels: [{
                level: 0,
                width: 1,
                height: 1,
                mode: "RGBA",
                path: `renderer/assets/reference_outfit_texture_mips/${name}/mip_00.png`,
                byte_length: bytes.length,
                sha256: levelSha256
            }]
        });
    }
    await fs.promises.writeFile(
        path.join(root, "renderer", "reference_outfit_texture_mips.json"),
        `${JSON.stringify({
            schema_version: 1,
            texture_count: textures.length,
            mip_level_count: textures.length,
            textures
        }, null, 2)}\n`
    );
    return loadReferenceOutfitMipManifestContract(root);
}

function favoriteShirtContext(favoriteColor, legacyHeadwearSourceType = null) {
    return {
        schemaVersion: 1,
        kind: "infinimii-favorite-shirt-v1",
        ltdSha256: REPORT_LTD_SHA256,
        favoriteColor,
        legacyHeadwearSourceType
    };
}

function favoriteShirtPolicyReport(favoriteColor, policyContract, mipContract) {
    const authoredVariation = FAVORITE_SHIRT_VARIATIONS[favoriteColor];
    const sourceAlbedo = `ClothTopsTshirtLongTexDefault_Body_Alb.${String(authoredVariation).padStart(2, "0")}`;
    return {
        status: "active",
        policy: "infinimii-favorite-shirt-v1",
        favorite_color: favoriteColor,
        rgb_hex: FAVORITE_SHIRT_RGB[favoriteColor],
        source_field: "general.favoriteColor",
        context_is_ltd_sha256_bound: true,
        title_exact: false,
        authored_shirt_family_and_loading_mechanism_title_exact: true,
        favorite_color_to_suffix_projection_title_exact: false,
        mapping_basis: "curated_named_authored_variant_with_neutral_fallback",
        authored_variation: authoredVariation,
        authored_variant_label: FAVORITE_SHIRT_LABELS[favoriteColor],
        albedo_mode: "select_authored_character_color_albedo",
        source_albedo: sourceAlbedo,
        source_bntx_sha256: FAVORITE_SHIRT_BNTX_SHA256[authoredVariation],
        selected_mip_manifest_record: structuredClone(mipContract.recordsByName[sourceAlbedo]),
        source_mip_chain_sha256: mipContract.mipChainSha256ByName[sourceAlbedo],
        source_mip_chain_hash_scope: mipContract.mipChainHashScope,
        source_rgb_used: true,
        source_alpha_preserved: true,
        authored_albedo_variation_used: true,
        presentation_profile_variation_used: false,
        alpha_sampler_active: false,
        normal_texture_unchanged: "ClothTopsTshirtLongTexDefault_Body_Nrm",
        material_information_texture_unchanged: "ClothTopsTshirtLongTexDefault_Body_Mic",
        policy_artifact: { ...policyContract.artifact }
    };
}

function favoriteShirtReportFixture(
    favoriteColor,
    policyContract,
    mipContract,
    legacyHeadwearSourceType = null
) {
    const report = renderReportFixture(legacyHeadwearSourceType);
    const context = favoriteShirtContext(favoriteColor, legacyHeadwearSourceType);
    const policy = favoriteShirtPolicyReport(favoriteColor, policyContract, mipContract);
    Object.assign(report.presentation_context, {
        kind: context.kind,
        sha256: getLtdPresentationContextSha256(context),
        favorite_color: favoriteColor,
        favorite_color_rgb_hex: FAVORITE_SHIRT_RGB[favoriteColor],
        favorite_shirt: structuredClone(policy)
    });
    report.active_material_path.presentation_outfit.favorite_shirt = structuredClone(policy);
    report.active_material_path.presentation_outfit.tops.albedo = policy.source_albedo;
    report.active_material_path.presentation_outfit.tops.albedo_source_bntx_sha256 =
        policy.source_bntx_sha256;
    report.active_material_path.presentation_outfit.tops.albedo_mip_chain_sha256 =
        policy.source_mip_chain_sha256;
    report.active_material_path.presentation_outfit.tops.albedo_mip_chain_hash_scope =
        policy.source_mip_chain_hash_scope;
    delete report.active_material_path.presentation_outfit.tops.presentation_variation_used_for_policy;
    report.active_material_path.presentation_outfit.tops.presentation_profile_variation_used_for_policy = false;
    return report;
}

function favoriteShirtReportBinding(
    favoriteColor,
    policyContract,
    mipContract,
    legacyHeadwearSourceType = null
) {
    const context = favoriteShirtContext(favoriteColor, legacyHeadwearSourceType);
    return {
        ...renderReportBinding(),
        presentationContext: context,
        presentationContextSha256: getLtdPresentationContextSha256(context),
        presentationContextKind: context.kind,
        favoriteShirtPolicyContract: policyContract,
        referenceOutfitMipManifestContract: mipContract
    };
}

test("favorite-shirt policy contract is loaded and hashed from the configured renderer", async t => {
    const contract = await favoriteShirtPolicyContractFixture(t);
    assert.equal(contract.policy, "infinimii-favorite-shirt-v1");
    assert.deepEqual(
        [...contract.favoriteColorToAuthoredVariation],
        [...FAVORITE_SHIRT_VARIATIONS]
    );
    assert.deepEqual(
        [...contract.authoredVariationBntxSha256],
        [...FAVORITE_SHIRT_BNTX_SHA256]
    );
    assert.equal(contract.artifact.path, "renderer/infinimii_favorite_shirt_policy.json");
    assert.ok(contract.artifact.byte_length > 0);
    assert.match(contract.artifact.sha256, /^[0-9a-f]{64}$/);

    await assert.rejects(
        favoriteShirtPolicyContractFixture(t, document => {
            document.favorite_color_to_authored_variation[6] = 16;
        }),
        assertRendererError("LTD_RENDERER_NOT_CONFIGURED", false)
    );
});

test("reference-outfit mip contract uses the Python canonical complete-record hash", async t => {
    const contract = await referenceOutfitMipManifestContractFixture(t);
    const name = "ClothTopsTshirtLongTexDefault_Body_Alb.14";
    assert.equal(contract.recordsByName[name].source_sha256, FAVORITE_SHIRT_BNTX_SHA256[14]);
    assert.equal(
        contract.mipChainHashScope,
        "sha256(UTF-8 JSON of the complete selected texture manifest record with sort_keys=True and separators=(',', ':'))"
    );
    assert.equal(
        contract.mipChainSha256ByName[name],
        "fcd7c4d1f93931219dfcc1423b9f8a7514fc4f565bc6149ee15a88b907089994"
    );
});

test("render report must bind exact output bytes, view, size, and inactive headwear state", () => {
    const report = renderReportFixture();
    const binding = renderReportBinding();
    assert.equal(validateRenderReportBinding(report, binding).capability_key, "checked-capability");

    for (const [label, mutate] of [
        ["output hash", value => { value.outputs[0].sha256 = "d".repeat(64); }],
        ["view", value => { value.outputs[0].view = "posed_full_body"; }],
        ["size", value => { value.outputs[0].size = [256, 256]; }],
        ["raster size", value => { value.outputs[0].supersampling.raster_size = [1024, 1024]; }],
        ["raster profile", value => { value.outputs[0].supersampling.portable_profile = "research-2x-lanczos"; }],
        ["context hash", value => { value.presentation_context.sha256 = "d".repeat(64); }],
        ["resource signature", value => { value.resource_support.classic_bridge.resource_signature.sha256 = "not-a-sha"; }],
        ["inactive for-hat flag", value => { value.presentation_context.for_hat = true; }],
        ["inactive source selector", value => { value.presentation_context.source_hair_type = 57; }],
        ["inactive capability status", value => { value.resource_support.classic_bridge.legacy_headwear_presentation.status = "active"; }],
        ["inactive attachment", value => { value.hair_attachment_state.legacy_headwear = {}; }],
        ["inactive for-hat hair", value => { value.hair_attachment_state.model_selections = [{ for_hat: true }]; }],
        ["inactive material draw", value => { value.active_material_path.legacy_headwear = {}; }],
        ["inactive submitted draw", value => { value.outputs[0].submitted_triangles["legacy_headwear:unexpected"] = 1; }]
    ]) {
        const malformed = structuredClone(report);
        mutate(malformed);
        assert.throws(
            () => validateRenderReportBinding(malformed, binding),
            assertRendererError("RENDER_FAILED", false),
            label
        );
    }
});

test("render report positively binds source 34 and 57 headwear draws", () => {
    for (const sourceHairType of [34, 57]) {
        const report = renderReportFixture(sourceHairType);
        const binding = renderReportBinding(sourceHairType);
        assert.equal(
            validateRenderReportBinding(report, binding).capability_key,
            "checked-capability"
        );
    }
});

test("render report binds all 12 favorite-shirt colors, including composite hats", async t => {
    const policyContract = await favoriteShirtPolicyContractFixture(t);
    const mipContract = await referenceOutfitMipManifestContractFixture(t);
    for (let favoriteColor = 0; favoriteColor < FAVORITE_SHIRT_RGB.length; favoriteColor += 1) {
        const legacyHeadwearSourceType = favoriteColor === 0
            ? 34
            : favoriteColor === 11 ? 57 : null;
        assert.equal(
            validateRenderReportBinding(
                favoriteShirtReportFixture(
                    favoriteColor,
                    policyContract,
                    mipContract,
                    legacyHeadwearSourceType
                ),
                favoriteShirtReportBinding(
                    favoriteColor,
                    policyContract,
                    mipContract,
                    legacyHeadwearSourceType
                )
            ).capability_key,
            "checked-capability"
        );
    }
});

test("favorite-shirt report mutations fail closed", async t => {
    const policyContract = await favoriteShirtPolicyContractFixture(t);
    const mipContract = await referenceOutfitMipManifestContractFixture(t);
    for (const [label, mutate] of [
        ["favorite index", value => { value.presentation_context.favorite_color = 9; }],
        ["favorite RGB", value => { value.presentation_context.favorite_color_rgb_hex = "FFFFFF"; }],
        ["source field", value => { value.presentation_context.favorite_shirt.source_field = "presentation_variation"; }],
        ["title claim", value => { value.presentation_context.favorite_shirt.title_exact = true; }],
        ["source RGB", value => { value.presentation_context.favorite_shirt.source_rgb_used = false; }],
        ["source alpha", value => { value.presentation_context.favorite_shirt.source_alpha_preserved = false; }],
        ["authored-family exactness", value => { value.presentation_context.favorite_shirt.authored_shirt_family_and_loading_mechanism_title_exact = false; }],
        ["projection exactness", value => { value.presentation_context.favorite_shirt.favorite_color_to_suffix_projection_title_exact = true; }],
        ["mapping basis", value => { value.presentation_context.favorite_shirt.mapping_basis = "guessed_rgb_nearest"; }],
        ["authored variation disabled", value => { value.presentation_context.favorite_shirt.authored_albedo_variation_used = false; }],
        ["profile variation misuse", value => { value.presentation_context.favorite_shirt.presentation_profile_variation_used = true; }],
        ["variation index", value => { value.presentation_context.favorite_shirt.authored_variation = 2; }],
        ["source albedo", value => { value.presentation_context.favorite_shirt.source_albedo = "ClothTopsTshirtLongTexDefault_Body_Alb.02"; }],
        ["BNTX hash", value => { value.presentation_context.favorite_shirt.source_bntx_sha256 = "bad"; }],
        ["inactive alpha restored", value => { value.presentation_context.favorite_shirt.alpha_sampler_active = true; }],
        ["normal changed", value => { value.active_material_path.presentation_outfit.favorite_shirt.normal_texture_unchanged = "wrong"; }],
        ["Mic changed", value => { value.active_material_path.presentation_outfit.favorite_shirt.material_information_texture_unchanged = "wrong"; }],
        ["wrong top program", value => { value.active_material_path.presentation_outfit.tops.gameall_program = 936; }],
        ["top alpha sampled", value => { value.active_material_path.presentation_outfit.tops.serialized_alpha_mask = "active"; }]
    ]) {
        const report = favoriteShirtReportFixture(6, policyContract, mipContract);
        mutate(report);
        assert.throws(
            () => validateRenderReportBinding(
                report,
                favoriteShirtReportBinding(6, policyContract, mipContract)
            ),
            assertRendererError("RENDER_FAILED", false),
            label
        );
    }

    for (const [label, mutate] of [
        ["coherent wrong authored source", value => {
            const alternateName = "ClothTopsTshirtLongTexDefault_Body_Alb.16";
            for (const policy of [
                value.presentation_context.favorite_shirt,
                value.active_material_path.presentation_outfit.favorite_shirt
            ]) {
                policy.authored_variation = 16;
                policy.authored_variant_label = "blue";
                policy.source_albedo = alternateName;
                policy.source_bntx_sha256 = FAVORITE_SHIRT_BNTX_SHA256[16];
                policy.selected_mip_manifest_record = structuredClone(
                    mipContract.recordsByName[alternateName]
                );
                policy.source_mip_chain_sha256 = mipContract.mipChainSha256ByName[alternateName];
            }
            const tops = value.active_material_path.presentation_outfit.tops;
            tops.albedo = alternateName;
            tops.albedo_source_bntx_sha256 = FAVORITE_SHIRT_BNTX_SHA256[16];
            tops.albedo_mip_chain_sha256 = mipContract.mipChainSha256ByName[alternateName];
        }],
        ["coherent alternate BNTX hash", value => {
            for (const policy of [
                value.presentation_context.favorite_shirt,
                value.active_material_path.presentation_outfit.favorite_shirt
            ]) policy.source_bntx_sha256 = FAVORITE_SHIRT_BNTX_SHA256[15];
        }],
        ["coherent alternate label", value => {
            for (const policy of [
                value.presentation_context.favorite_shirt,
                value.active_material_path.presentation_outfit.favorite_shirt
            ]) policy.authored_variant_label = "blue";
        }],
        ["coherent forged policy hash", value => {
            for (const policy of [
                value.presentation_context.favorite_shirt,
                value.active_material_path.presentation_outfit.favorite_shirt
            ]) policy.policy_artifact.sha256 = "f".repeat(64);
        }],
        ["coherent forged selected mip record", value => {
            for (const policy of [
                value.presentation_context.favorite_shirt,
                value.active_material_path.presentation_outfit.favorite_shirt
            ]) policy.selected_mip_manifest_record.levels[0].sha256 = "0".repeat(64);
        }],
        ["coherent forged mip-chain hash", value => {
            for (const policy of [
                value.presentation_context.favorite_shirt,
                value.active_material_path.presentation_outfit.favorite_shirt
            ]) policy.source_mip_chain_sha256 = "f".repeat(64);
            value.active_material_path.presentation_outfit.tops.albedo_mip_chain_sha256 =
                "f".repeat(64);
        }],
        ["coherent forged mip-chain scope", value => {
            for (const policy of [
                value.presentation_context.favorite_shirt,
                value.active_material_path.presentation_outfit.favorite_shirt
            ]) policy.source_mip_chain_hash_scope = "selected levels only";
            value.active_material_path.presentation_outfit.tops.albedo_mip_chain_hash_scope =
                "selected levels only";
        }],
        ["top BNTX binding", value => {
            value.active_material_path.presentation_outfit.tops.albedo_source_bntx_sha256 =
                FAVORITE_SHIRT_BNTX_SHA256[16];
        }],
        ["top mip-chain binding", value => {
            value.active_material_path.presentation_outfit.tops.albedo_mip_chain_sha256 =
                "f".repeat(64);
        }],
        ["top mip-chain scope", value => {
            value.active_material_path.presentation_outfit.tops.albedo_mip_chain_hash_scope =
                "selected levels only";
        }]
    ]) {
        const report = favoriteShirtReportFixture(6, policyContract, mipContract);
        mutate(report);
        assert.throws(
            () => validateRenderReportBinding(
                report,
                favoriteShirtReportBinding(6, policyContract, mipContract)
            ),
            assertRendererError("RENDER_FAILED", false),
            label
        );
    }

    assert.throws(
        () => validateRenderReportBinding(
            favoriteShirtReportFixture(6, policyContract, mipContract),
            {
                ...favoriteShirtReportBinding(6, policyContract, mipContract),
                favoriteShirtPolicyContract: null
            }
        ),
        assertRendererError("RENDER_FAILED", false),
        "an active shirt report requires a canonically loaded policy contract"
    );
    assert.throws(
        () => validateRenderReportBinding(
            favoriteShirtReportFixture(6, policyContract, mipContract),
            {
                ...favoriteShirtReportBinding(6, policyContract, mipContract),
                referenceOutfitMipManifestContract: null
            }
        ),
        assertRendererError("RENDER_FAILED", false),
        "an active shirt report requires a canonically loaded mip manifest contract"
    );
});

test("active legacy-headwear report mutations fail closed", () => {
    for (const sourceHairType of [34, 57]) {
        const report = renderReportFixture(sourceHairType);
        const binding = renderReportBinding(sourceHairType);
        const expected = LEGACY_HEADWEAR_REPORT_CASES[sourceHairType];
        const drawKey = `legacy_headwear:${expected.shape}`;
        for (const [label, mutate] of [
            ["reported for-hat flag", value => { value.presentation_context.for_hat = false; }],
            ["reported source selector", value => { value.presentation_context.source_hair_type = sourceHairType === 34 ? 57 : 34; }],
            ["reported canonical selector", value => { value.presentation_context.canonical_hair_type = 44; }],
            ["capability presentation kind", value => { value.resource_support.classic_bridge.legacy_headwear_presentation.presentation_kind = "wrong"; }],
            ["capability resource", value => { value.resource_support.classic_bridge.legacy_headwear_presentation.resource = "wrong"; }],
            ["capability shape", value => { value.resource_support.classic_bridge.legacy_headwear_presentation.shape = "wrong"; }],
            ["attachment identity", value => { value.hair_attachment_state.legacy_headwear.model = "wrong"; }],
            ["for-hat selection count", value => { value.hair_attachment_state.model_selections.push({}); }],
            ["for-hat logical name", value => { value.hair_attachment_state.model_selections[0].logical_name = "hair_front"; }],
            ["for-hat resource", value => { value.hair_attachment_state.model_selections[0].resource = "MiiHairAllLegacy046"; }],
            ["for-hat model", value => { value.hair_attachment_state.model_selections[0].model_name = "MiiHairAllLegacy045"; }],
            ["for-hat model index", value => { value.hair_attachment_state.model_selections[0].model_index = 0; }],
            ["for-hat selection flag", value => { value.hair_attachment_state.model_selections[0].for_hat = false; }],
            ["material identity", value => { value.active_material_path.legacy_headwear.source_hair_type = 45; }],
            ["material loaded", value => { value.active_material_path.legacy_headwear.loaded = false; }],
            ["material rendered", value => { value.active_material_path.legacy_headwear.rendered = false; }],
            ["material program", value => { value.active_material_path.legacy_headwear.gameall_program = 95; }],
            ["material draw key", value => { value.active_material_path.legacy_headwear.draw_key = "legacy_headwear:wrong"; }],
            ["submitted draw count", value => { value.outputs[0].submitted_triangles[drawKey] -= 1; }],
            ["additional submitted headwear", value => { value.outputs[0].submitted_triangles["legacy_headwear:wrong"] = 1; }]
        ]) {
            const malformed = structuredClone(report);
            mutate(malformed);
            assert.throws(
                () => validateRenderReportBinding(malformed, binding),
                assertRendererError("RENDER_FAILED", false),
                `${sourceHairType}: ${label}`
            );
        }
    }
});

test("transient failures get one retry while deterministic unsupported inputs do not", async () => {
    let transientAttempts = 0;
    const recovered = await executeRenderAttemptWithRetry(async () => {
        transientAttempts += 1;
        if (transientAttempts === 1) {
            throw new LtdRenderError("RENDER_CLEANUP_FAILED", "cleanup failed", {
                diagnostics: "workspace locked",
                status: 503
            });
        }
        return "rendered";
    }, { ltdSha256: "a".repeat(64), rendererRevision: "b".repeat(64) });
    assert.equal(recovered, "rendered");
    assert.equal(transientAttempts, 2);

    let deterministicAttempts = 0;
    await assert.rejects(
        executeRenderAttemptWithRetry(async () => {
            deterministicAttempts += 1;
            throw new LtdRenderError("UNSUPPORTED_LTD_RENDER_PATH", "unsupported", {
                deterministic: true
            });
        }),
        assertRendererError("UNSUPPORTED_LTD_RENDER_PATH", true)
    );
    assert.equal(deterministicAttempts, 1);
});
