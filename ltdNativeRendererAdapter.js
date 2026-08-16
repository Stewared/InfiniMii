import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import {
    hasPinnedNativeRenderOrchestrator,
    NativeLtdRuntimeError,
    NativeLtdRuntimePool
} from "./ltdNativeRendererClient.js";


const MAX_NATIVE_RUNTIME_WORKERS = 2;
const NATIVE_RUNTIME_STARTUP_TIMEOUT_MS = 30_000;
const NATIVE_RUNTIME_REQUEST_TIMEOUT_MS = 120_000;
const NATIVE_PARTS_CATALOG_SHA256 =
    "d8d56e7ee1e291e2e4cc213ef88521b594093a83952747f1d3c8ab0ca5b00523";
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const nativeRuntimeStates = new Map();


function isPlainObject(value) {
    return value !== null && typeof value === "object" && !Array.isArray(value);
}


function requireRegularFile(filePath, label) {
    let stat;
    try {
        stat = fs.statSync(filePath);
    } catch (error) {
        throw new TypeError(`${label} does not exist.`, { cause: error });
    }
    if (!stat.isFile()) throw new TypeError(`${label} is not a regular file.`);
    return path.resolve(filePath);
}


function requireDirectory(directory, label) {
    let stat;
    try {
        stat = fs.statSync(directory);
    } catch (error) {
        throw new TypeError(`${label} does not exist.`, { cause: error });
    }
    if (!stat.isDirectory()) throw new TypeError(`${label} is not a directory.`);
    return path.resolve(directory);
}


function listMaterialTextureRoots(rendererRoot) {
    const candidates = [
        ["renderer", "assets", "texture_mips"],
        ["renderer", "assets", "texture_mips_mii2"],
        ["renderer", "assets", "reference_outfit_texture_mips"]
    ].map(parts => path.join(rendererRoot, ...parts));
    return candidates
        .filter(candidate => fs.existsSync(candidate) && fs.statSync(candidate).isDirectory())
        .map(candidate => path.resolve(candidate));
}


function listNativeRuntimeRevisionFiles(rendererRoot) {
    const candidates = [
        ["native_runtime", "build", "ltd_native_runtime.exe"],
        ["native_runtime", "build", "libzstd.dll"],
        ["native_runtime", "build", "native_png_zlib1.dll"],
        ["native_runtime", "generated", "native_parts_catalog.bin"],
        ["native_runtime", "generated", "native_parts_catalog.json"]
    ].map(parts => path.join(rendererRoot, ...parts));
    return candidates
        .filter(candidate => fs.existsSync(candidate) && fs.statSync(candidate).isFile())
        .map(candidate => path.resolve(candidate));
}


export function resolveNativeLtdRuntimeConfiguration(rendererRoot) {
    const root = requireDirectory(path.resolve(String(rendererRoot || "")), "native LTD renderer root");
    const executable = path.join(root, "native_runtime", "build", "ltd_native_runtime.exe");
    if (!fs.existsSync(executable)) return null;
    const configuration = Object.freeze({
        root,
        executable: requireRegularFile(executable, "native LTD runtime executable"),
        commandArgs: Object.freeze([]),
        partsCatalog: requireRegularFile(
            path.join(root, "native_runtime", "generated", "native_parts_catalog.bin"),
            "native LTD Parts catalog"
        ),
        partsCatalogSha256: NATIVE_PARTS_CATALOG_SHA256,
        modelRoot: requireDirectory(
            path.join(root, "renderer", "assets", "models"),
            "native LTD model root"
        ),
        faceTextureRoot: requireDirectory(
            path.join(root, "renderer", "assets", "face_sprite_mips"),
            "native LTD face texture root"
        ),
        materialTextureRoots: Object.freeze(listMaterialTextureRoots(root)),
        posePath: requireRegularFile(
            path.join(root, "renderer", "assets", "animations", "IconPose.json"),
            "native LTD pose"
        ),
        revisionFiles: Object.freeze(listNativeRuntimeRevisionFiles(root))
    });
    if (configuration.materialTextureRoots.length < 1) {
        throw new TypeError("native LTD material texture roots are unavailable.");
    }
    return configuration;
}


function configurationIdentity(configuration) {
    return [
        configuration.root,
        configuration.executable,
        ...configuration.commandArgs,
        configuration.partsCatalog,
        ...configuration.materialTextureRoots
    ].join("\0");
}


function getRuntimeState(configuration) {
    const identity = configurationIdentity(configuration);
    let state = nativeRuntimeStates.get(identity);
    if (!state) {
        const pool = new NativeLtdRuntimePool({
            command: configuration.executable,
            commandArgs: [...configuration.commandArgs],
            cwd: configuration.root,
            maxWorkers: MAX_NATIVE_RUNTIME_WORKERS,
            startupTimeoutMs: NATIVE_RUNTIME_STARTUP_TIMEOUT_MS
        });
        state = {
            identity,
            pool,
            readinessPromise: null,
            disabled: false
        };
        nativeRuntimeStates.set(identity, state);
    }
    return state;
}


function disableRuntimeState(state) {
    if (state.disabled) return;
    state.disabled = true;
    state.pool.close();
}


async function ensureRuntimeReady(state, timeoutMs) {
    if (state.disabled) return false;
    if (!state.readinessPromise) {
        state.readinessPromise = state.pool.run(
            { op: "readiness" },
            { timeoutMs }
        ).then(result => {
            if (
                !isPlainObject(result)
                || result.protocol_ready !== true
                || typeof result.activation_ready !== "boolean"
                || !hasPinnedNativeRenderOrchestrator(result.render_modules)
            ) {
                throw new NativeLtdRuntimeError(
                    "NATIVE_RUNTIME_PROTOCOL_ERROR",
                    "The native LTD runtime returned invalid readiness metadata.",
                    { workerUnavailable: true }
                );
            }
            if (result.activation_ready !== true) {
                disableRuntimeState(state);
                return false;
            }
            return true;
        }).catch(error => {
            disableRuntimeState(state);
            if (error instanceof NativeLtdRuntimeError) return false;
            throw error;
        });
    }
    return await state.readinessPromise;
}


function validateRenderRequest(request) {
    if (!isPlainObject(request)) throw new TypeError("native LTD render request must be an object");
    for (const key of ["ltdPath", "outputDirectory", "presentationContextKind", "presentationContextSha256"]) {
        if (typeof request[key] !== "string" || !request[key]) {
            throw new TypeError(`${key} is required`);
        }
    }
    if (!path.isAbsolute(request.ltdPath) || !path.isAbsolute(request.outputDirectory)) {
        throw new TypeError("native LTD render paths must be absolute");
    }
    if (!Number.isInteger(request.size) || ![128, 512].includes(request.size)) {
        throw new TypeError("native LTD output size must be 128 or 512");
    }
    if (!['portrait', 'full_body'].includes(request.view)) {
        throw new TypeError("native LTD view must be portrait or full_body");
    }
    if (!SHA256_PATTERN.test(request.presentationContextSha256)) {
        throw new TypeError("native LTD presentation context hash is invalid");
    }
}


async function validateActivatedResult(result, request) {
    const expectedImageName = request.view === "full_body" ? "mii_full_body.png" : "mii.png";
    const expectedImagePath = path.resolve(request.outputDirectory, expectedImageName);
    const expectedReportPath = path.resolve(request.outputDirectory, "render_report.json");
    const expectedReportView = request.view === "full_body"
        ? "posed_full_body"
        : "appearance_bust_portrait";
    const output = Array.isArray(result?.render_report?.outputs)
        && result.render_report.outputs.length === 1
        ? result.render_report.outputs[0]
        : null;
    if (
        result?.activation_ready !== true
        || !hasPinnedNativeRenderOrchestrator(result?.modules)
        || result?.pixels_produced !== true
        || result?.png_produced !== true
        || result?.files_written !== true
        || result?.transaction_cleanup_complete !== true
        || ![expectedImageName, expectedImagePath].includes(result?.output_path)
        || !["render_report.json", expectedReportPath].includes(result?.report_path)
        || !SHA256_PATTERN.test(String(result?.input_sha256 || ""))
        || !SHA256_PATTERN.test(String(result?.output_sha256 || ""))
        || !SHA256_PATTERN.test(String(result?.report_sha256 || ""))
        || result?.render_report?.input_sha256 !== result.input_sha256
        || result?.render_report?.presentation_context?.kind !== request.presentationContextKind
        || result?.render_report?.presentation_context?.sha256 !== request.presentationContextSha256
        || output?.path !== expectedImageName
        || output?.view !== expectedReportView
        || output?.size?.[0] !== request.size
        || output?.size?.[1] !== request.size
        || output?.supersampling?.portable_profile !== "native-resolution-v1"
        || output?.supersampling?.raster_size?.[0] !== request.size
        || output?.supersampling?.raster_size?.[1] !== request.size
        || output?.sha256 !== result.output_sha256
    ) {
        throw new NativeLtdRuntimeError(
            "NATIVE_RUNTIME_PROTOCOL_ERROR",
            "The native LTD runtime returned an unbound render result.",
            { workerUnavailable: true }
        );
    }

    let outputBytes;
    let reportBytes;
    let storedReport;
    try {
        const [outputStat, reportStat] = await Promise.all([
            fs.promises.lstat(expectedImagePath),
            fs.promises.lstat(expectedReportPath)
        ]);
        if (
            !outputStat.isFile()
            || outputStat.isSymbolicLink()
            || !reportStat.isFile()
            || reportStat.isSymbolicLink()
        ) throw new Error("native output paths must be regular files");
        [outputBytes, reportBytes] = await Promise.all([
            fs.promises.readFile(expectedImagePath),
            fs.promises.readFile(expectedReportPath)
        ]);
        storedReport = JSON.parse(reportBytes.toString("utf8"));
    } catch (error) {
        throw new NativeLtdRuntimeError(
            "NATIVE_RUNTIME_PROTOCOL_ERROR",
            "The native LTD runtime did not publish a readable output transaction.",
            { workerUnavailable: true, cause: error }
        );
    }
    const storedOutputSha256 = crypto.createHash("sha256").update(outputBytes).digest("hex");
    const storedReportSha256 = crypto.createHash("sha256").update(reportBytes).digest("hex");
    const declaredReportBytes = Buffer.from(`${JSON.stringify(result.render_report)}\n`, "utf8");
    if (
        storedOutputSha256 !== result.output_sha256
        || storedReportSha256 !== result.report_sha256
        || !reportBytes.equals(declaredReportBytes)
        || storedReport?.outputs?.[0]?.sha256 !== storedOutputSha256
    ) {
        throw new NativeLtdRuntimeError(
            "NATIVE_RUNTIME_PROTOCOL_ERROR",
            "The native LTD runtime output files do not match its authenticated result.",
            { workerUnavailable: true }
        );
    }
    return Object.freeze({ outputBytes, reportBytes, storedReport });
}


export async function tryNativeLtdRender(configuration, request, {
    timeoutMs = NATIVE_RUNTIME_REQUEST_TIMEOUT_MS
} = {}) {
    if (!configuration) return Object.freeze({ activated: false, reason: "not-configured" });
    validateRenderRequest(request);
    const state = getRuntimeState(configuration);
    if (!await ensureRuntimeReady(state, timeoutMs)) {
        return Object.freeze({ activated: false, reason: "not-ready" });
    }
    let result;
    try {
        result = await state.pool.run({
            op: "render_ltd",
            repository_root: configuration.root,
            ltd_path: path.resolve(request.ltdPath),
            catalog_path: configuration.partsCatalog,
            model_root: configuration.modelRoot,
            face_texture_root: configuration.faceTextureRoot,
            material_texture_roots: [...configuration.materialTextureRoots],
            pose_path: configuration.posePath,
            output_dir: path.resolve(request.outputDirectory),
            view: request.view,
            output_size: request.size,
            supersampling: {
                profile: "native-resolution-v1",
                raster_size: request.size
            },
            presentation_context: {
                kind: request.presentationContextKind,
                sha256: request.presentationContextSha256
            }
        }, { timeoutMs });
    } catch (error) {
        if (error instanceof NativeLtdRuntimeError && error.workerUnavailable === true) {
            disableRuntimeState(state);
            return Object.freeze({ activated: false, reason: "unavailable", error });
        }
        return Object.freeze({ activated: false, reason: "request-rejected", error });
    }
    if (
        result?.activation_ready !== true
        || result?.pixels_produced !== true
        || result?.png_produced !== true
    ) {
        return Object.freeze({ activated: false, reason: "request-not-supported" });
    }
    try {
        const validatedFiles = await validateActivatedResult(result, request);
        result = Object.freeze({ ...result, validatedFiles });
    } catch (error) {
        disableRuntimeState(state);
        return Object.freeze({ activated: false, reason: "invalid-result", error });
    }
    return Object.freeze({ activated: true, result });
}


export function closeNativeLtdRuntimePools() {
    for (const state of nativeRuntimeStates.values()) state.pool.close();
    nativeRuntimeStates.clear();
}


process.once("exit", closeNativeLtdRuntimePools);
