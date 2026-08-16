import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import sharp from "sharp";

import { getLtdSha256 } from "./ltdCanonical.js";
import {
    closeNativeLtdRuntimePools,
    resolveNativeLtdRuntimeConfiguration,
    tryNativeLtdRender
} from "./ltdNativeRendererAdapter.js";
import {
    LTD_RENDER_WORKER_PROTOCOL,
    LTD_RENDER_WORKER_PROTOCOL_VERSION,
    PersistentRenderWorkerError,
    PersistentRenderWorkerPool
} from "./ltdRenderWorkerClient.js";
import {
    getFavoriteShirtPolicy,
    getLegacyHeadwearSourceType,
    getLtdPresentationContextSha256,
    INFINIMII_FAVORITE_SHIRT_CONTEXT_KIND,
    INFINIMII_FAVORITE_SHIRT_RGB,
    INFINIMII_FAVORITE_SHIRT_VARIATIONS,
    LTD_PRESENTATION_CONTEXT_NONE,
    normalizeLtdPresentationContext
} from "./ltdPresentationContext.js";
import { resolveLtdRuntimePaths } from "./ltdRuntimePaths.js";

const RENDER_TIMEOUT_MS = 120_000;
const MAX_OUTPUT_CHARS = 512 * 1024;
const MAX_DIAGNOSTIC_CHARS = 16 * 1024;
const MAX_CONCURRENT_RENDERS = 2;
const MAX_RENDER_ATTEMPTS = 2;
const TRANSPARENT_BACKGROUND_MODE = "transparent";
const NATIVE_RASTER_PROFILE = "native-resolution-v1";
const SSAA_RASTER_PROFILE = "research-2x-lanczos";
const SHA256_PATTERN = /^[0-9a-f]{64}$/i;
const FAVORITE_SHIRT_POLICY_RELATIVE_PATH = Object.freeze([
    "renderer", "infinimii_favorite_shirt_policy.json"
]);
const REFERENCE_OUTFIT_MIP_MANIFEST_RELATIVE_PATH = Object.freeze([
    "renderer", "reference_outfit_texture_mips.json"
]);
const REFERENCE_OUTFIT_MIP_CACHE_RELATIVE_PATH = Object.freeze([
    "renderer", "assets", "reference_outfit_texture_mips"
]);
const REFERENCE_OUTFIT_MIP_CHAIN_HASH_SCOPE =
    "sha256(UTF-8 JSON of the complete selected texture manifest record with sort_keys=True and separators=(',', ':'))";
const canonicalFavoriteShirtPolicyContracts = new WeakSet();
const canonicalReferenceOutfitMipManifestContracts = new WeakSet();
const pendingRenders = new Map();
const rendererRevisionSnapshots = new Map();
const rendererRuntimeFingerprintSnapshots = new Map();
const referenceOutfitMipManifestContractSnapshots = new Map();
const persistentRendererPools = new Map();
const disabledPersistentWorkerIdentities = new Set();
const LEGACY_HEADWEAR_REPORT_CONTRACT = Object.freeze({
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

export function createRenderSlotLimiter(maxConcurrent) {
    if (!Number.isInteger(maxConcurrent) || maxConcurrent < 1) {
        throw new TypeError("maxConcurrent must be a positive integer.");
    }
    let activeCount = 0;
    const waiters = [];
    return {
        async acquire() {
            if (activeCount < maxConcurrent) {
                activeCount += 1;
                return;
            }
            // release() transfers an already-occupied token directly to this
            // waiter. The resumed waiter must not increment it a second time.
            await new Promise(resolve => waiters.push(resolve));
        },
        release() {
            const waiter = waiters.shift();
            if (waiter) {
                waiter();
            } else {
                activeCount = Math.max(0, activeCount - 1);
            }
        },
        get activeCount() {
            return activeCount;
        },
        get queuedCount() {
            return waiters.length;
        }
    };
}

const renderSlotLimiter = createRenderSlotLimiter(MAX_CONCURRENT_RENDERS);

export class LtdRenderError extends Error {
    constructor(code, message, options = {}) {
        super(message, options);
        this.name = "LtdRenderError";
        this.code = code;
        this.deterministic = options.deterministic === true;
        this.status = options.status || (this.deterministic ? 422 : 503);
        if (typeof options.diagnostics === "string" && options.diagnostics) {
            // Private operator diagnostics only. Route handlers never include
            // this field in their public response bodies.
            this.diagnostics = options.diagnostics;
        }
        if (Number.isInteger(options.attempts)) this.attempts = options.attempts;
        if (typeof options.ltdSha256 === "string") this.ltdSha256 = options.ltdSha256;
        if (typeof options.rendererRevision === "string") this.rendererRevision = options.rendererRevision;
    }
}

const DIRECT_RENDER_CONTRACT_PATHS = Object.freeze([
    ["renderer", "classic_bridge_portrait_framing.json"],
    ["renderer", "legacy_headwear_presentation.json"],
    ["renderer", "presentation_outfit.json"],
    FAVORITE_SHIRT_POLICY_RELATIVE_PATH,
    ["renderer", "screen_space_face_shadow_source.json"],
    ["renderer", "reference_capture_outfit.json"],
    ["renderer", "reference_outfit_material_state.json"],
    REFERENCE_OUTFIT_MIP_MANIFEST_RELATIVE_PATH,
    ["renderer", "mii_mask_semantics.json"],
    ["renderer", "title_mii_icon_snapshot.json"],
    ["renderer", "mii_pose_pipeline.json"],
    ["renderer", "body_base_cutline_source.json"],
    ["renderer", "share_mii_facepaint.json"],
    ["renderer", "hair_shader_expression.json"],
    ["renderer", "assets", "color_tables.json"],
    ["renderer", "assets", "animations", "IconPose.json"]
]);

function requireRuntimeDirectory(name, resolved) {
    let stat;
    try {
        stat = fs.statSync(resolved);
    } catch (error) {
        throw new LtdRenderError(
            "LTD_RENDERER_NOT_CONFIGURED",
            `${name} does not exist at ${resolved}. Copy the LTD runtime asset drop into ltd-renderer or configure an override.`,
            { cause: error, status: 503 }
        );
    }
    if (!stat.isDirectory()) {
        throw new LtdRenderError("LTD_RENDERER_NOT_CONFIGURED", `${name} is not a directory.`, { status: 503 });
    }
    return resolved;
}

function persistentWorkerRequested() {
    const value = String(process.env.LTD_RENDERER_PERSISTENT_WORKER ?? "1").trim().toLowerCase();
    if (["1", "true", "yes", "on"].includes(value)) return true;
    if (["0", "false", "no", "off"].includes(value)) return false;
    throw new LtdRenderError(
        "LTD_RENDERER_NOT_CONFIGURED",
        "LTD_RENDERER_PERSISTENT_WORKER must be a boolean value.",
        { status: 503 }
    );
}

export function resolveLtdRendererConfiguration() {
    const runtimePaths = resolveLtdRuntimePaths();
    const root = requireRuntimeDirectory("LTD_RENDERER_ROOT", runtimePaths.rendererRoot);
    const assetRoot = requireRuntimeDirectory("LTD_RENDERER_ASSET_ROOT", runtimePaths.assetRoot);
    // Child Python processes import the active-parts builder in-process. Give
    // that module the same normalized asset root even when an override was
    // configured relative to the repository.
    process.env.LTD_RENDERER_ROOT = root;
    process.env.LTD_RENDERER_ASSET_ROOT = assetRoot;
    const python = String(process.env.LTD_RENDERER_PYTHON || "python").trim() || "python";
    const activePartsScript = path.join(root, "tools", "build_mii_active_parts.py");
    const renderScript = path.join(root, "renderer", "render_mii.py");
    const workerScript = path.join(root, "renderer", "render_worker.py");
    const capabilityLedger = path.join(root, "renderer", "classic_bridge_resource_bundles.json");
    const partsMetadata = path.join(root, "manifests", "render_asset_byml_metadata.jsonl");
    const portraitFraming = path.join(root, "renderer", "classic_bridge_portrait_framing.json");
    const canonicalizer = fileURLToPath(new URL("./ltdCanonical.js", import.meta.url));
    const presentationContextModule = fileURLToPath(
        new URL("./ltdPresentationContext.js", import.meta.url)
    );
    const workerClientModule = fileURLToPath(new URL("./ltdRenderWorkerClient.js", import.meta.url));
    const rendererClientModule = fileURLToPath(new URL("./ltdImageRenderer.js", import.meta.url));
    const nativeRuntimeClientModule = fileURLToPath(
        new URL("./ltdNativeRendererClient.js", import.meta.url)
    );
    const nativeRuntimeAdapterModule = fileURLToPath(
        new URL("./ltdNativeRendererAdapter.js", import.meta.url)
    );
    for (const required of [activePartsScript, renderScript, capabilityLedger, partsMetadata, portraitFraming]) {
        let stat;
        try {
            stat = fs.statSync(required);
        } catch (error) {
            throw new LtdRenderError(
                "LTD_RENDERER_NOT_CONFIGURED",
                `Required LTD renderer input is missing: ${path.basename(required)}`,
                { cause: error, status: 503 }
            );
        }
        if (!stat.isFile()) {
            throw new LtdRenderError(
                "LTD_RENDERER_NOT_CONFIGURED",
                `Required LTD renderer input is not a regular file: ${path.basename(required)}`,
                { status: 503 }
            );
        }
    }
    return {
        root,
        assetRoot,
        python,
        activePartsScript,
        renderScript,
        workerScript,
        persistentWorkerEnabled: persistentWorkerRequested()
            && fs.existsSync(workerScript)
            && fs.statSync(workerScript).isFile(),
        capabilityLedger,
        partsMetadata,
        portraitFraming,
        directRenderContracts: DIRECT_RENDER_CONTRACT_PATHS
            .map(parts => path.join(root, ...parts))
            .filter(filePath => fs.existsSync(filePath) && fs.statSync(filePath).isFile()),
        canonicalizer,
        presentationContextModule,
        workerClientModule,
        rendererClientModule,
        nativeRuntimeClientModule,
        nativeRuntimeAdapterModule,
        nativeRuntime: resolveNativeLtdRuntimeConfiguration(root),
        persistentWorkerRevisionFiles: fs.existsSync(workerScript)
            && fs.statSync(workerScript).isFile()
            ? [workerScript]
            : []
    };
}

function hashFile(filePath) {
    return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

function isPlainObject(value) {
    return value !== null && typeof value === "object" && !Array.isArray(value);
}

function hasExactKeys(value, expectedKeys) {
    if (!isPlainObject(value)) return false;
    const keys = Object.keys(value);
    return keys.length === expectedKeys.length
        && expectedKeys.every(key => Object.prototype.hasOwnProperty.call(value, key));
}

function matchesExactObject(value, expected) {
    const expectedKeys = Object.keys(expected);
    return hasExactKeys(value, expectedKeys)
        && expectedKeys.every(key => value[key] === expected[key]);
}

function arraysEqual(left, right) {
    return Array.isArray(left)
        && left.length === right.length
        && left.every((value, index) => value === right[index]);
}

function invalidFavoriteShirtPolicy(cause = undefined) {
    return new LtdRenderError(
        "LTD_RENDERER_NOT_CONFIGURED",
        "The configured LTD renderer favorite-shirt policy artifact is invalid.",
        { cause, status: 503 }
    );
}

export function loadFavoriteShirtPolicyContract(rendererRoot) {
    const policyPath = path.join(
        path.resolve(String(rendererRoot || "")),
        ...FAVORITE_SHIRT_POLICY_RELATIVE_PATH
    );
    let bytes;
    try {
        const stat = fs.lstatSync(policyPath);
        if (!stat.isFile() || stat.isSymbolicLink() || stat.size < 1 || stat.size > 64 * 1024) {
            throw new Error("favorite-shirt policy must be a small regular file");
        }
        bytes = fs.readFileSync(policyPath);
        if (bytes.length !== stat.size) throw new Error("favorite-shirt policy changed while loading");
    } catch (error) {
        throw invalidFavoriteShirtPolicy(error);
    }

    let value;
    try {
        value = JSON.parse(bytes.toString("utf8"));
    } catch (error) {
        throw invalidFavoriteShirtPolicy(error);
    }
    const expectedTopLevelKeys = [
        "schema_version",
        "policy",
        "description",
        "title_exact",
        "title_exact_boundary",
        "mapping_basis",
        "source_boundary",
        "shirt_albedo",
        "favorite_color_rgb_hex",
        "favorite_color_to_authored_variation",
        "favorite_color_to_authored_variant_label",
        "authored_variation_bntx_sha256"
    ];
    const expectedTitleExactBoundary = {
        authored_shirt_family_and_loading_mechanism: true,
        favorite_color_to_suffix_projection: false
    };
    const expectedMappingBasis = "curated_named_authored_variant_with_neutral_fallback";
    const expectedSourceBoundary = {
        source_field: "general.favoriteColor",
        context_is_ltd_sha256_bound: true,
        share_mii_contains_favorite_color: false,
        presentation_profile_variation_used: false,
        reference_image_values_used: false
    };
    const expectedShirtAlbedo = {
        mode: "select_authored_character_color_albedo",
        authored_albedo_variation_used: true,
        texture_name_pattern: "ClothTopsTshirtLongTexDefault_Body_Alb.{variation:02d}",
        source_rgb_used: true,
        source_alpha_preserved: true,
        alpha_sampler_active: false,
        normal_texture_unchanged: "ClothTopsTshirtLongTexDefault_Body_Nrm",
        material_information_texture_unchanged: "ClothTopsTshirtLongTexDefault_Body_Mic"
    };
    const labels = value?.favorite_color_to_authored_variant_label;
    const bntxHashes = value?.authored_variation_bntx_sha256;
    const valid = hasExactKeys(value, expectedTopLevelKeys)
        && value.schema_version === 2
        && value.policy === INFINIMII_FAVORITE_SHIRT_CONTEXT_KIND
        && typeof value.description === "string"
        && value.description.trim().length > 0
        && value.title_exact === false
        && matchesExactObject(value.title_exact_boundary, expectedTitleExactBoundary)
        && value.mapping_basis === expectedMappingBasis
        && matchesExactObject(value.source_boundary, expectedSourceBoundary)
        && matchesExactObject(value.shirt_albedo, expectedShirtAlbedo)
        && arraysEqual(value.favorite_color_rgb_hex, INFINIMII_FAVORITE_SHIRT_RGB)
        && arraysEqual(
            value.favorite_color_to_authored_variation,
            INFINIMII_FAVORITE_SHIRT_VARIATIONS
        )
        && Array.isArray(labels)
        && labels.length === INFINIMII_FAVORITE_SHIRT_RGB.length
        && labels.every(label => typeof label === "string" && label.length > 0)
        && Array.isArray(bntxHashes)
        && bntxHashes.length === 17
        && bntxHashes.every(hash => SHA256_PATTERN.test(hash) && hash === hash.toLowerCase())
        && new Set(bntxHashes).size === bntxHashes.length;
    if (!valid) throw invalidFavoriteShirtPolicy();

    const contract = Object.freeze({
        policy: value.policy,
        favoriteColorRgbHex: Object.freeze([...value.favorite_color_rgb_hex]),
        favoriteColorToAuthoredVariation: Object.freeze([
            ...value.favorite_color_to_authored_variation
        ]),
        favoriteColorToAuthoredVariantLabel: Object.freeze([...labels]),
        authoredVariationBntxSha256: Object.freeze([...bntxHashes]),
        mappingBasis: expectedMappingBasis,
        shirtAlbedo: Object.freeze({ ...expectedShirtAlbedo }),
        artifact: Object.freeze({
            path: FAVORITE_SHIRT_POLICY_RELATIVE_PATH.join("/"),
            byte_length: bytes.length,
            sha256: crypto.createHash("sha256").update(bytes).digest("hex")
        })
    });
    canonicalFavoriteShirtPolicyContracts.add(contract);
    return contract;
}

function invalidReferenceOutfitMipCache(cause = undefined) {
    return new LtdRenderError(
        "LTD_RENDERER_NOT_CONFIGURED",
        "The configured LTD renderer reference-outfit mip cache is invalid.",
        { cause, status: 503 }
    );
}

function deepFreezeJson(value) {
    if (value === null || typeof value !== "object" || Object.isFrozen(value)) return value;
    for (const child of Object.values(value)) deepFreezeJson(child);
    return Object.freeze(value);
}

function exactJsonEqual(left, right) {
    if (left === null || right === null || typeof left !== "object" || typeof right !== "object") {
        return Object.is(left, right);
    }
    if (Array.isArray(left) || Array.isArray(right)) {
        return Array.isArray(left)
            && Array.isArray(right)
            && left.length === right.length
            && left.every((value, index) => exactJsonEqual(value, right[index]));
    }
    const leftKeys = Object.keys(left).sort();
    const rightKeys = Object.keys(right).sort();
    return arraysEqual(leftKeys, rightKeys)
        && leftKeys.every(key => exactJsonEqual(left[key], right[key]));
}

function pythonAsciiJsonString(value) {
    return JSON.stringify(value).replace(/[\u0080-\uffff]/g, character =>
        `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`
    );
}

function pythonCanonicalManifestJson(value, parentKey = null, currentKey = null) {
    if (value === null) return "null";
    if (typeof value === "string") return pythonAsciiJsonString(value);
    if (typeof value === "boolean") return value ? "true" : "false";
    if (typeof value === "number") {
        if (!Number.isFinite(value)) throw new Error("manifest JSON contains a non-finite number");
        const samplerFloat = parentKey === "sampler"
            && new Set(["min_lod", "max_lod", "lod_bias"]).has(currentKey);
        if (samplerFloat && Number.isInteger(value)) {
            return `${Object.is(value, -0) ? "-0" : String(value)}.0`;
        }
        return Object.is(value, -0) ? "0" : String(value);
    }
    if (Array.isArray(value)) {
        return `[${value.map(child => pythonCanonicalManifestJson(child)).join(",")}]`;
    }
    if (!isPlainObject(value)) throw new Error("manifest JSON contains a non-JSON value");
    const entries = Object.keys(value).sort().map(key =>
        `${pythonAsciiJsonString(key)}:${pythonCanonicalManifestJson(value[key], currentKey, key)}`
    );
    return `{${entries.join(",")}}`;
}

function referenceOutfitMipChainSha256(record) {
    return crypto
        .createHash("sha256")
        .update(pythonCanonicalManifestJson(record), "utf8")
        .digest("hex");
}

export function loadReferenceOutfitMipManifestContract(rendererRoot) {
    const root = path.resolve(rendererRoot);
    const manifestPath = path.join(root, ...REFERENCE_OUTFIT_MIP_MANIFEST_RELATIVE_PATH);
    if (!fs.existsSync(manifestPath)) return null;

    try {
        const manifestStat = fs.lstatSync(manifestPath);
        if (
            !manifestStat.isFile()
            || manifestStat.isSymbolicLink()
            || manifestStat.size < 1
            || manifestStat.size > 4 * 1024 * 1024
        ) throw new Error("reference-outfit mip manifest must be a small regular file");
        const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
        const textures = manifest?.textures;
        if (
            manifest?.schema_version !== 1
            || !Array.isArray(textures)
            || !Number.isInteger(manifest.texture_count)
            || manifest.texture_count !== textures.length
            || !Number.isInteger(manifest.mip_level_count)
            || manifest.mip_level_count < 1
        ) throw new Error("reference-outfit mip manifest inventory is invalid");

        const cacheRoot = path.join(root, ...REFERENCE_OUTFIT_MIP_CACHE_RELATIVE_PATH);
        const cacheStat = fs.lstatSync(cacheRoot);
        if (!cacheStat.isDirectory() || cacheStat.isSymbolicLink()) {
            throw new Error("reference-outfit mip cache must be a regular directory");
        }
        const names = textures.map(texture => texture?.name);
        if (
            names.some(name => typeof name !== "string" || !name || /[\\/]/.test(name))
            || new Set(names).size !== names.length
        ) throw new Error("reference-outfit texture names are invalid");
        const cacheEntries = fs.readdirSync(cacheRoot, { withFileTypes: true });
        if (
            cacheEntries.some(entry => !entry.isDirectory() || entry.isSymbolicLink())
            || !arraysEqual(
                cacheEntries.map(entry => entry.name).sort(),
                [...names].sort()
            )
        ) throw new Error("reference-outfit mip directory inventory changed");

        const files = [];
        let levelCount = 0;
        for (const texture of textures) {
            const levels = texture?.levels;
            if (
                !Number.isInteger(texture?.mip_count)
                || texture.mip_count < 1
                || !Array.isArray(levels)
                || levels.length !== texture.mip_count
            ) throw new Error(`reference-outfit mip inventory changed for ${texture?.name}`);
            const textureDirectory = path.join(cacheRoot, texture.name);
            const textureStat = fs.lstatSync(textureDirectory);
            if (!textureStat.isDirectory() || textureStat.isSymbolicLink()) {
                throw new Error(`reference-outfit texture directory changed for ${texture.name}`);
            }
            const expectedFileNames = [];
            for (let index = 0; index < levels.length; index += 1) {
                const level = levels[index];
                const expectedFileName = `mip_${String(index).padStart(2, "0")}.png`;
                const expectedRelativePath = [
                    ...REFERENCE_OUTFIT_MIP_CACHE_RELATIVE_PATH,
                    texture.name,
                    expectedFileName
                ].join("/");
                if (
                    !isPlainObject(level)
                    || level.level !== index
                    || level.path !== expectedRelativePath
                    || !Number.isInteger(level.byte_length)
                    || level.byte_length < 1
                    || !SHA256_PATTERN.test(String(level.sha256 || ""))
                    || level.sha256 !== level.sha256.toLowerCase()
                ) throw new Error(`reference-outfit mip level ${index} changed for ${texture.name}`);
                const levelPath = path.resolve(root, ...level.path.split("/"));
                if (path.dirname(levelPath) !== path.resolve(textureDirectory)) {
                    throw new Error(`reference-outfit mip escaped its texture directory: ${level.path}`);
                }
                const levelStat = fs.lstatSync(levelPath);
                if (!levelStat.isFile() || levelStat.isSymbolicLink()) {
                    throw new Error(`reference-outfit mip is not a regular file: ${level.path}`);
                }
                const bytes = fs.readFileSync(levelPath);
                const digest = crypto.createHash("sha256").update(bytes).digest("hex");
                if (bytes.length !== level.byte_length || digest !== level.sha256) {
                    throw new Error(`reference-outfit mip hash changed: ${level.path}`);
                }
                expectedFileNames.push(expectedFileName);
                files.push(levelPath);
                levelCount += 1;
            }
            const actualEntries = fs.readdirSync(textureDirectory, { withFileTypes: true });
            if (
                actualEntries.some(entry => !entry.isFile() || entry.isSymbolicLink())
                || !arraysEqual(
                    actualEntries.map(entry => entry.name).sort(),
                    expectedFileNames.sort()
                )
            ) throw new Error(`reference-outfit mip file inventory changed for ${texture.name}`);
        }
        if (levelCount !== manifest.mip_level_count) {
            throw new Error("reference-outfit total mip level inventory changed");
        }
        const recordsByName = Object.fromEntries(textures.map(texture => [
            texture.name,
            deepFreezeJson(texture)
        ]));
        const mipChainSha256ByName = Object.fromEntries(textures.map(texture => [
            texture.name,
            referenceOutfitMipChainSha256(texture)
        ]));
        const contract = Object.freeze({
            artifact: Object.freeze({
                path: REFERENCE_OUTFIT_MIP_MANIFEST_RELATIVE_PATH.join("/"),
                byte_length: manifestStat.size,
                sha256: hashFile(manifestPath)
            }),
            recordsByName: Object.freeze(recordsByName),
            mipChainSha256ByName: Object.freeze(mipChainSha256ByName),
            mipChainHashScope: REFERENCE_OUTFIT_MIP_CHAIN_HASH_SCOPE,
            revisionFiles: Object.freeze([...files])
        });
        canonicalReferenceOutfitMipManifestContracts.add(contract);
        return contract;
    } catch (error) {
        if (error instanceof LtdRenderError) throw error;
        throw invalidReferenceOutfitMipCache(error);
    }
}

function getReferenceOutfitMipManifestContract(config) {
    const key = rendererConfigurationIdentity(config);
    if (!referenceOutfitMipManifestContractSnapshots.has(key)) {
        referenceOutfitMipManifestContractSnapshots.set(
            key,
            loadReferenceOutfitMipManifestContract(config.root)
        );
    }
    return referenceOutfitMipManifestContractSnapshots.get(key);
}

function listPythonFiles(directory) {
    const files = [];
    const visit = current => {
        for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
            const child = path.join(current, entry.name);
            if (entry.isDirectory()) visit(child);
            else if (entry.isFile() && entry.name.toLowerCase().endsWith(".py")) files.push(child);
        }
    };
    visit(directory);
    return files;
}

function listOptionalNativeRendererFiles(directory) {
    if (!fs.existsSync(directory)) return [];
    const files = [];
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
        if (!entry.isFile()) continue;
        const lowerName = entry.name.toLowerCase();
        if (
            lowerName.endsWith(".c")
            || lowerName.endsWith(".so")
            || lowerName.endsWith(".dylib")
            || lowerName.endsWith(".pyd")
        ) {
            files.push(path.join(directory, entry.name));
        }
    }
    return files;
}

function rendererRuntimeFingerprint(config) {
    const key = config.python;
    if (rendererRuntimeFingerprintSnapshots.has(key)) {
        return rendererRuntimeFingerprintSnapshots.get(key);
    }
    const script = [
        "import hashlib,json,platform,sys",
        "import numpy,PIL,zstandard",
        "import numpy._core._multiarray_umath as numpy_core",
        "from PIL import _imaging as pillow_core",
        "import zstandard.backend_c as zstandard_core",
        "def digest(name):",
        "    with open(name,'rb') as stream:",
        "        return hashlib.sha256(stream.read()).hexdigest()",
        "payload={",
        "    'executable':sys.executable,",
        "    'executable_sha256':digest(sys.executable),",
        "    'implementation':platform.python_implementation(),",
        "    'python':platform.python_version(),",
        "    'cache_tag':getattr(sys.implementation,'cache_tag',None),",
        "    'numpy':numpy.__version__,",
        "    'numpy_core_sha256':digest(numpy_core.__file__),",
        "    'pillow':PIL.__version__,",
        "    'pillow_core_sha256':digest(pillow_core.__file__),",
        "    'zstandard':zstandard.__version__,",
        "    'zstandard_core_sha256':digest(zstandard_core.__file__),",
        "}",
        "print(json.dumps(payload,sort_keys=True,separators=(',',':')))"
    ].join("\n");
    const completed = spawnSync(config.python, ["-c", script], {
        cwd: config.root,
        encoding: "utf8",
        timeout: 15_000,
        windowsHide: true
    });
    if (completed.error || completed.status !== 0) {
        throw new LtdRenderError(
            "LTD_RENDERER_NOT_CONFIGURED",
            "The configured LTD renderer Python runtime could not be fingerprinted.",
            { cause: completed.error, status: 503 }
        );
    }
    const output = String(completed.stdout || "").trim();
    let parsed;
    try {
        parsed = JSON.parse(output);
    } catch (error) {
        throw new LtdRenderError(
            "LTD_RENDERER_NOT_CONFIGURED",
            "The configured LTD renderer Python runtime emitted an invalid fingerprint.",
            { cause: error, status: 503 }
        );
    }
    const fingerprint = JSON.stringify(parsed);
    rendererRuntimeFingerprintSnapshots.set(key, fingerprint);
    return fingerprint;
}

function rendererRevision(config) {
    const files = new Set([
        config.activePartsScript,
        config.capabilityLedger,
        config.partsMetadata,
        config.portraitFraming,
        config.canonicalizer,
        config.presentationContextModule,
        config.workerClientModule,
        config.rendererClientModule,
        config.nativeRuntimeClientModule,
        config.nativeRuntimeAdapterModule,
        ...config.persistentWorkerRevisionFiles,
        ...(config.nativeRuntime?.revisionFiles || []),
        ...config.directRenderContracts,
        ...listPythonFiles(path.join(config.root, "renderer")),
        ...listOptionalNativeRendererFiles(path.join(config.root, "renderer"))
    ]);
    const referenceMipContract = getReferenceOutfitMipManifestContract(config);
    for (const mipPath of referenceMipContract?.revisionFiles || []) files.add(mipPath);
    const bymlParser = path.join(config.root, "tools", "byml_v7.py");
    if (fs.existsSync(bymlParser)) files.add(bymlParser);
    const hasher = crypto.createHash("sha256")
        .update("infinimii-ltd-renderer-revision-v4-transparent-native-resolution\0")
        .update(`${LTD_RENDER_WORKER_PROTOCOL}\0${LTD_RENDER_WORKER_PROTOCOL_VERSION}\0`)
        .update(rendererRuntimeFingerprint(config))
        .update("\0");
    for (const filePath of [...files].sort((a, b) => a.localeCompare(b))) {
        hasher
            .update(path.relative(config.root, filePath).replaceAll("\\", "/"))
            .update("\0")
            .update(hashFile(filePath));
    }
    return hasher.digest("hex");
}

function rendererConfigurationIdentity(config) {
    return [
        config.root,
        config.assetRoot,
        config.python,
        config.nativeRuntime ? "native-runtime-candidate" : "python-only",
        config.persistentWorkerEnabled ? "persistent-worker" : "cold-process"
    ].join("\0");
}

function processRendererRevision(config) {
    const key = rendererConfigurationIdentity(config);
    let revision = rendererRevisionSnapshots.get(key);
    if (!revision) {
        revision = rendererRevision(config);
        rendererRevisionSnapshots.set(key, revision);
    }
    return revision;
}

export function getConfiguredLtdRendererRevision() {
    return processRendererRevision(resolveLtdRendererConfiguration());
}

async function acquireRenderSlot() {
    await renderSlotLimiter.acquire();
}

function releaseRenderSlot() {
    renderSlotLimiter.release();
}

function appendBounded(current, chunk) {
    if (current.length >= MAX_OUTPUT_CHARS) return current;
    return (current + chunk.toString("utf8")).slice(0, MAX_OUTPUT_CHARS);
}

function escapeRegExp(value) {
    return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function sanitizeDiagnosticText(value, sensitivePaths = []) {
    let sanitized = String(value || "")
        .replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, "")
        .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, "");
    for (const [index, sensitivePath] of sensitivePaths.entries()) {
        const resolved = String(sensitivePath || "").trim();
        if (!resolved) continue;
        sanitized = sanitized.replace(
            new RegExp(escapeRegExp(resolved), "gi"),
            index === 0 ? "<render-workspace>" : `<renderer-path-${index}>`
        );
    }
    // A traceback can name the per-request input even when a child normalizes
    // path separators differently than Node. Keep the useful filename/line
    // tail without retaining the random host temporary directory.
    sanitized = sanitized.replace(
        /(?:[A-Za-z]:[\\/]|\/)(?:[^\r\n"']*[\\/])?infinimii-ltd-render-[^\\/\s"']+/gi,
        "<render-workspace>"
    );
    return sanitized.slice(-MAX_DIAGNOSTIC_CHARS);
}

export function sanitizeChildDiagnostics(result, sensitivePaths = []) {
    const code = Number.isInteger(result?.code) ? result.code : "unknown";
    const stderr = sanitizeDiagnosticText(result?.stderr, sensitivePaths).trim();
    const stdout = sanitizeDiagnosticText(result?.stdout, sensitivePaths).trim();
    return [
        `exitCode=${code}`,
        ...(stderr ? [`stderr:\n${stderr}`] : []),
        ...(stdout ? [`stdout:\n${stdout}`] : [])
    ].join("\n").slice(-MAX_DIAGNOSTIC_CHARS);
}

function runProcess(command, args, {
    cwd,
    timeoutMs = RENDER_TIMEOUT_MS,
    sensitivePaths = []
} = {}) {
    return new Promise((resolve, reject) => {
        const child = spawn(command, args, {
            cwd,
            shell: false,
            windowsHide: true,
            stdio: ["ignore", "pipe", "pipe"]
        });
        let stdout = "";
        let stderr = "";
        let timedOut = false;
        const timer = setTimeout(() => {
            timedOut = true;
            child.kill("SIGKILL");
        }, timeoutMs);
        timer.unref?.();
        child.stdout.on("data", chunk => { stdout = appendBounded(stdout, chunk); });
        child.stderr.on("data", chunk => { stderr = appendBounded(stderr, chunk); });
        child.once("error", error => {
            clearTimeout(timer);
            reject(new LtdRenderError("RENDER_FAILED", "Could not start the LTD renderer process.", {
                cause: error,
                diagnostics: sanitizeDiagnosticText(
                    `spawnError=${error?.code || error?.name || "unknown"}: ${error?.message || ""}`,
                    sensitivePaths
                ),
                status: 503
            }));
        });
        child.once("close", code => {
            clearTimeout(timer);
            if (timedOut) {
                reject(new LtdRenderError("RENDER_TIMEOUT", "The LTD renderer timed out.", {
                    diagnostics: sanitizeChildDiagnostics({ code, stdout, stderr }, sensitivePaths),
                    status: 503
                }));
                return;
            }
            resolve({ code, stdout, stderr });
        });
    });
}

function getPersistentRendererPool(config) {
    const identity = rendererConfigurationIdentity(config);
    let pool = persistentRendererPools.get(identity);
    if (!pool) {
        pool = new PersistentRenderWorkerPool({
            command: config.python,
            workerScript: config.workerScript,
            cwd: config.root,
            maxWorkers: MAX_CONCURRENT_RENDERS,
            startupTimeoutMs: 30_000
        });
        persistentRendererPools.set(identity, pool);
    }
    return pool;
}

function disablePersistentRendererPool(config) {
    const identity = rendererConfigurationIdentity(config);
    disabledPersistentWorkerIdentities.add(identity);
    const pool = persistentRendererPools.get(identity);
    if (pool) pool.close();
    persistentRendererPools.delete(identity);
}

export function closePersistentLtdRenderWorkers() {
    for (const pool of persistentRendererPools.values()) pool.close();
    persistentRendererPools.clear();
    closeNativeLtdRuntimePools();
}

process.once("exit", closePersistentLtdRenderWorkers);

export async function resetWorkerWorkspaceForColdFallback(workerRequest) {
    const inputPath = path.resolve(workerRequest.input);
    const workspace = path.dirname(inputPath);
    const outputDirectory = path.resolve(workerRequest.output_dir);
    const activePartsPath = path.resolve(workerRequest.build_active_parts);
    if (
        path.basename(workspace).startsWith("infinimii-ltd-render-") === false
        || path.dirname(outputDirectory) !== workspace
        || path.basename(outputDirectory) !== "output"
        || path.dirname(activePartsPath) !== workspace
        || path.basename(activePartsPath) !== "active_parts.json"
    ) {
        throw new LtdRenderError(
            "RENDER_CLEANUP_FAILED",
            "Refusing to reset an unexpected persistent-worker workspace.",
            { status: 503 }
        );
    }
    await Promise.all([
        fs.promises.rm(outputDirectory, { recursive: true, force: true, maxRetries: 2, retryDelay: 50 }),
        fs.promises.rm(activePartsPath, { force: true, maxRetries: 2, retryDelay: 50 })
    ]);
    await fs.promises.mkdir(outputDirectory);
}

async function runConfiguredRenderer(config, renderArguments, workerRequest, options = {}) {
    const identity = rendererConfigurationIdentity(config);
    let attemptedPersistentWorker = false;
    if (config.persistentWorkerEnabled && !disabledPersistentWorkerIdentities.has(identity)) {
        attemptedPersistentWorker = true;
        try {
            const result = await getPersistentRendererPool(config).run(workerRequest, {
                timeoutMs: options.timeoutMs || RENDER_TIMEOUT_MS
            });
            if (!result.restartWorker) return result;
        } catch (error) {
            if (!(error instanceof PersistentRenderWorkerError) || error.workerUnavailable !== true) {
                throw error;
            }
            // Startup/protocol failures cannot improve without a deployment
            // change. Disable this process-local pool after the first failure;
            // the exact cold renderer below remains available.
            if ([
                "WORKER_START_FAILED",
                "WORKER_START_TIMEOUT",
                "WORKER_PROTOCOL_ERROR"
            ].includes(error.code)) {
                disablePersistentRendererPool(config);
            }
        }
    }
    if (attemptedPersistentWorker) await resetWorkerWorkspaceForColdFallback(workerRequest);
    return await runProcess(config.python, renderArguments, options);
}

export function classifyRendererFailure(result, { sensitivePaths = [] } = {}) {
    const detail = `${result.stdout}\n${result.stderr}`;
    const lensModeMismatch = detail.match(/glass_lens_material_mode\s*=\s*0\s*,\s*got\s+(-?\d+)/i);
    if (lensModeMismatch && ![0, 1, 2].includes(Number(lensModeMismatch[1]))) {
        return new LtdRenderError(
            "INVALID_LTD",
            "The LTD contains a lens material mode outside the recovered title domain.",
            { deterministic: true, status: 400 }
        );
    }
    if (/must be .*(?:got|received)|outside (?:the )?(?:valid|supported) range|invalid CharInfoEx/i.test(detail)) {
        return new LtdRenderError(
            "INVALID_LTD",
            "The LTD contains a CharInfoEx value outside the recovered title domain.",
            { deterministic: true, status: 400 }
        );
    }
    if (
        /requires a separate faceline target/i.test(detail)
        || /not supported by (?:the )?classic bridge/i.test(detail)
        || /classic bridge fails closed/i.test(detail)
        || /classic-bridge composition enables an unsupported optional component/i.test(detail)
        || /classic-bridge generated faceline layers lack an exact contract/i.test(detail)
        || /extended_faceline_color_unimplemented/i.test(detail)
        || /classic_faceline_[a-z0-9_]*selection[a-z0-9_]*(?:unimplemented|unsupported|fail_closed)/i.test(detail)
        || /classic_faceline_[a-z0-9_]*selection[a-z0-9_]*.*(?:is unsupported|unimplemented|fails? closed)/i.test(detail)
    ) {
        return new LtdRenderError(
            "UNSUPPORTED_LTD_RENDER_PATH",
            "This valid LTD needs a source-backed render path that is not in the portable renderer yet.",
            { deterministic: true }
        );
    }
    if (
        /resource[- ]signature|classic (?:bridge|capability) requires|no source-backed.*bundle|unsupported.*resource|classic resource bundle/i.test(detail)
        || /classic-bridge.*(?:unstaged components|not composable)/i.test(detail)
        || /classic-bridge composition lacks a required active base component/i.test(detail)
        || /classic-bridge selector is outside the exact component domain/i.test(detail)
    ) {
        return new LtdRenderError(
            "UNSUPPORTED_LTD_RESOURCE_SIGNATURE",
            "This valid LTD uses rendering resources that are not in the checked portable bundle yet.",
            { deterministic: true }
        );
    }
    if (/unsupported.*flag|fail.closed.*flag|CharInfo.*flag/i.test(detail)) {
        return new LtdRenderError(
            "UNSUPPORTED_CHARINFO_FLAG",
            "This valid LTD enables a CharInfoEx feature whose render path is not recovered yet.",
            { deterministic: true }
        );
    }
    if (/PartsIndex|active parts|unresolved.*part/i.test(detail)) {
        return new LtdRenderError(
            "UNRESOLVED_PARTS",
            "The LTD PartsIndex selection could not be resolved exactly.",
            { deterministic: true }
        );
    }
    if (/invalid.*ltd|ShareMii.*invalid|unsupported.*version/i.test(detail)) {
        return new LtdRenderError("INVALID_LTD", "The renderer rejected the LTD container.", {
            deterministic: true,
            status: 400
        });
    }
    return new LtdRenderError("RENDER_FAILED", "The LTD renderer failed without publishing an image.", {
        diagnostics: sanitizeChildDiagnostics(result, sensitivePaths),
        status: 503
    });
}

function normalizeRenderOptions(options = {}) {
    const allowed = new Set(["fullBody", "size", "presentationContext"]);
    const unsupported = Object.keys(options).filter(key => !allowed.has(key) && options[key] !== undefined);
    if (unsupported.length > 0) {
        throw new LtdRenderError(
            "UNSUPPORTED_RENDER_OPTIONS",
            `The LTD renderer does not support these options: ${unsupported.join(", ")}.`,
            { deterministic: true }
        );
    }
    const parsedSize = Number(options.size ?? 512);
    if (!Number.isInteger(parsedSize) || parsedSize < 128 || parsedSize > 1024) {
        throw new LtdRenderError("UNSUPPORTED_RENDER_OPTIONS", "LTD render size must be 128-1024 pixels.", {
            deterministic: true
        });
    }
    const presentationContext = options.presentationContext == null
        ? null
        : normalizeLtdPresentationContext(options.presentationContext);
    return {
        fullBody: options.fullBody === true,
        size: parsedSize,
        presentationContext,
        presentationContextSha256: getLtdPresentationContextSha256(presentationContext),
        presentationContextKind: presentationContext?.kind || LTD_PRESENTATION_CONTEXT_NONE
    };
}

export async function validateTransparentRgbaPng(buffer, expectedSize, {
    rasterProfile = NATIVE_RASTER_PROFILE
} = {}) {
    const requirePartialAlpha = rasterProfile === SSAA_RASTER_PROFILE;
    if (rasterProfile !== NATIVE_RASTER_PROFILE && !requirePartialAlpha) {
        throw new LtdRenderError(
            "RENDER_FAILED",
            `The LTD renderer output uses an unknown raster profile: ${rasterProfile}.`,
            { status: 503 }
        );
    }
    if (!buffer.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) {
        throw new LtdRenderError("RENDER_FAILED", "The LTD renderer output is not a PNG.", { status: 503 });
    }
    const image = sharp(buffer);
    const metadata = await image.metadata();
    if (metadata.width !== expectedSize || metadata.height !== expectedSize) {
        throw new LtdRenderError("RENDER_FAILED", "The LTD renderer output dimensions are incorrect.", {
            status: 503
        });
    }
    if (metadata.hasAlpha !== true || metadata.channels !== 4) {
        throw new LtdRenderError(
            "RENDER_OUTPUT_NOT_TRANSPARENT",
            "The LTD renderer output is not an RGBA PNG.",
            { status: 503 }
        );
    }
    const { data, info } = await image.raw().toBuffer({ resolveWithObject: true });
    let transparentPixels = 0;
    let partialAlphaPixels = 0;
    let opaquePixels = 0;
    let transparentRgbViolation = false;
    let foregroundMinX = info.width;
    let foregroundMinY = info.height;
    let foregroundMaxX = -1;
    let foregroundMaxY = -1;
    for (let offset = 0; offset < data.length; offset += info.channels) {
        const alpha = data[offset + 3];
        if (alpha === 0) {
            transparentPixels += 1;
            if (data[offset] !== 0 || data[offset + 1] !== 0 || data[offset + 2] !== 0) {
                transparentRgbViolation = true;
            }
        } else if (alpha === 255) {
            opaquePixels += 1;
        } else {
            partialAlphaPixels += 1;
        }
        if (alpha !== 0) {
            const pixelIndex = offset / info.channels;
            const x = pixelIndex % info.width;
            const y = Math.floor(pixelIndex / info.width);
            foregroundMinX = Math.min(foregroundMinX, x);
            foregroundMinY = Math.min(foregroundMinY, y);
            foregroundMaxX = Math.max(foregroundMaxX, x);
            foregroundMaxY = Math.max(foregroundMaxY, y);
        }
    }
    const pixelCount = info.width * info.height;
    const minimumForegroundPixels = Math.max(1, Math.ceil(pixelCount * 0.01));
    const minimumBackgroundPixels = Math.max(1, Math.ceil(pixelCount * 0.01));
    const foregroundPixels = opaquePixels + partialAlphaPixels;
    const minimumForegroundSpan = Math.max(1, Math.ceil(Math.min(info.width, info.height) * 0.01));
    const foregroundWidth = foregroundMaxX >= foregroundMinX
        ? foregroundMaxX - foregroundMinX + 1
        : 0;
    const foregroundHeight = foregroundMaxY >= foregroundMinY
        ? foregroundMaxY - foregroundMinY + 1
        : 0;
    if (
        transparentPixels < minimumBackgroundPixels
        || opaquePixels === 0
        || (requirePartialAlpha && partialAlphaPixels === 0)
        || foregroundPixels < minimumForegroundPixels
        || foregroundWidth < minimumForegroundSpan
        || foregroundHeight < minimumForegroundSpan
        || transparentRgbViolation
    ) {
        throw new LtdRenderError(
            "RENDER_OUTPUT_NOT_TRANSPARENT",
            requirePartialAlpha
                ? "The LTD renderer output lacks a canonical transparent background and meaningful anti-aliased foreground."
                : "The LTD renderer output lacks a canonical transparent background and meaningful foreground.",
            { status: 503 }
        );
    }
    return metadata;
}

function rejectUnboundHeadwearReport() {
    throw new LtdRenderError(
        "RENDER_FAILED",
        "The LTD render report does not bind the requested legacy-headwear presentation draw.",
        { status: 503 }
    );
}

function matchesLegacyHeadwearIdentity(value, expected, sourceHairType) {
    return value?.source_hair_type === sourceHairType
        && value?.presentation_kind === expected.presentationKind
        && value?.resource === expected.resource
        && value?.model === expected.resource
        && value?.model_index === 0
        && value?.shape === expected.shape
        && value?.gameall_program === 96;
}

function validateLegacyHeadwearReportBinding(report, output, {
    ltdSha256,
    presentationContext,
    presentationContextKind,
    presentationContextSha256
}) {
    const reportedContext = report?.presentation_context;
    const capabilityHeadwear = report?.resource_support?.classic_bridge?.legacy_headwear_presentation;
    const hairAttachment = report?.hair_attachment_state;
    const hairSelections = Array.isArray(hairAttachment?.model_selections)
        ? hairAttachment.model_selections
        : [];
    const activeMaterialPath = report?.active_material_path;
    const submittedTriangles = output?.submitted_triangles;
    const submittedHeadwearKeys = submittedTriangles && typeof submittedTriangles === "object"
        && !Array.isArray(submittedTriangles)
        ? Object.keys(submittedTriangles).filter(key => key.startsWith("legacy_headwear:"))
        : [];

    if (presentationContextKind === LTD_PRESENTATION_CONTEXT_NONE) {
        if (
            presentationContext != null
            || reportedContext?.for_hat !== false
            || reportedContext?.source_hair_type !== null
            || capabilityHeadwear?.status !== "inactive_no_source_context"
            || hairAttachment?.legacy_headwear !== null
            || hairSelections.some(selection => selection?.for_hat === true)
            || Object.prototype.hasOwnProperty.call(activeMaterialPath || {}, "legacy_headwear")
            || submittedHeadwearKeys.length !== 0
        ) rejectUnboundHeadwearReport();
        return;
    }

    let normalizedContext;
    try {
        normalizedContext = normalizeLtdPresentationContext(presentationContext);
    } catch {
        rejectUnboundHeadwearReport();
    }
    const sourceHairType = getLegacyHeadwearSourceType(normalizedContext);
    if (sourceHairType == null) {
        if (
            normalizedContext.kind !== INFINIMII_FAVORITE_SHIRT_CONTEXT_KIND
            || reportedContext?.for_hat !== false
            || reportedContext?.source_hair_type !== null
            || capabilityHeadwear?.status !== "inactive_no_source_context"
            || hairAttachment?.legacy_headwear !== null
            || hairSelections.some(selection => selection?.for_hat === true)
            || Object.prototype.hasOwnProperty.call(activeMaterialPath || {}, "legacy_headwear")
            || submittedHeadwearKeys.length !== 0
        ) rejectUnboundHeadwearReport();
        return;
    }
    const expected = LEGACY_HEADWEAR_REPORT_CONTRACT[sourceHairType];
    const normalizedLtdSha256 = String(ltdSha256 || "").toLowerCase();
    const normalizedContextSha256 = String(presentationContextSha256 || "").toLowerCase();
    if (
        !expected
        || normalizedContext.kind !== presentationContextKind
        || normalizedContext.ltdSha256 !== normalizedLtdSha256
        || getLtdPresentationContextSha256(normalizedContext) !== normalizedContextSha256
        || reportedContext?.for_hat !== true
        || reportedContext?.source_hair_type !== sourceHairType
        || reportedContext?.canonical_hair_type !== 45
    ) rejectUnboundHeadwearReport();

    const headwearDrawKey = `legacy_headwear:${expected.shape}`;
    const forHatHair = hairSelections.length === 1 ? hairSelections[0] : null;
    const attachmentHeadwear = hairAttachment?.legacy_headwear;
    const materialHeadwear = activeMaterialPath?.legacy_headwear;
    if (
        !matchesLegacyHeadwearIdentity(
            capabilityHeadwear,
            expected,
            sourceHairType
        )
        || !matchesLegacyHeadwearIdentity(
            attachmentHeadwear,
            expected,
            sourceHairType
        )
        || !matchesLegacyHeadwearIdentity(
            materialHeadwear,
            expected,
            sourceHairType
        )
        || forHatHair?.logical_name !== "hair"
        || forHatHair?.resource !== "MiiHairAllLegacy045"
        || forHatHair?.model_name !== "MiiHairAllLegacyHat045"
        || forHatHair?.model_index !== 1
        || forHatHair?.for_hat !== true
        || materialHeadwear?.loaded !== true
        || materialHeadwear?.rendered !== true
        || materialHeadwear?.draw_key !== headwearDrawKey
        || submittedHeadwearKeys.length !== 1
        || submittedHeadwearKeys[0] !== headwearDrawKey
        || submittedTriangles?.[headwearDrawKey] !== expected.submittedTriangles
    ) rejectUnboundHeadwearReport();
}

function rejectUnboundFavoriteShirtReport() {
    throw new LtdRenderError(
        "RENDER_FAILED",
        "The LTD render report does not bind the requested InfiniMii favorite-shirt policy.",
        { status: 503 }
    );
}

const FAVORITE_SHIRT_REPORT_KEYS = Object.freeze([
    "status",
    "policy",
    "favorite_color",
    "rgb_hex",
    "source_field",
    "context_is_ltd_sha256_bound",
    "title_exact",
    "authored_shirt_family_and_loading_mechanism_title_exact",
    "favorite_color_to_suffix_projection_title_exact",
    "mapping_basis",
    "authored_variation",
    "authored_variant_label",
    "albedo_mode",
    "source_albedo",
    "source_bntx_sha256",
    "selected_mip_manifest_record",
    "source_mip_chain_sha256",
    "source_mip_chain_hash_scope",
    "source_rgb_used",
    "source_alpha_preserved",
    "authored_albedo_variation_used",
    "presentation_profile_variation_used",
    "alpha_sampler_active",
    "normal_texture_unchanged",
    "material_information_texture_unchanged",
    "policy_artifact"
]);

function matchesExactFavoriteShirtReport(value, expected) {
    if (!hasExactKeys(value, FAVORITE_SHIRT_REPORT_KEYS)) return false;
    for (const key of FAVORITE_SHIRT_REPORT_KEYS) {
        if (key === "policy_artifact" || key === "selected_mip_manifest_record") continue;
        if (value[key] !== expected[key]) return false;
    }
    return matchesExactObject(value.policy_artifact, expected.policy_artifact)
        && exactJsonEqual(
            value.selected_mip_manifest_record,
            expected.selected_mip_manifest_record
        );
}

function validateFavoriteShirtReportBinding(report, {
    presentationContext,
    favoriteShirtPolicyContract,
    referenceOutfitMipManifestContract
}) {
    let favoritePolicy = null;
    try {
        favoritePolicy = getFavoriteShirtPolicy(presentationContext);
    } catch {
        rejectUnboundFavoriteShirtReport();
    }
    const reportedContext = report?.presentation_context;
    const contextPolicy = reportedContext?.favorite_shirt;
    const materialPath = report?.active_material_path?.presentation_outfit;
    const materialPolicy = materialPath?.favorite_shirt;

    if (favoritePolicy == null) {
        if (
            reportedContext?.favorite_color !== null
            || reportedContext?.favorite_color_rgb_hex !== null
            || contextPolicy?.status !== "inactive_no_source_context"
            || contextPolicy?.policy !== INFINIMII_FAVORITE_SHIRT_CONTEXT_KIND
            || contextPolicy?.title_exact !== false
            || materialPolicy?.status !== "inactive_no_source_context"
        ) rejectUnboundFavoriteShirtReport();
        return;
    }

    if (!canonicalFavoriteShirtPolicyContracts.has(favoriteShirtPolicyContract)) {
        rejectUnboundFavoriteShirtReport();
    }
    if (!canonicalReferenceOutfitMipManifestContracts.has(referenceOutfitMipManifestContract)) {
        rejectUnboundFavoriteShirtReport();
    }
    const favoriteColor = favoritePolicy.favoriteColor;
    const authoredVariation = favoriteShirtPolicyContract
        .favoriteColorToAuthoredVariation[favoriteColor];
    const authoredVariantLabel = favoriteShirtPolicyContract
        .favoriteColorToAuthoredVariantLabel[favoriteColor];
    const sourceAlbedo = `ClothTopsTshirtLongTexDefault_Body_Alb.${String(authoredVariation).padStart(2, "0")}`;
    const selectedMipManifestRecord = referenceOutfitMipManifestContract
        .recordsByName[sourceAlbedo];
    const sourceMipChainSha256 = referenceOutfitMipManifestContract
        .mipChainSha256ByName[sourceAlbedo];
    if (
        favoritePolicy.policy !== favoriteShirtPolicyContract.policy
        || favoritePolicy.rgbHex !== favoriteShirtPolicyContract.favoriteColorRgbHex[favoriteColor]
        || favoritePolicy.authoredVariation !== authoredVariation
        || favoritePolicy.authoredAlbedo !== sourceAlbedo
        || favoritePolicy.sourceField !== "general.favoriteColor"
        || favoritePolicy.titleExact !== false
        || !selectedMipManifestRecord
        || selectedMipManifestRecord.name !== sourceAlbedo
        || selectedMipManifestRecord.source_sha256 !== favoriteShirtPolicyContract
            .authoredVariationBntxSha256[authoredVariation]
        || !SHA256_PATTERN.test(String(sourceMipChainSha256 || ""))
    ) rejectUnboundFavoriteShirtReport();

    const expected = {
        status: "active",
        policy: favoriteShirtPolicyContract.policy,
        favorite_color: favoriteColor,
        rgb_hex: favoritePolicy.rgbHex,
        source_field: "general.favoriteColor",
        context_is_ltd_sha256_bound: true,
        title_exact: false,
        authored_shirt_family_and_loading_mechanism_title_exact: true,
        favorite_color_to_suffix_projection_title_exact: false,
        mapping_basis: favoriteShirtPolicyContract.mappingBasis,
        authored_variation: authoredVariation,
        authored_variant_label: authoredVariantLabel,
        albedo_mode: "select_authored_character_color_albedo",
        source_albedo: sourceAlbedo,
        source_bntx_sha256: favoriteShirtPolicyContract
            .authoredVariationBntxSha256[authoredVariation],
        selected_mip_manifest_record: selectedMipManifestRecord,
        source_mip_chain_sha256: sourceMipChainSha256,
        source_mip_chain_hash_scope: referenceOutfitMipManifestContract.mipChainHashScope,
        source_rgb_used: true,
        source_alpha_preserved: true,
        authored_albedo_variation_used: true,
        presentation_profile_variation_used: false,
        alpha_sampler_active: false,
        normal_texture_unchanged: "ClothTopsTshirtLongTexDefault_Body_Nrm",
        material_information_texture_unchanged: "ClothTopsTshirtLongTexDefault_Body_Mic",
        policy_artifact: favoriteShirtPolicyContract.artifact
    };
    if (
        reportedContext?.favorite_color !== favoriteColor
        || reportedContext?.favorite_color_rgb_hex !== favoritePolicy.rgbHex
        || !matchesExactFavoriteShirtReport(contextPolicy, expected)
        || !matchesExactFavoriteShirtReport(materialPolicy, expected)
        || materialPath?.tops?.resource !== "ClothTopsTshirtLong"
        || materialPath?.tops?.material !== "mt_Body"
        || materialPath?.tops?.gameall_program !== 984
        || materialPath?.tops?.normal !== "ClothTopsTshirtLongTexDefault_Body_Nrm (unchanged)"
        || materialPath?.tops?.material_information !== "ClothTopsTshirtLongTexDefault_Body_Mic (unchanged)"
        || materialPath?.tops?.serialized_alpha_mask !== "inactive in selected GameAll 984; not sampled"
        || materialPath?.tops?.albedo !== contextPolicy?.source_albedo
        || materialPath?.tops?.albedo_source_bntx_sha256 !== expected.source_bntx_sha256
        || materialPath?.tops?.albedo_mip_chain_sha256 !== expected.source_mip_chain_sha256
        || materialPath?.tops?.albedo_mip_chain_hash_scope !== expected.source_mip_chain_hash_scope
        || materialPath?.tops?.presentation_profile_variation_used_for_policy !== false
    ) rejectUnboundFavoriteShirtReport();
}

export function validateRenderReportBinding(report, {
    ltdSha256,
    outputSha256,
    imageName,
    reportView,
    size,
    presentationContext = null,
    presentationContextSha256,
    presentationContextKind,
    favoriteShirtPolicyContract = null,
    referenceOutfitMipManifestContract = null,
    supersampleFactor = 1
}) {
    if (String(report?.input_sha256 || "").toLowerCase() !== String(ltdSha256 || "").toLowerCase()) {
        throw new LtdRenderError("RENDER_FAILED", "The LTD render report names a different input hash.", {
            status: 503
        });
    }
    const capability = report?.resource_support?.classic_bridge;
    if (
        typeof capability?.capability_key !== "string"
        || !capability.capability_key
        || !SHA256_PATTERN.test(String(capability?.resource_signature?.sha256 || ""))
    ) {
        throw new LtdRenderError("RENDER_FAILED", "The LTD render report lacks exact capability provenance.", {
            status: 503
        });
    }
    const outputs = Array.isArray(report?.outputs) ? report.outputs : [];
    const output = outputs.length === 1 ? outputs[0] : null;
    const reportedPresentationContext = report?.presentation_context;
    if (
        output?.path !== imageName
        || output?.view !== reportView
        || output?.size?.length !== 2
        || output.size[0] !== size
        || output.size[1] !== size
        || output?.supersampling?.raster_size?.[0] !== size * supersampleFactor
        || output?.supersampling?.raster_size?.[1] !== size * supersampleFactor
        || output?.supersampling?.portable_profile !== "native-resolution-v1"
        || String(output?.sha256 || "").toLowerCase() !== String(outputSha256 || "").toLowerCase()
        || reportedPresentationContext?.kind !== presentationContextKind
        || String(reportedPresentationContext?.sha256 || "").toLowerCase()
            !== String(presentationContextSha256 || "").toLowerCase()
    ) {
        throw new LtdRenderError(
            "RENDER_FAILED",
            "The LTD render report does not bind the requested output bytes, view, and dimensions.",
            { status: 503 }
        );
    }
    validateLegacyHeadwearReportBinding(report, output, {
        ltdSha256,
        presentationContext,
        presentationContextKind,
        presentationContextSha256
    });
    validateFavoriteShirtReportBinding(report, {
        presentationContext,
        favoriteShirtPolicyContract,
        referenceOutfitMipManifestContract
    });
    return capability;
}

function normalizeAttemptFailure(error, sensitivePaths) {
    if (error instanceof LtdRenderError) return error;
    return new LtdRenderError("RENDER_FAILED", "The LTD renderer encountered a transient process failure.", {
        cause: error,
        diagnostics: sanitizeDiagnosticText(
            `${error?.name || "Error"}: ${error?.message || String(error)}`,
            sensitivePaths
        ),
        status: 503
    });
}

function cleanupFailure(error, sensitivePaths) {
    return new LtdRenderError("RENDER_CLEANUP_FAILED", "The LTD renderer could not clean up its workspace.", {
        cause: error,
        diagnostics: sanitizeDiagnosticText(
            `${error?.name || "Error"}: ${error?.message || String(error)}`,
            sensitivePaths
        ),
        status: 503
    });
}

async function renderAttempt(ltdBytes, options, config, revision) {
    await acquireRenderSlot();
    const tempParent = path.resolve(os.tmpdir());
    let tempDirectory;
    let result;
    let failure;
    try {
        const favoriteShirtPolicyContract = options.presentationContextKind
            === INFINIMII_FAVORITE_SHIRT_CONTEXT_KIND
            ? loadFavoriteShirtPolicyContract(config.root)
            : null;
        const referenceOutfitMipManifestContract = options.presentationContextKind
            === INFINIMII_FAVORITE_SHIRT_CONTEXT_KIND
            ? getReferenceOutfitMipManifestContract(config)
            : null;
        tempDirectory = await fs.promises.mkdtemp(path.join(tempParent, "infinimii-ltd-render-"));
        const sensitivePaths = [tempDirectory, config.root, config.assetRoot];
        const inputPath = path.join(tempDirectory, "input.ltd");
        const activePartsPath = path.join(tempDirectory, "active_parts.json");
        const presentationContextPath = path.join(tempDirectory, "presentation_context.json");
        const outputDirectory = path.join(tempDirectory, "output");
        await fs.promises.mkdir(outputDirectory);
        await fs.promises.writeFile(inputPath, ltdBytes, { flag: "wx" });
        if (options.presentationContext) {
            await fs.promises.writeFile(
                presentationContextPath,
                `${JSON.stringify(options.presentationContext, null, 2)}\n`,
                { flag: "wx" }
            );
        }

        const view = options.fullBody ? "full-body" : "portrait";
        const renderArguments = [
            config.renderScript,
            inputPath,
            "--asset-root", config.assetRoot,
            "--build-active-parts", activePartsPath,
            "--output-dir", outputDirectory,
            "--size", String(options.size),
            "--view", view,
            "--supersample-factor", "1"
        ];
        if (options.presentationContext) {
            renderArguments.push("--presentation-context", presentationContextPath);
        }
        const workerRequest = {
            input: inputPath,
            asset_root: config.assetRoot,
            build_active_parts: activePartsPath,
            output_dir: outputDirectory,
            size: options.size,
            view,
            supersample_factor: 1,
            ...(options.presentationContext
                ? { presentation_context: presentationContextPath }
                : {})
        };
        const nativeAttempt = config.nativeRuntime && [128, 512].includes(options.size)
            ? await tryNativeLtdRender(config.nativeRuntime, {
                ltdPath: inputPath,
                outputDirectory,
                size: options.size,
                view: options.fullBody ? "full_body" : "portrait",
                presentationContextKind: options.presentationContextKind,
                presentationContextSha256: options.presentationContextSha256
            }, { timeoutMs: RENDER_TIMEOUT_MS })
            : { activated: false, reason: "not-configured-or-size-unsupported" };
        let renderResult;
        if (nativeAttempt.activated) {
            renderResult = {
                code: 0,
                stdout: "native LTD runtime rendered the requested image",
                stderr: "",
                nativeRuntime: true
            };
        } else {
            if (config.nativeRuntime) {
                // A failed or unsupported native attempt may have written a
                // partial file. Never let it influence the established
                // renderer or its report validation.
                await resetWorkerWorkspaceForColdFallback(workerRequest);
            }
            renderResult = await runConfiguredRenderer(config, renderArguments, workerRequest, {
                cwd: config.root,
                sensitivePaths
            });
        }
        if (renderResult.code !== 0) throw classifyRendererFailure(renderResult, { sensitivePaths });

        const imageName = options.fullBody ? "mii_full_body.png" : "mii.png";
        const imagePath = path.join(outputDirectory, imageName);
        const reportPath = path.join(outputDirectory, "render_report.json");
        const [buffer, reportBytes] = nativeAttempt.activated
            ? [
                nativeAttempt.result.validatedFiles.outputBytes,
                nativeAttempt.result.validatedFiles.reportBytes
            ]
            : await Promise.all([
                fs.promises.readFile(imagePath),
                fs.promises.readFile(reportPath)
            ]);
        await validateTransparentRgbaPng(buffer, options.size, {
            rasterProfile: NATIVE_RASTER_PROFILE
        });
        const report = JSON.parse(reportBytes.toString("utf8"));
        const ltdSha256 = getLtdSha256(ltdBytes);
        const outputSha256 = crypto.createHash("sha256").update(buffer).digest("hex");
        const expectedReportView = options.fullBody ? "posed_full_body" : "appearance_bust_portrait";
        const capability = validateRenderReportBinding(report, {
            ltdSha256,
            outputSha256,
            imageName,
            reportView: expectedReportView,
            size: options.size,
            presentationContext: options.presentationContext,
            presentationContextSha256: options.presentationContextSha256,
            presentationContextKind: options.presentationContextKind,
            favoriteShirtPolicyContract,
            referenceOutfitMipManifestContract,
            supersampleFactor: 1
        });
        result = {
            buffer,
            provenance: {
                ltdSha256,
                rendererRevision: revision,
                capabilityKey: capability.capability_key,
                resourceSignature: capability.resource_signature.sha256,
                outputSha256,
                view,
                size: options.size,
                backgroundMode: TRANSPARENT_BACKGROUND_MODE,
                presentationContextSha256: options.presentationContextSha256,
                presentationContextKind: options.presentationContextKind,
                rasterProfile: "native-resolution-v1",
                titleFinalPixelEquivalenceClaimed: false
            }
        };
    } catch (error) {
        failure = normalizeAttemptFailure(error, [tempDirectory, config.root, config.assetRoot]);
    }

    try {
        if (tempDirectory) {
            const resolved = path.resolve(tempDirectory);
            if (path.dirname(resolved) === tempParent && path.basename(resolved).startsWith("infinimii-ltd-render-")) {
                await fs.promises.rm(resolved, {
                    recursive: true,
                    force: true,
                    maxRetries: 2,
                    retryDelay: 50
                });
            } else {
                throw new Error("Refusing to clean an unexpected renderer workspace path.");
            }
        }
    } catch (error) {
        const cleanup = cleanupFailure(error, [tempDirectory, config.root, config.assetRoot]);
        if (!failure) {
            failure = cleanup;
        } else {
            failure.cleanupDiagnostics = cleanup.diagnostics;
        }
    } finally {
        releaseRenderSlot();
    }

    if (failure) throw failure;
    return result;
}

export async function executeRenderAttemptWithRetry(attemptRender, {
    ltdSha256 = "",
    rendererRevision: revision = "",
    presentationContextSha256 = "",
    presentationContextKind = LTD_PRESENTATION_CONTEXT_NONE,
    rasterProfile = "native-resolution-v1"
} = {}) {
    if (typeof attemptRender !== "function") throw new TypeError("attemptRender must be a function.");
    let previousDiagnostics = "";
    for (let attempt = 1; attempt <= MAX_RENDER_ATTEMPTS; attempt++) {
        try {
            return await attemptRender(attempt);
        } catch (error) {
            const failure = normalizeAttemptFailure(error, []);
            failure.ltdSha256 = ltdSha256;
            failure.rendererRevision = revision;
            failure.backgroundMode = TRANSPARENT_BACKGROUND_MODE;
            failure.presentationContextSha256 = presentationContextSha256;
            failure.presentationContextKind = presentationContextKind;
            failure.rasterProfile = rasterProfile;
            failure.attempts = attempt;
            if (previousDiagnostics) failure.previousAttemptDiagnostics = previousDiagnostics;
            if (failure.deterministic || attempt === MAX_RENDER_ATTEMPTS) throw failure;
            previousDiagnostics = failure.diagnostics || failure.message;
        }
    }
    throw new LtdRenderError("RENDER_FAILED", "The LTD renderer exhausted its retry budget.", { status: 503 });
}

async function renderWithRetry(ltdBytes, options, config, revision) {
    return await executeRenderAttemptWithRetry(
        async () => await renderAttempt(ltdBytes, options, config, revision),
        {
            ltdSha256: getLtdSha256(ltdBytes),
            rendererRevision: revision,
            presentationContextSha256: options.presentationContextSha256,
            presentationContextKind: options.presentationContextKind,
            rasterProfile: "native-resolution-v1"
        }
    );
}

export async function renderLtdImage(ltdBytes, rawOptions = {}) {
    const bytes = Buffer.from(ltdBytes);
    const options = normalizeRenderOptions(rawOptions);
    if (
        options.presentationContext
        && options.presentationContext.ltdSha256 !== getLtdSha256(bytes)
    ) {
        throw new LtdRenderError(
            "UNSUPPORTED_RENDER_OPTIONS",
            "The LTD presentation context is bound to different LTD bytes.",
            { deterministic: true }
        );
    }
    const config = resolveLtdRendererConfiguration();
    const revision = processRendererRevision(config);
    const key = `${getLtdSha256(bytes)}:${revision}:${config.persistentWorkerEnabled ? "persistent-worker" : "cold-process"}:${options.fullBody ? "full-body" : "portrait"}:${options.size}:${TRANSPARENT_BACKGROUND_MODE}:${options.presentationContextSha256}:native-resolution-v1`;
    let pending = pendingRenders.get(key);
    if (!pending) {
        pending = renderWithRetry(bytes, options, config, revision);
        pendingRenders.set(key, pending);
        pending.finally(() => {
            if (pendingRenders.get(key) === pending) pendingRenders.delete(key);
        }).catch(() => {});
    }
    const result = await pending;
    return { ...result, buffer: Buffer.from(result.buffer) };
}
