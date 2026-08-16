import crypto from "crypto";
import { execFile } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";
import { promisify } from "util";
import { fileURLToPath } from "url";
import { normalizeGlassesTypeFor3DSRender } from "miijs";

const execFileAsync = promisify(execFile);
const MODULE_DIRECTORY = path.dirname(fileURLToPath(import.meta.url));
const RUNTIME_ROOT = path.join(MODULE_DIRECTORY, "native", "tomodachi");
const ASSET_ROOT = path.join(RUNTIME_ROOT, "assets");
const BODY_MODEL_ROOT = path.join(ASSET_ROOT, "body", "models");
const BODY_MATERIAL_ROOT = path.join(ASSET_ROOT, "body", "materials");
const HEADWEAR_MODEL_ROOT = path.join(ASSET_ROOT, "headwear", "models");
const HEADWEAR_MATERIAL_ROOT = path.join(ASSET_ROOT, "headwear", "materials");
const BODY_MODEL_DIRECTORY = path.join(ASSET_ROOT, "model", "body");
const HEADWEAR_MODEL_DIRECTORY = path.join(ASSET_ROOT, "model", "headwear");
const OBJECT_MODEL_DIRECTORY = path.join(ASSET_ROOT, "model", "obj");
const CATALOG_ROOT = path.join(RUNTIME_ROOT, "catalog");

const SOURCE_WIDTH = 512;
const PORTRAIT_SOURCE_HEIGHT = 1088;
const FULL_BODY_SOURCE_HEIGHT = 512;
const RENDER_CONTRACT = "tomodachi-native-pica-cgfx-v1:THMSBIN1:THLUBIN1:spica-texenv-fraglight:texel-center-wrap-neighbor";
const COMPOSITION_CONTRACT = "tomodachi-shared-body-head-depth-ffl-high-v3";
const PORTRAIT_PROJECTION_CONTRACT = "tomodachi-portrait-orthographic-v1";
const FULL_BODY_PROJECTION_CONTRACT = "ffl-whole-body-camera-fov15-height-v1";
const RENDER_PLAN_VERSION = "infinimii-native-all-mii-ffl-high-v5";
const FAVORITE_COLOR_RGB = Object.freeze([
    "D21E14", "FF6E19", "FFD820", "78D220", "007830", "0A48B4",
    "3CAAE0", "F55A7D", "7328AD", "483818", "E0E0E0", "181814"
]);
const NATIVE_TOMODACHI_RENDERER_REVISION = sha256Json({
    renderContract: RENDER_CONTRACT,
    compositionContract: COMPOSITION_CONTRACT,
    portraitProjectionContract: PORTRAIT_PROJECTION_CONTRACT,
    fullBodyProjectionContract: FULL_BODY_PROJECTION_CONTRACT,
    renderPlanVersion: RENDER_PLAN_VERSION,
    favoriteColorRgb: FAVORITE_COLOR_RGB
});
const requestedConcurrency = Number.parseInt(
    process.env.TOMODACHI_NATIVE_RENDER_CONCURRENCY || "",
    10
);
const MAX_RENDER_CONCURRENCY = Number.isInteger(requestedConcurrency) && requestedConcurrency > 0
    ? Math.min(requestedConcurrency, 16)
    : Math.max(1, Math.min(4, os.availableParallelism?.() || os.cpus().length || 1));

let activeRenderCount = 0;
const renderWaiters = [];
const pendingRenders = new Map();
let cachedRendererExecutables = null;

function integer(value, fallback = 0) {
    const number = Number(value);
    return Number.isFinite(number) ? Math.trunc(number) : fallback;
}

function flag(value) {
    return value ? 1 : 0;
}

function stable(value) {
    if (Array.isArray(value)) return value.map(stable);
    if (value && typeof value === "object") {
        const result = {};
        for (const key of Object.keys(value).sort()) result[key] = stable(value[key]);
        return result;
    }
    return value;
}

function sha256Json(value) {
    return crypto
        .createHash("sha256")
        .update(Buffer.from(JSON.stringify(stable(value)), "utf8"))
        .digest("hex");
}

export function getNativeTomodachiRendererRevision() {
    return NATIVE_TOMODACHI_RENDERER_REVISION;
}

function toPlainMii(mii) {
    if (mii && typeof mii.toObject === "function") {
        return mii.toObject({ depopulate: true, flattenMaps: true });
    }
    return mii;
}

function decodedMiiFields(mii) {
    const plainMii = toPlainMii(mii);
    const fields = plainMii?.fields ?? plainMii;
    if (
        !fields ||
        typeof fields !== "object" ||
        Array.isArray(fields) ||
        !fields.general ||
        typeof fields.general !== "object" ||
        Array.isArray(fields.general)
    ) {
        throw new TypeError("Native Tomodachi rendering requires decoded Mii fields");
    }
    return fields;
}

export function normalizeNativeTomodachiGlassesType(value) {
    const type = value === undefined || value === null ? 0 : Number(value);
    return normalizeGlassesTypeFor3DSRender(type);
}

function parseCsv(text, sourceName) {
    const rows = [];
    let row = [];
    let field = "";
    let quoted = false;

    for (let index = 0; index < text.length; index += 1) {
        const character = text[index];
        if (quoted) {
            if (character === '"') {
                if (text[index + 1] === '"') {
                    field += '"';
                    index += 1;
                } else {
                    quoted = false;
                }
            } else {
                field += character;
            }
            continue;
        }

        if (character === '"' && field.length === 0) {
            quoted = true;
        } else if (character === ",") {
            row.push(field);
            field = "";
        } else if (character === "\n") {
            row.push(field.replace(/\r$/, ""));
            rows.push(row);
            row = [];
            field = "";
        } else {
            field += character;
        }
    }

    if (quoted) throw new Error(`Unterminated quoted CSV field in ${sourceName}`);
    if (field.length > 0 || row.length > 0) {
        row.push(field.replace(/\r$/, ""));
        rows.push(row);
    }
    if (rows.length < 2) throw new Error(`Renderer catalog is empty: ${sourceName}`);

    const headers = rows.shift().map((header, index) =>
        index === 0 ? header.replace(/^\uFEFF/, "") : header
    );
    return rows
        .filter(values => values.some(value => value !== ""))
        .map((values, rowIndex) => {
            if (values.length !== headers.length) {
                throw new Error(
                    `${sourceName}:${rowIndex + 2} has ${values.length} fields; expected ${headers.length}`
                );
            }
            return Object.fromEntries(headers.map((header, index) => [header, values[index]]));
        });
}

function readCatalog(name) {
    const catalogPath = path.join(CATALOG_ROOT, name);
    return parseCsv(fs.readFileSync(catalogPath, "utf8"), catalogPath);
}

function catalogPairs(rows, kind) {
    const pairs = new Map();
    for (const row of rows) {
        const key = `${integer(row.item_index, -1)}:${integer(row.color_slot, -1)}`;
        if (pairs.has(key)) throw new Error(`Duplicate ${kind} catalog pair ${key}`);
        pairs.set(key, Object.freeze(row));
    }
    return pairs;
}

function listArchives(directory, extension) {
    return new Set(
        fs.readdirSync(directory)
            .filter(name => name.endsWith(extension))
            .map(name => name.slice(0, -extension.length))
    );
}

const bodyPairs = catalogPairs(readCatalog("body_catalog_color_pairs.csv"), "body");
const headwearPairs = catalogPairs(readCatalog("headwear_catalog_color_pairs.csv"), "headwear");
const bodyArchives = listArchives(BODY_MODEL_ROOT, ".cgfx");
const headwearArchives = listArchives(HEADWEAR_MODEL_ROOT, ".cgfx");
const metadataRowsByArchive = new Map();
for (const row of readCatalog("headwear_metadata_variants.csv")) {
    const rows = metadataRowsByArchive.get(row.archive) || [];
    rows.push(Object.freeze(row));
    metadataRowsByArchive.set(row.archive, rows);
}

function hasTomodachiLifeData(mii) {
    const value = mii?.tl;
    return value !== null && value !== undefined && (
        typeof value !== "object" || Array.isArray(value) || Object.keys(value).length > 0
    );
}

function canonicalFields(fields) {
    return {
        gender: integer(fields?.general?.gender),
        favorite_color: integer(fields?.general?.favoriteColor),
        height: integer(fields?.general?.height, 64),
        weight: integer(fields?.general?.weight, 64),
        face_color: integer(fields?.face?.color),
        face_type: integer(fields?.face?.type),
        face_feature: integer(fields?.face?.feature),
        face_makeup: integer(fields?.face?.makeup),
        hair_type: integer(fields?.hair?.type),
        hair_flipped: flag(fields?.hair?.flipped),
        hair_color: integer(fields?.hair?.color, 1),
        hair_dye_color: integer(fields?.tl?.hairDye?.color),
        hair_dye_mode: integer(fields?.tl?.hairDye?.mode),
        eye_type: integer(fields?.eyes?.type),
        eye_color: integer(fields?.eyes?.color, 8),
        eye_size: integer(fields?.eyes?.size, 4),
        eye_squash: integer(fields?.eyes?.squash, 3),
        eye_rotation: integer(fields?.eyes?.rotation, 4),
        eye_distance: integer(fields?.eyes?.distanceApart, 2),
        eye_y: integer(fields?.eyes?.yPosition, 12),
        eyebrow_type: integer(fields?.eyebrows?.type, 6),
        eyebrow_color: integer(fields?.eyebrows?.color, 1),
        eyebrow_size: integer(fields?.eyebrows?.size, 4),
        eyebrow_squash: integer(fields?.eyebrows?.squash, 3),
        eyebrow_rotation: integer(fields?.eyebrows?.rotation, 6),
        eyebrow_distance: integer(fields?.eyebrows?.distanceApart, 2),
        eyebrow_y: integer(fields?.eyebrows?.yPosition, 7),
        nose_type: integer(fields?.nose?.type, 1),
        nose_size: integer(fields?.nose?.size, 4),
        nose_y: integer(fields?.nose?.yPosition, 9),
        mouth_type: integer(fields?.mouth?.type, 14),
        mouth_color: integer(fields?.mouth?.color, 19),
        mouth_size: integer(fields?.mouth?.size, 4),
        mouth_squash: integer(fields?.mouth?.squash, 3),
        mouth_y: integer(fields?.mouth?.yPosition, 13),
        mustache_type: integer(fields?.beard?.mustache?.type),
        mustache_size: integer(fields?.beard?.mustache?.size, 4),
        mustache_y: integer(fields?.beard?.mustache?.yPosition, 10),
        beard_type: integer(fields?.beard?.type),
        beard_color: integer(fields?.beard?.color, 8),
        glasses_type: normalizeNativeTomodachiGlassesType(fields?.glasses?.type),
        glasses_color: integer(fields?.glasses?.color, 8),
        glasses_size: integer(fields?.glasses?.size, 4),
        glasses_y: integer(fields?.glasses?.yPosition, 10),
        mole_on: flag(fields?.mole?.on),
        mole_size: integer(fields?.mole?.size, 4),
        mole_x: integer(fields?.mole?.xPosition, 2),
        mole_y: integer(fields?.mole?.yPosition, 20)
    };
}

function littleEndianHexWord(value, fallback) {
    if (typeof value !== "string" || !/^[0-9a-fA-F]{4}$/.test(value)) return fallback;
    return Number.parseInt(`${value.slice(2, 4)}${value.slice(0, 2)}`, 16);
}

function colorSlot(value) {
    const slot = integer(value, 0);
    return slot >= 0 && slot <= 15 ? slot : 0;
}

function selectBodyArchive(row, gender, miiType) {
    const available = String(row.physical_archives || "")
        .split("|")
        .filter(archive => archive && bodyArchives.has(archive));
    if (available.length === 0) {
        throw new Error(`Body item ${row.item_index} has no bundled physical archive`);
    }

    const fileId = integer(row.file_id, -1);
    const base = `body_body${String(fileId).padStart(3, "0")}`;
    let preferred = gender === 1 ? [`${base}F`, base] : [base, `${base}F`];
    if (fileId === 0) {
        const special = String(miiType || "").toLowerCase() === "special";
        if (special) {
            preferred = gender === 1
                ? ["body_body000SpF", "body_body000Sp"]
                : ["body_body000Sp", "body_body000SpF"];
        } else {
            preferred = gender === 1
                ? ["body_body000F", "body_body000"]
                : ["body_body000", "body_body000F"];
        }
    }

    const selected = preferred.find(archive => available.includes(archive));
    if (selected) return selected;
    if (available.length === 1) return available[0];
    throw new Error(
        `Could not resolve body item ${row.item_index} for gender ${gender}: ${available.join(", ")}`
    );
}

function metadataVariantFor(archive, hairType) {
    const matches = (metadataRowsByArchive.get(archive) || []).filter(row =>
        row.hair !== "" && integer(row.hair, -1) === hairType
    );
    if (matches.length > 1) {
        throw new Error(`${archive} has multiple metadata variants for hair ${hairType}`);
    }
    return matches.length === 1 ? integer(matches[0].metadata_variant, -1) : -1;
}

function miiCliArguments(fields) {
    return Object.entries(fields).map(([name, value]) =>
        `--mii-${name.replaceAll("_", "-")}=${value}`
    );
}

export async function planNativeTomodachiRender(mii, options = {}) {
    const fields = decodedMiiFields(mii);
    const canonical = canonicalFields(fields);
    const hasTlData = hasTomodachiLifeData(fields);
    const clothing = fields?.tl?.clothing;
    const outfitIndex = hasTlData
        ? littleEndianHexWord(clothing?.outfit, 0)
        : 0;
    const outfitColor = hasTlData ? colorSlot(clothing?.outfitColor) : 0;
    const headwearIndex = hasTlData
        ? littleEndianHexWord(clothing?.hat, 0xffff)
        : 0xffff;
    const headwearColor = hasTlData ? colorSlot(clothing?.hatColor) : 0;

    const bodyRow = bodyPairs.get(`${outfitIndex}:${outfitColor}`);
    if (!bodyRow) {
        throw new Error(`No Tomodachi body catalog row for item ${outfitIndex}, color ${outfitColor}`);
    }
    const bodyArchive = selectBodyArchive(bodyRow, canonical.gender, fields?.meta?.type);
    const bodyRgb = outfitIndex === 0
        ? FAVORITE_COLOR_RGB[canonical.favorite_color]
        : String(bodyRow.rgb_hex || "").toUpperCase();
    if (!/^[0-9A-F]{6}$/.test(bodyRgb || "")) {
        throw new Error(`Invalid body color for item ${outfitIndex}: ${JSON.stringify(bodyRgb)}`);
    }

    let headwear = null;
    if (headwearIndex !== 0xffff) {
        const row = headwearPairs.get(`${headwearIndex}:${headwearColor}`);
        if (!row) {
            throw new Error(
                `No Tomodachi headwear catalog row for item ${headwearIndex}, color ${headwearColor}`
            );
        }
        const archive = String(row.physical_archive || "");
        if (!headwearArchives.has(archive)) {
            throw new Error(`Headwear item ${headwearIndex} has no bundled physical archive`);
        }
        const rgb = String(row.rgb_hex || "").toUpperCase();
        if (!/^[0-9A-F]{6}$/.test(rgb)) {
            throw new Error(`Invalid headwear color for item ${headwearIndex}: ${JSON.stringify(rgb)}`);
        }
        const headTypes = new Set(
            (metadataRowsByArchive.get(archive) || []).map(metadataRow =>
                integer(metadataRow.head_type, -1)
            )
        );
        if (headTypes.size !== 1 || [...headTypes][0] < 0) {
            throw new Error(`${archive} does not have one authoritative CGFX HeadType`);
        }
        headwear = Object.freeze({
            itemIndex: headwearIndex,
            archive,
            rgb,
            typeId: integer(row.headwear_type_id, -1),
            headType: [...headTypes][0],
            metadataVariant: metadataVariantFor(archive, canonical.hair_type)
        });
    }

    const mode = Boolean(options?.fullBody) ? "full-body" : "portrait";
    const plan = {
        version: RENDER_PLAN_VERSION,
        mode,
        viewport: {
            width: SOURCE_WIDTH,
            height: mode === "full-body" ? FULL_BODY_SOURCE_HEIGHT : PORTRAIT_SOURCE_HEIGHT
        },
        canonical,
        body: {
            itemIndex: outfitIndex,
            archive: bodyArchive,
            rgb: bodyRgb
        },
        headwear
    };
    return Object.freeze({
        ...plan,
        cacheKey: sha256Json(plan)
    });
}

function executableNames() {
    const extension = process.platform === "win32" ? ".exe" : "";
    return {
        body: `render_body_model${extension}`,
        headwear: `render_headwear_model${extension}`
    };
}

function rendererBinDirectory() {
    const configured = String(process.env.TOMODACHI_NATIVE_RENDERER_BIN_DIR || "").trim();
    if (configured) return path.resolve(configured);
    if (process.platform === "win32" && process.arch === "x64") {
        return path.join(RUNTIME_ROOT, "bin", "win32-x64");
    }
    return path.join(RUNTIME_ROOT, "build");
}

function rendererExecutables() {
    if (cachedRendererExecutables) return cachedRendererExecutables;

    const names = executableNames();
    const directory = rendererBinDirectory();
    const releaseDirectory = path.join(directory, "Release");
    const resolveExecutable = name => {
        const direct = path.join(directory, name);
        if (fs.existsSync(direct)) return direct;
        const release = path.join(releaseDirectory, name);
        if (fs.existsSync(release)) return release;
        throw new Error(
            `Missing bundled Tomodachi renderer ${name}. Build native/tomodachi or set TOMODACHI_NATIVE_RENDERER_BIN_DIR.`
        );
    };
    cachedRendererExecutables = Object.freeze({
        body: resolveExecutable(names.body),
        headwear: resolveExecutable(names.headwear)
    });
    return cachedRendererExecutables;
}

async function acquireRenderPermit() {
    if (activeRenderCount < MAX_RENDER_CONCURRENCY) {
        activeRenderCount += 1;
        return;
    }
    await new Promise(resolve => renderWaiters.push(resolve));
    activeRenderCount += 1;
}

function releaseRenderPermit() {
    activeRenderCount -= 1;
    renderWaiters.shift()?.();
}

function validateRendererLog(log, rendererKind, mode, plan) {
    if (!log.includes(`native-pica=${RENDER_CONTRACT}`)) {
        throw new Error(`${rendererKind} renderer did not report the audited native shader contract`);
    }
    const compositionLines = log
        .split(/\r?\n/)
        .filter(line => line.startsWith("composition="));
    if (compositionLines.length !== 1 || compositionLines[0] !== `composition=${COMPOSITION_CONTRACT}`) {
        throw new Error(`${rendererKind} renderer composition contract changed`);
    }
    const expectedProjection = mode === "full-body"
        ? FULL_BODY_PROJECTION_CONTRACT
        : PORTRAIT_PROJECTION_CONTRACT;
    const projectionLines = log
        .split(/\r?\n/)
        .filter(line => line.startsWith("projection="));
    if (projectionLines.length !== 1 || projectionLines[0] !== `projection=${expectedProjection}`) {
        throw new Error(`${rendererKind} renderer projection contract changed`);
    }

    const countPattern = rendererKind === "body"
        ? /body-triangles=(\d+) body-fragments=(\d+) discarded-fragments=(\d+)/
        : /headwear-triangles=(\d+) body-triangles=(\d+) headwear-fragments=(\d+) body-fragments=(\d+)/;
    const counts = countPattern.exec(log)?.slice(1).map(Number);
    const requiredCounts = rendererKind === "body" ? counts?.slice(0, 2) : counts;
    if (!requiredCounts || requiredCounts.some(value => !Number.isFinite(value) || value <= 0)) {
        throw new Error(`${rendererKind} renderer reported an incomplete native draw`);
    }

    if (rendererKind === "headwear") {
        const selectorLines = log
            .split(/\r?\n/)
            .filter(line => line.startsWith("cfl-head-model="));
        const selectorMatch = selectorLines.length === 1
            ? /^cfl-head-model=(normal|cap|headgear) effective-hair=(-?\d+) shape-index=(-?\d+) headwear-type=(-?\d+) head-type=(-?\d+)$/.exec(selectorLines[0])
            : null;
        if (!selectorMatch) {
            throw new Error("headwear renderer did not report one complete CFL head selector");
        }
        const headType = plan.headwear.headType;
        const expectedModel = headType === 6
            ? "cap"
            : (headType === 7 || headType === 8 ? "headgear" : "normal");
        const expectedShapeIndex = expectedModel === "headgear"
            ? -1
            : (Math.min(131, Math.max(0, plan.canonical.hair_type)) * 2) +
                (expectedModel === "cap" ? 1 : 0);
        const [, model, effectiveHair, shapeIndex, headwearType, reportedHeadType] = selectorMatch;
        if (
            model !== expectedModel ||
            Number(effectiveHair) !== plan.canonical.hair_type ||
            Number(shapeIndex) !== expectedShapeIndex ||
            Number(headwearType) !== plan.headwear.typeId ||
            Number(reportedHeadType) !== headType
        ) {
            throw new Error(
                `headwear renderer CFL selector changed: expected ${expectedModel}/${plan.canonical.hair_type}/${expectedShapeIndex}/${plan.headwear.typeId}/${headType}, got ${selectorLines[0]}`
            );
        }
    }
}

function decodeRendererBmp(bmp, width, height) {
    if (
        bmp.length < 54 ||
        bmp[0] !== 0x42 ||
        bmp[1] !== 0x4d ||
        bmp.readUInt32LE(10) !== 54 ||
        bmp.readUInt32LE(14) !== 40 ||
        bmp.readInt32LE(18) !== width ||
        bmp.readInt32LE(22) !== -height ||
        bmp.readUInt16LE(26) !== 1 ||
        bmp.readUInt16LE(28) !== 32 ||
        bmp.readUInt32LE(30) !== 0 ||
        bmp.length !== 54 + (width * height * 4)
    ) {
        throw new Error("Native renderer produced an unsupported BMP layout");
    }

    const bgra = bmp.subarray(54);
    const rgba = Buffer.allocUnsafe(bgra.length);
    for (let offset = 0; offset < bgra.length; offset += 4) {
        rgba[offset] = bgra[offset + 2];
        rgba[offset + 1] = bgra[offset + 1];
        rgba[offset + 2] = bgra[offset];
        rgba[offset + 3] = bgra[offset + 3];
    }
    return rgba;
}

async function executePlan(plan) {
    await acquireRenderPermit();
    const workDirectory = await fs.promises.mkdtemp(path.join(os.tmpdir(), "infinimii-tomodachi-"));
    const outputPath = path.join(workDirectory, "render.bmp");
    const maskPath = path.join(workDirectory, "headwear-mask.bmp");

    try {
        const executables = rendererExecutables();
        const commonArguments = [
            `--body-dir=${BODY_MODEL_DIRECTORY}`,
            `--cfl=${path.join(ASSET_ROOT, "CFL_Res.dat")}`,
            `--ffl=${path.join(ASSET_ROOT, "FFLResHigh.dat")}`
        ];
        const bodyModel = path.join(BODY_MODEL_ROOT, `${plan.body.archive}.cgfx`);
        const bodyMaterial = path.join(BODY_MATERIAL_ROOT, `${plan.body.archive}.materials.bin`);
        const miiArguments = miiCliArguments(plan.canonical);
        const modeArguments = plan.mode === "full-body" ? ["--full-body"] : [];
        let executable;
        let rendererKind;
        let argumentsList;

        if (!plan.headwear) {
            executable = executables.body;
            rendererKind = "body";
            argumentsList = [
                `--model=${bodyModel}`,
                commonArguments[0],
                `--out=${outputPath}`,
                `--color=${plan.body.rgb}`,
                `--width=${plan.viewport.width}`,
                `--height=${plan.viewport.height}`,
                `--material-sidecar=${bodyMaterial}`,
                `--lut-sidecar=${path.join(BODY_MATERIAL_ROOT, "lutCommon.luts.bin")}`,
                `--lut-source=${path.join(ASSET_ROOT, "common", "env_lut_common.bin.dat")}`,
                ...miiArguments,
                ...modeArguments,
                commonArguments[1],
                commonArguments[2]
            ];
        } else {
            executable = executables.headwear;
            rendererKind = "headwear";
            argumentsList = [
                `--headwear-model=${path.join(HEADWEAR_MODEL_ROOT, `${plan.headwear.archive}.cgfx`)}`,
                `--headwear-item=${plan.headwear.itemIndex}`,
                `--headwear-rgb=${plan.headwear.rgb}`,
                `--headwear-metadata-variant=${plan.headwear.metadataVariant}`,
                `--headwear-type=${plan.headwear.typeId}`,
                `--fixed-body-model=${bodyModel}`,
                `--fixed-body-rgb=${plan.body.rgb}`,
                commonArguments[0],
                `--headwear-dir=${HEADWEAR_MODEL_DIRECTORY}`,
                `--head-model=${path.join(OBJECT_MODEL_DIRECTORY, "obj_mHead.bin.dat")}`,
                `--headwear-wrapper=${path.join(OBJECT_MODEL_DIRECTORY, "obj_mHeadwear.bin.dat")}`,
                commonArguments[1],
                commonArguments[2],
                `--material-sidecar=${path.join(HEADWEAR_MATERIAL_ROOT, `${plan.headwear.archive}.materials.bin`)}`,
                `--body-material-sidecar=${bodyMaterial}`,
                `--lut-sidecar=${path.join(BODY_MATERIAL_ROOT, "lutCommon.luts.bin")}`,
                `--lut-source=${path.join(ASSET_ROOT, "common", "env_lut_common.bin.dat")}`,
                `--object-mask-out=${maskPath}`,
                `--out=${outputPath}`,
                `--width=${plan.viewport.width}`,
                `--height=${plan.viewport.height}`,
                ...miiArguments,
                ...modeArguments
            ];
        }

        const result = await execFileAsync(executable, argumentsList, {
            cwd: RUNTIME_ROOT,
            encoding: "utf8",
            maxBuffer: 1024 * 1024,
            timeout: 120_000,
            windowsHide: true
        });
        validateRendererLog(
            `${result.stdout || ""}${result.stderr || ""}`,
            rendererKind,
            plan.mode,
            plan
        );
        const sourceBuffer = decodeRendererBmp(
            await fs.promises.readFile(outputPath),
            plan.viewport.width,
            plan.viewport.height
        );
        if (plan.headwear) {
            const mask = await fs.promises.stat(maskPath);
            if (!mask.isFile() || mask.size < 54) {
                throw new Error("Native headwear renderer did not produce its object mask");
            }
        }
        return Object.freeze({
            buffer: sourceBuffer,
            cacheKey: plan.cacheKey,
            width: plan.viewport.width,
            height: plan.viewport.height,
            mode: plan.mode
        });
    } catch (error) {
        const details = String(error?.stderr || error?.message || error)
            .replaceAll(MODULE_DIRECTORY, "<InfiniMii>")
            .slice(-4000);
        throw new Error(`Tomodachi native render failed: ${details}`, { cause: error });
    } finally {
        await fs.promises.rm(workDirectory, { recursive: true, force: true });
        releaseRenderPermit();
    }
}

export async function renderNativeTomodachiPlan(plan) {
    const existing = pendingRenders.get(plan.cacheKey);
    if (existing) return existing;

    const pending = executePlan(plan);
    pendingRenders.set(plan.cacheKey, pending);
    try {
        return await pending;
    } finally {
        if (pendingRenders.get(plan.cacheKey) === pending) {
            pendingRenders.delete(plan.cacheKey);
        }
    }
}

export async function renderNativeTomodachiMii(mii, options = {}) {
    const plan = await planNativeTomodachiRender(mii, options);
    return renderNativeTomodachiPlan(plan);
}
