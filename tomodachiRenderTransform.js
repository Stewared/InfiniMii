import crypto from "crypto";
import sharp from "sharp";

export const TOMODACHI_SOURCE_WIDTH = 512;
export const TOMODACHI_SOURCE_HEIGHT = 1088;
export const TOMODACHI_FULL_BODY_SOURCE_HEIGHT = 512;
export const MII_IMAGE_SIZE = 512;

// This is the native viewport region that matches the site's previous MiiJS
// face camera. It intentionally clips the lower body instead of shrinking the
// complete portrait into the thumbnail.
export const LEGACY_FACE_FRAME = Object.freeze({
    left: 21,
    top: 85,
    width: 469,
    height: 469
});

const NATIVE_BACKGROUND = Object.freeze({ r: 0xf7, g: 0xf8, b: 0xfb });
const FACE_FRAME_PROFILE_VERSION = "legacy-face-v3";
const FULL_BODY_PROFILE_VERSION = "ffl-whole-body-camera-v1";

export function normalizeNativeTomodachiRenderSize(value = MII_IMAGE_SIZE) {
    const numeric = Number(value);
    if (!Number.isFinite(numeric)) return null;
    let size = Math.floor(numeric);
    size -= size % 64;
    if (size < 64) size = 64;
    return size <= 2048 ? size : null;
}

export function canUseNativeTomodachiRendererForOptions(options = {}) {
    if (!options || typeof options !== "object") return true;
    if (options.expression !== undefined && Number(options.expression) !== 0) return false;
    if (options.size !== undefined && normalizeNativeTomodachiRenderSize(options.size) === null) return false;
    if (options.bodyPath || options.fflResBuffer || options.fflResPath) return false;
    return true;
}

export function tomodachiFaceRenderCacheKey(renderKey, sourceSha256, size = MII_IMAGE_SIZE) {
    return `${FACE_FRAME_PROFILE_VERSION}:${String(renderKey)}:${String(sourceSha256).toLowerCase()}:${size}`;
}

export function tomodachiFullBodyRenderCacheKey(renderKey, sourceSha256, size = MII_IMAGE_SIZE) {
    return `${FULL_BODY_PROFILE_VERSION}:${String(renderKey)}:${String(sourceSha256).toLowerCase()}:${size}`;
}

function keyNativeBackground(data) {
    for (let offset = 0; offset < data.length; offset += 4) {
        if (
            data[offset] === NATIVE_BACKGROUND.r &&
            data[offset + 1] === NATIVE_BACKGROUND.g &&
            data[offset + 2] === NATIVE_BACKGROUND.b
        ) {
            data[offset] = 0;
            data[offset + 1] = 0;
            data[offset + 2] = 0;
            data[offset + 3] = 0;
        }
    }
}

async function readRgbaSource(sourceBuffer, { width, height, sourceIsRaw, id }) {
    if (sourceIsRaw) {
        const expectedLength = width * height * 4;
        if (sourceBuffer.length !== expectedLength) {
            throw new Error(`${id}: expected ${expectedLength} bytes of native RGBA data`);
        }
        return {
            data: Buffer.from(sourceBuffer),
            info: { width, height, channels: 4 }
        };
    }

    return sharp(sourceBuffer)
        .ensureAlpha()
        .raw()
        .toBuffer({ resolveWithObject: true });
}

export async function transformTomodachiFaceRender({
    sourceBuffer,
    id,
    sourceSha256,
    size = MII_IMAGE_SIZE,
    sourceIsRaw = false
}) {
    const expectedHash = String(sourceSha256 || "").toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(expectedHash)) {
        throw new Error(`${id}: missing native render SHA-256 for face framing`);
    }
    if (!Number.isInteger(size) || size < 64 || size > 2048) {
        throw new Error(`${id}: invalid face render size ${JSON.stringify(size)}`);
    }
    const actualHash = crypto.createHash("sha256").update(sourceBuffer).digest("hex");
    if (actualHash !== expectedHash) {
        throw new Error(`${id}: native render changed before face framing`);
    }
    const { data, info } = await readRgbaSource(sourceBuffer, {
        width: TOMODACHI_SOURCE_WIDTH,
        height: TOMODACHI_SOURCE_HEIGHT,
        sourceIsRaw,
        id
    });

    if (
        info.width !== TOMODACHI_SOURCE_WIDTH ||
        info.height !== TOMODACHI_SOURCE_HEIGHT ||
        info.channels !== 4
    ) {
        throw new Error(
            `Expected a ${TOMODACHI_SOURCE_WIDTH}x${TOMODACHI_SOURCE_HEIGHT} native RGBA render`
        );
    }

    // The audited native renderer uses one exact matte color. Key it before
    // resizing so Sharp creates clean antialiased alpha at the new edges.
    keyNativeBackground(data);

    return sharp(data, {
        raw: {
            width: info.width,
            height: info.height,
            channels: 4
        }
    })
        .extract(LEGACY_FACE_FRAME)
        .resize(size, size, {
            fit: "fill",
            kernel: sharp.kernel.lanczos3
        })
        .png({ compressionLevel: 9 })
        .toBuffer();
}

export async function transformTomodachiFullBodyRender({
    sourceBuffer,
    id,
    sourceSha256,
    size = MII_IMAGE_SIZE,
    sourceIsRaw = false
}) {
    const expectedHash = String(sourceSha256 || "").toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(expectedHash)) {
        throw new Error(`${id}: missing native render SHA-256 for full-body framing`);
    }
    if (!Number.isInteger(size) || size < 64 || size > 2048) {
        throw new Error(`${id}: invalid full-body render size ${JSON.stringify(size)}`);
    }
    const actualHash = crypto.createHash("sha256").update(sourceBuffer).digest("hex");
    if (actualHash !== expectedHash) {
        throw new Error(`${id}: native render changed before full-body framing`);
    }
    const { data, info } = await readRgbaSource(sourceBuffer, {
        width: TOMODACHI_SOURCE_WIDTH,
        height: TOMODACHI_FULL_BODY_SOURCE_HEIGHT,
        sourceIsRaw,
        id
    });

    if (
        info.width !== TOMODACHI_SOURCE_WIDTH ||
        info.height !== TOMODACHI_FULL_BODY_SOURCE_HEIGHT ||
        info.channels !== 4
    ) {
        throw new Error(
            `Expected a ${TOMODACHI_SOURCE_WIDTH}x${TOMODACHI_FULL_BODY_SOURCE_HEIGHT} native RGBA render`
        );
    }

    // Whole-body mode is already rendered in its final square camera viewport.
    // Only key the audited matte and perform an explicitly requested resize;
    // there is no fitted crop or per-Mii positioning step here.
    keyNativeBackground(data);
    let pipeline = sharp(data, {
        raw: {
            width: info.width,
            height: info.height,
            channels: 4
        }
    });
    if (size !== TOMODACHI_SOURCE_WIDTH) {
        pipeline = pipeline.resize(size, size, {
            fit: "fill",
            kernel: sharp.kernel.lanczos3
        });
    }
    return pipeline
        .png({ compressionLevel: 9 })
        .toBuffer();
}
