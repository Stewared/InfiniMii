import qrcode from "qrcode-generator";
import sharp from "sharp";

function normalizeSize(value, fallback, { min = 0, max = 4096 } = {}) {
    const parsed = Number(value);
    if (!Number.isFinite(parsed)) return fallback;
    return Math.min(max, Math.max(min, Math.round(parsed)));
}

function safeCssColor(value, fallback) {
    const color = String(value || "").trim();
    return /^#[0-9a-f]{3,8}$/i.test(color) ? color : fallback;
}

function sanitizeXml10(value) {
    return String(value || "").replace(
        /[^\u0009\u000A\u000D\u0020-\uD7FF\uE000-\uFFFD\u{10000}-\u{10FFFF}]/gu,
        "\uFFFD"
    );
}

function escapeXml(value) {
    return sanitizeXml10(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&apos;");
}

function bytesToLatin1(value) {
    if (typeof value === "string") return value;
    if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
        return Buffer.from(value).toString("latin1");
    }
    throw new TypeError("QR payload must be a string, Buffer, or Uint8Array.");
}

function buildQrSvg(payload, options) {
    const size = normalizeSize(options.size, 512, { min: 64 });
    const margin = normalizeSize(options.margin, 0, { min: 0, max: Math.floor(size / 4) });
    const foreground = safeCssColor(options.dotsOptions?.color, "#000000");
    const background = safeCssColor(options.backgroundOptions?.color, "#ffffff");
    const errorCorrection = String(options.qrOptions?.errorCorrectionLevel || "H").toUpperCase();
    const correctionLevel = ["L", "M", "Q", "H"].includes(errorCorrection)
        ? errorCorrection
        : "H";

    const qr = qrcode(0, correctionLevel);
    qr.addData(bytesToLatin1(payload), "Byte");
    qr.make();

    const moduleCount = qr.getModuleCount();
    const moduleSize = Math.max(1, Math.floor((size - (margin * 2)) / moduleCount));
    const renderedSize = moduleCount * moduleSize;
    const offset = Math.floor((size - renderedSize) / 2);
    const paths = [];
    for (let row = 0; row < moduleCount; row++) {
        for (let column = 0; column < moduleCount; column++) {
            if (!qr.isDark(row, column)) continue;
            paths.push(`M${offset + (column * moduleSize)} ${offset + (row * moduleSize)}h${moduleSize}v${moduleSize}h-${moduleSize}z`);
        }
    }

    return {
        size,
        svg: Buffer.from(
            `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 ${size} ${size}" shape-rendering="crispEdges">`
            + `<rect width="${size}" height="${size}" fill="${background}"/>`
            + `<path d="${paths.join("")}" fill="${foreground}"/>`
            + "</svg>"
        )
    };
}

function buildPlateSvg(size, left, top, width, height, color = "#ffffff") {
    return Buffer.from(
        `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}">`
        + `<rect x="${left}" y="${top}" width="${width}" height="${height}" fill="${color}"/>`
        + "</svg>"
    );
}

function buildLabelSvg(size, label, centerX, baselineY, fontSize) {
    const text = escapeXml(String(label || "").replace(/\s+/g, " ").trim().slice(0, 80));
    if (!text) return null;
    const plateWidth = Math.min(size, Math.max(fontSize * 4, text.length * fontSize * 0.62));
    const plateHeight = Math.ceil(fontSize * 1.45);
    const plateX = Math.round(centerX - (plateWidth / 2));
    const plateY = Math.round(baselineY - fontSize);
    return Buffer.from(
        `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}">`
        + `<rect x="${plateX}" y="${plateY}" width="${plateWidth}" height="${plateHeight}" rx="${Math.ceil(fontSize / 3)}" fill="#ffffff" fill-opacity="0.88"/>`
        + `<text x="${centerX}" y="${baselineY}" text-anchor="middle" font-family="sans-serif" font-size="${fontSize}" font-weight="600" fill="#000000">${text}</text>`
        + "</svg>"
    );
}

function buildSpecialBorderSvg(size, left, top, box) {
    const lineWidth = Math.max(3, Math.round(size / 102));
    const half = lineWidth / 2;
    return Buffer.from(
        `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}">`
        + `<rect x="${left + half}" y="${top + half}" width="${box - lineWidth}" height="${box - lineWidth}" fill="none" stroke="#d4af37" stroke-width="${lineWidth}"/>`
        + `<rect x="${half}" y="${half}" width="${size - lineWidth}" height="${size - lineWidth}" fill="none" stroke="#d4af37" stroke-width="${lineWidth}"/>`
        + "</svg>"
    );
}

/**
 * Render a binary QR entirely through qrcode-generator + libvips/sharp.
 * This intentionally avoids node-canvas, whose native addon is unavailable on
 * some supported Node releases. The QR payload bytes remain byte-for-byte
 * binary data rather than being converted through UTF-8.
 */
export async function renderServerQrPng(payload, options = {}) {
    const { size, svg } = buildQrSvg(payload, options);
    const image = options.image;
    const label = String(options.label || "").trim();
    const isSpecial = options.special === true;
    // Match the original MiiJS contract: a label and special border decorate
    // an actual portrait overlay; without an image, keep the QR unobscured.
    // This also makes the portrait-render failure path maximally scannable.
    if (!image) {
        return await sharp(svg).png().toBuffer();
    }

    const overlayFracValue = Number(options.overlayFrac);
    const overlayFrac = Number.isFinite(overlayFracValue)
        ? Math.min(0.4, Math.max(0.1, overlayFracValue))
        : 0.3;
    const box = Math.max(1, Math.floor(size * overlayFrac));
    const left = Math.floor((size - box) / 2);
    const top = Math.floor((size - box) / 2);
    const composites = [{
        input: buildPlateSvg(size, left, top, box, box),
        left: 0,
        top: 0
    }];

    if (image) {
        const overlay = await sharp(Buffer.isBuffer(image) ? image : Buffer.from(image))
            .resize({ width: box, height: box, fit: "contain", withoutEnlargement: false })
            .png()
            .toBuffer();
        composites.push({ input: overlay, left, top });
    }

    if (label) {
        const fontSize = Math.max(12, Math.floor(box * 0.12));
        const labelSvg = buildLabelSvg(size, label, left + (box / 2), top + fontSize, fontSize);
        if (labelSvg) composites.push({ input: labelSvg, left: 0, top: 0 });
    }

    if (isSpecial) {
        composites.push({ input: buildSpecialBorderSvg(size, left, top, box), left: 0, top: 0 });
    }

    return await sharp(svg).composite(composites).png().toBuffer();
}
