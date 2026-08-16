import assert from "node:assert/strict";
import test from "node:test";

import miijs from "miijs";
import sharp from "sharp";

import { renderServerQrPng } from "../serverQrRenderer.js";

test("Canvas-free server QR preserves arbitrary payload bytes", async () => {
    const payload = Buffer.from(Array.from({ length: 112 }, (_, index) => (index * 197) & 0xff));
    const png = await renderServerQrPng(payload, { size: 512 });
    const metadata = await sharp(png).metadata();
    assert.equal(metadata.format, "png");
    assert.equal(metadata.width, 512);
    assert.equal(metadata.height, 512);
    assert.deepEqual(await miijs.scanQR(png), payload);
});

test("Canvas-free server QR remains readable with an image, label, and special border", async () => {
    const payload = Buffer.from(Array.from({ length: 96 }, (_, index) => (255 - (index * 31)) & 0xff));
    const overlay = await sharp({
        create: {
            width: 96,
            height: 96,
            channels: 4,
            background: { r: 52, g: 118, b: 210, alpha: 1 }
        }
    }).png().toBuffer();
    const png = await renderServerQrPng(payload, {
        size: 512,
        image: overlay,
        label: "Canvas-free Mii",
        special: true
    });
    assert.deepEqual(await miijs.scanQR(png), payload);
});

test("label-only fallback keeps the QR unobscured when portrait rendering failed", async () => {
    const payload = Buffer.from(Array.from({ length: 172 }, (_, index) => (index * 151) & 0xff));
    const clean = await renderServerQrPng(payload, { size: 512 });
    const fallback = await renderServerQrPng(payload, {
        size: 512,
        label: "Portrait unavailable",
        special: true
    });
    assert.deepEqual(fallback, clean);
    assert.deepEqual(await miijs.scanQR(fallback), payload);
});

test("portrait QR sanitizes XML-illegal control characters in labels", async () => {
    const payload = Buffer.from(Array.from({ length: 112 }, (_, index) => (index * 83) & 0xff));
    const overlay = await sharp({
        create: {
            width: 96,
            height: 96,
            channels: 4,
            background: { r: 202, g: 91, b: 65, alpha: 1 }
        }
    }).png().toBuffer();
    const png = await renderServerQrPng(payload, {
        size: 512,
        image: overlay,
        label: "Bad\u0000Mii\u0001Name"
    });
    assert.deepEqual(await miijs.scanQR(png), payload);
});
