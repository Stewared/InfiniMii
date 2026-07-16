import assert from "node:assert/strict";
import test from "node:test";

import {
    buildMiitopiaQrMii,
    canReuseMiiInstanceForExport,
    getDefaultQrConsoleForMii,
    hasDecodedTomodachiLifeData,
    isMiitopiaQrConsole,
    normalizeMiiFieldsForExport,
    normalizeQrConsole
} from "../miiQrUtils.js";

test("normalizes supported QR console aliases", () => {
    assert.equal(normalizeQrConsole("Tomodachi Life"), "TOMODACHI");
    assert.equal(normalizeQrConsole("wii_u"), "WIIU");
    assert.equal(normalizeQrConsole("3ds"), "3DS");
    assert.equal(isMiitopiaQrConsole("mte"), true);
    assert.equal(normalizeQrConsole("Miitopia"), "3DS");
});

test("normalizes export fields without mutating decoded Mii data", () => {
    const fields = { meta: { name: "Example" }, general: { favoriteColor: 2 } };
    const normalized = normalizeMiiFieldsForExport(fields);

    assert.equal(normalized.meta.type, "Default");
    assert.deepEqual(normalized.perms, {});
    assert.equal(fields.meta.type, undefined);
    assert.equal(fields.perms, undefined);
    assert.equal(canReuseMiiInstanceForExport(fields), false);
    assert.equal(canReuseMiiInstanceForExport({
        meta: { type: "Default" },
        perms: {}
    }), true);
    assert.equal(canReuseMiiInstanceForExport({
        meta: { type: "Default" },
        perms: {}
    }, { special: true }), false);
});

test("detects Tomodachi data and preserves disabled Miitopia behavior", () => {
    assert.equal(hasDecodedTomodachiLifeData({ tl: {} }), false);
    assert.equal(hasDecodedTomodachiLifeData({ tl: { catchphrase: "Hello" } }), true);
    assert.equal(getDefaultQrConsoleForMii({ tl: { catchphrase: "Hello" } }), "TOMODACHI");

    const source = { mt: {}, tl: { catchphrase: "Hello" } };
    const converted = buildMiitopiaQrMii(source);
    assert.equal(converted.mt.warCry, "Hello");
    assert.equal(source.mt.warCry, undefined);
});
