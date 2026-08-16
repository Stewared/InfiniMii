import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { makeTrustedMiiBytesInput, parseNativeLtdUpload } from "../ltdCanonical.js";

import {
    LTD_ONLY_DOWNLOAD_MESSAGE,
    LTD_ONLY_EXPORT_FORMATS,
    LTD_EXCLUSIVE_FEATURE_EXEMPT_MII_IDS,
    LTD_WORKSPACE_UNAVAILABLE_CODE,
    LTD_WORKSPACE_UNAVAILABLE_MESSAGES,
    LtdOnlyDownloadError,
    LtdWorkspaceUnavailableError,
    assertLtdWorkspaceAccessAvailable,
    assertMiiDownloadFormat,
    getAllowedExportFormats,
    getMiiDownloadPolicy,
    getLtdWorkspaceUnavailableMessage,
    isLtdEraMii,
    isLtdExclusiveFeatureExemptMii,
    isLtdExclusiveFeatureLockedMii,
    isLtdWorkspaceAccessUnavailable,
    normalizeMiiDownloadEra,
    sendLtdOnlyDownloadError
} from "../ltdOnlyDownloadPolicy.js";

const ALL_FORMATS = Object.freeze([
    Object.freeze({ value: "ltd", label: "Living the Dream ShareMii (.ltd)" }),
    Object.freeze({ value: "rcd", label: "Wii RCD (.rcd)" }),
    Object.freeze({ value: "qr", label: "QR Code (PNG)" }),
    Object.freeze({ value: "charinfo", label: "Switch CHARINFO (.charinfo)" })
]);

function nativeLtdFixture() {
    const repositoryRoot = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
    const candidates = [
        path.join(repositoryRoot, "ltd-renderer", "dcmp", "mii2.ltd"),
        path.join(repositoryRoot, "ltd-renderer", "dcmp", "mii0.ltd")
    ];
    const externalFixture = candidates.find(candidate => fs.existsSync(candidate));
    return externalFixture ? fs.readFileSync(externalFixture) : null;
}

test("the LTD-only menu remains deeply immutable", () => {
    assert.deepEqual(LTD_ONLY_EXPORT_FORMATS, [
        { value: "ltd", label: "Living the Dream ShareMii (.ltd)" }
    ]);
    assert.equal(Object.isFrozen(LTD_ONLY_EXPORT_FORMATS), true);
    assert.equal(Object.isFrozen(LTD_ONLY_EXPORT_FORMATS[0]), true);
});

test("era normalization is exact and case-insensitive", () => {
    assert.equal(normalizeMiiDownloadEra(" ltd "), "LTD");
    assert.equal(normalizeMiiDownloadEra(null), "");
    assert.equal(isLtdEraMii({ era: "ltd" }), true);
    assert.equal(isLtdEraMii({ era: "CHARINFO" }), false);
});

test("only LTD-era records receive the LTD-only menu", () => {
    assert.deepEqual(getAllowedExportFormats({ era: "LTD" }, ALL_FORMATS), [ALL_FORMATS[0]]);

    for (const era of ["RCD", "TL", "CFCD", "FFCD", "CHARINFO"]) {
        assert.equal(getAllowedExportFormats({ era }, ALL_FORMATS), ALL_FORMATS, era);
        assert.equal(getMiiDownloadPolicy({ era }, { storedRecord: true }).ltdOnly, false, era);
    }
});

test("missing or unknown non-native eras are not mistaken for LTD", () => {
    for (const mii of [{}, { era: "" }, { era: "future-format" }]) {
        const policy = getMiiDownloadPolicy(mii, { storedRecord: true });
        assert.equal(policy.ltdOnly, false);
        assert.equal(policy.reason, "non-ltd-era");
        assert.equal(getAllowedExportFormats(mii, ALL_FORMATS, { storedRecord: true }), ALL_FORMATS);
    }
});

test("stale generated LTD rows use authoritative classic-era evidence", () => {
    const twoCnagShape = {
        id: "2CNAG",
        era: "LTD",
        console: "Mii Studio",
        tl: { island: { name: "Example" } },
        ltdProvenance: {
            kind: "canonical-regenerated-charinfo",
            sourceKind: "normalized-site-fields",
            sourceFormat: "charinfo"
        }
    };
    const policy = getMiiDownloadPolicy(twoCnagShape, { storedRecord: true });
    assert.equal(isLtdEraMii(twoCnagShape, { storedRecord: true }), false);
    assert.equal(policy.era, "CFCD");
    assert.equal(policy.ltdOnly, false);
    assert.equal(policy.reason, "non-ltd-era");
    assert.equal(getAllowedExportFormats(twoCnagShape, ALL_FORMATS, { storedRecord: true }), ALL_FORMATS);

    const officialWii = {
        era: "LTD",
        officialCategories: ["Wii/Wii Sports"],
        ltdProvenance: { kind: "canonical-regenerated-charinfo", sourceFormat: "charinfo" }
    };
    assert.equal(getMiiDownloadPolicy(officialWii, { storedRecord: true }).era, "RCD");
    assert.equal(getMiiDownloadPolicy(officialWii, { storedRecord: true }).ltdOnly, false);
});

test("the Average Mii is exempt from LTD-exclusive capabilities only", () => {
    assert.deepEqual(LTD_EXCLUSIVE_FEATURE_EXEMPT_MII_IDS, ["average"]);
    assert.equal(isLtdExclusiveFeatureExemptMii({ id: "average", era: "LTD" }), true);
    assert.equal(isLtdEraMii({ id: "average", era: "LTD" }), true);
    assert.equal(isLtdExclusiveFeatureLockedMii({ id: "average", era: "LTD" }), false);

    const policy = getMiiDownloadPolicy({ id: "average", era: "LTD" }, { storedRecord: true });
    assert.equal(policy.era, "LTD");
    assert.equal(policy.ltdOnly, false);
    assert.equal(policy.ltdExclusiveExempt, true);
    assert.equal(policy.reason, "ltd-exclusive-feature-exempt");
    assert.equal(getAllowedExportFormats({ id: "average", era: "LTD" }, ALL_FORMATS, { storedRecord: true }), ALL_FORMATS);
    assert.equal(assertMiiDownloadFormat({ id: "average", era: "LTD" }, "rcd", { storedRecord: true }), "rcd");

    assert.equal(isLtdExclusiveFeatureExemptMii({ id: "not-average", meta: { name: "John Doe" }, era: "LTD" }), false);
    assert.equal(isLtdExclusiveFeatureLockedMii({ id: "not-average", meta: { name: "John Doe" }, era: "LTD" }), true);
    assert.equal(getMiiDownloadPolicy({ id: "not-average", meta: { name: "John Doe" }, era: "LTD" }).ltdOnly, true);

    const storedAverage = {
        id: "average",
        era: "LTD",
        console: "Mii Studio",
        meta: { name: "John Doe", creatorName: "InfiniMii" },
        ltdProvenance: {
            kind: "canonical-regenerated-charinfo",
            sourceKind: "normalized-site-fields",
            sourceFormat: "charinfo"
        }
    };
    const storedAveragePolicy = getMiiDownloadPolicy(storedAverage, { storedRecord: true });
    assert.equal(storedAveragePolicy.era, "CHARINFO");
    assert.equal(storedAveragePolicy.ltdOnly, false);
    assert.equal(storedAveragePolicy.ltdExclusiveExempt, true);
    assert.equal(isLtdExclusiveFeatureLockedMii(storedAverage, { storedRecord: true }), false);
    assert.equal(getAllowedExportFormats(storedAverage, ALL_FORMATS, { storedRecord: true }), ALL_FORMATS);
    assert.equal(assertMiiDownloadFormat(storedAverage, "ltd", { storedRecord: true }), "ltd");
    assert.equal(assertMiiDownloadFormat(storedAverage, "charinfo", { storedRecord: true }), "charinfo");
});

test("explicit LTD Miis receive stable feature-specific workspace errors", () => {
    assert.equal(isLtdWorkspaceAccessUnavailable({ era: "LTD" }), true);
    assert.throws(
        () => assertLtdWorkspaceAccessAvailable({ era: "LTD" }, "dashboard"),
        error => error instanceof LtdWorkspaceUnavailableError
            && error.code === LTD_WORKSPACE_UNAVAILABLE_CODE
            && error.status === 422
            && error.feature === "dashboard"
            && error.message === LTD_WORKSPACE_UNAVAILABLE_MESSAGES.dashboard
    );
    assert.throws(
        () => assertLtdWorkspaceAccessAvailable({ era: "LTD" }, "kidomatic"),
        error => error instanceof LtdWorkspaceUnavailableError
            && error.feature === "kidomatic"
            && error.message === LTD_WORKSPACE_UNAVAILABLE_MESSAGES.kidomatic
    );
});

test("authenticated native LTD Miis are unavailable without a stored era", { skip: !nativeLtdFixture() }, async () => {
    const native = await parseNativeLtdUpload(makeTrustedMiiBytesInput(nativeLtdFixture(), { declaredLtd: true }));
    assert.equal(Object.hasOwn(native.fields, "era"), false);
    assert.equal(isLtdWorkspaceAccessUnavailable(native.fields), true);
    assert.throws(
        () => assertLtdWorkspaceAccessAvailable(native.fields, "dashboard"),
        error => error instanceof LtdWorkspaceUnavailableError
            && error.code === LTD_WORKSPACE_UNAVAILABLE_CODE
            && error.status === 422
    );
});

test("stripped decoded LTD projections remain unavailable to Dashboard and Kidomatic", () => {
    const projection = {
        console: "LTD",
        meta: { name: "Decoded LTD", console: "ltd" },
        general: { height: 64, weight: 64 }
    };

    assert.equal(isLtdEraMii(projection), false);
    assert.equal(isLtdWorkspaceAccessUnavailable(projection), true);
    assert.throws(
        () => assertLtdWorkspaceAccessAvailable(projection, "MiiDashboard"),
        error => error instanceof LtdWorkspaceUnavailableError
            && error.feature === "dashboard"
            && error.message === getLtdWorkspaceUnavailableMessage("dashboard")
    );
    assert.throws(
        () => assertLtdWorkspaceAccessAvailable({ meta: { console: "LTD" } }, "kidomatic"),
        error => error instanceof LtdWorkspaceUnavailableError
            && error.message === getLtdWorkspaceUnavailableMessage("kidomatic")
    );
});

test("workspace policy preserves classified classic eras and stale-LTD correction", () => {
    for (const era of ["RCD", "TL", "CFCD", "FFCD", "CHARINFO"]) {
        const classified = { era, console: "LTD", meta: { console: "LTD" } };
        assert.equal(isLtdWorkspaceAccessUnavailable(classified), false, era);
        assert.equal(assertLtdWorkspaceAccessAvailable(classified, "dashboard"), true, era);
    }

    const staleGeneratedLtd = {
        era: "LTD",
        console: "Mii Studio",
        meta: { console: "Mii Studio" },
        ltdProvenance: {
            kind: "canonical-regenerated-charinfo",
            sourceFormat: "charinfo"
        }
    };
    assert.equal(getMiiDownloadPolicy(staleGeneratedLtd, { storedRecord: true }).era, "CHARINFO");
    assert.equal(isLtdWorkspaceAccessUnavailable(staleGeneratedLtd, { storedRecord: true }), false);
});

test("the Average Mii remains exempt from temporary workspace restrictions", () => {
    for (const average of [
        { id: "average", era: "LTD" },
        { id: "average", console: "LTD", meta: { console: "LTD" } },
        { id: "average", fields: { console: "LTD", meta: { console: "LTD" } } }
    ]) {
        assert.equal(isLtdWorkspaceAccessUnavailable(average), false);
        assert.equal(assertLtdWorkspaceAccessAvailable(average, "kidomatic"), true);
    }
});

test("a forged native-LTD claim does not grant source-era authority", () => {
    const forged = {
        era: "RCD",
        ltdProvenance: {
            kind: "native-upload",
            codec: "forged",
            sourceFormat: "ltd",
            byteExact: true
        }
    };
    assert.equal(isLtdEraMii(forged), false);
    assert.equal(getMiiDownloadPolicy(forged, { storedRecord: true }).ltdOnly, false);
});

test("every explicit classified non-LTD era outranks valid native LTD evidence", { skip: !nativeLtdFixture() }, async () => {
    const native = await parseNativeLtdUpload(makeTrustedMiiBytesInput(nativeLtdFixture(), { declaredLtd: true }));
    for (const era of ["RCD", "TL", "CFCD", "FFCD", "CHARINFO"]) {
        const classified = { ...native.fields, era };
        assert.equal(isLtdEraMii(classified), false, era);
        assert.equal(getMiiDownloadPolicy(classified, { storedRecord: true }).ltdOnly, false, era);
        assert.equal(getAllowedExportFormats(classified, ALL_FORMATS, { storedRecord: true }), ALL_FORMATS, era);
    }
});

test("a genuine native LTD remains LTD-exclusive and format-locked", { skip: !nativeLtdFixture() }, async () => {
    const native = await parseNativeLtdUpload(makeTrustedMiiBytesInput(nativeLtdFixture(), { declaredLtd: true }));
    const storedNative = { id: "native-ltd", ...native.fields, era: "LTD" };
    const policy = getMiiDownloadPolicy(storedNative, { storedRecord: true });

    assert.equal(policy.era, "LTD");
    assert.equal(policy.ltdOnly, true);
    assert.equal(policy.ltdExclusiveExempt, false);
    assert.equal(isLtdExclusiveFeatureLockedMii(storedNative, { storedRecord: true }), true);
    assert.deepEqual(getAllowedExportFormats(storedNative, ALL_FORMATS, { storedRecord: true }), [ALL_FORMATS[0]]);
    assert.throws(
        () => assertMiiDownloadFormat(storedNative, "charinfo", { storedRecord: true }),
        error => error instanceof LtdOnlyDownloadError
    );
});

test("format authorization limits only LTD-era records", () => {
    assert.equal(assertMiiDownloadFormat({ era: "RCD" }, "qr", { storedRecord: true }), "qr");
    assert.equal(assertMiiDownloadFormat({ era: "CHARINFO" }, ".CFCD", { storedRecord: true }), "cfcd");
    assert.equal(assertMiiDownloadFormat({ era: "LTD" }, ".LTD", { storedRecord: true }), "ltd");

    assert.throws(
        () => assertMiiDownloadFormat({ era: "LTD" }, "rcd", { storedRecord: true }),
        error => error instanceof LtdOnlyDownloadError
            && error.code === "LTD_ONLY_DOWNLOAD"
            && error.status === 400
            && error.message === LTD_ONLY_DOWNLOAD_MESSAGE
    );
});

function responseDouble() {
    return {
        statusCode: null,
        headers: {},
        contentType: null,
        body: null,
        setHeader(name, value) {
            this.headers[name] = value;
        },
        status(value) {
            this.statusCode = value;
            return this;
        },
        type(value) {
            this.contentType = value;
            return this;
        },
        json(value) {
            this.body = value;
            return this;
        },
        send(value) {
            this.body = value;
            return this;
        }
    };
}

test("LTD-only route responses are non-cacheable and content-negotiated", () => {
    const jsonResponse = responseDouble();
    const returned = sendLtdOnlyDownloadError(
        { accepts: type => type === "json" },
        jsonResponse,
        new LtdOnlyDownloadError()
    );
    assert.equal(returned, jsonResponse);
    assert.equal(jsonResponse.statusCode, 410);
    assert.equal(jsonResponse.headers["Cache-Control"], "no-store");
    assert.deepEqual(jsonResponse.body, {
        error: LTD_ONLY_DOWNLOAD_MESSAGE,
        code: "LTD_ONLY_DOWNLOAD"
    });

    const textResponse = responseDouble();
    sendLtdOnlyDownloadError({ accepts: () => false }, textResponse);
    assert.equal(textResponse.statusCode, 410);
    assert.equal(textResponse.contentType, "text/plain");
    assert.equal(textResponse.body, LTD_ONLY_DOWNLOAD_MESSAGE);
});
