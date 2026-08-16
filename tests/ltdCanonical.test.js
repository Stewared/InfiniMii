import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import miijs from "miijs";

import {
    LTD_CREATE_ID_POLICY_ID,
    LTD_HISTORICAL_SCHEMA_POLICY_ID,
    LTD_MAX_BYTES,
    LTD_PROFILE_POLICY_ID,
    assertNativeLtdShareMiiImportSafety,
    LtdCanonicalError,
    applyRawWiiPaletteSchema,
    assertGeneratedLtdShareMiiCompatibility,
    buildShareMiiV3CompatibleLtdDownload,
    canonicalizeMiiToLtd,
    getHistoricalSourceRecordSha256,
    getLtdSha256,
    getShareMiiImportSafePersonality,
    getStoredLtdBytes,
    isStoredLtdCanonicalizationCurrent,
    makeTrustedMiiBytesInput,
    makeTrustedMiiFileInput,
    mergeStoredMiiForCanonicalization,
    parseNativeLtdUpload
} from "../ltdCanonical.js";

const testDirectory = path.dirname(fileURLToPath(import.meta.url));

function portableMii(overrides = {}) {
    return {
        meta: {
            name: "Portable",
            creatorName: "Unit Test",
            type: "Default",
            ...overrides.meta
        },
        general: {
            gender: 0,
            height: 64,
            weight: 64,
            favoriteColor: 3,
            ...overrides.general
        },
        perms: {},
        face: { type: 0, color: 0, ...overrides.face },
        hair: { type: 1, color: 2, ...overrides.hair },
        eyes: {
            type: 2,
            color: 1,
            size: 4,
            squash: 3,
            rotation: 2,
            distanceApart: 2,
            yPosition: 10,
            ...overrides.eyes
        },
        eyebrows: {
            type: 2,
            color: 2,
            size: 4,
            squash: 3,
            rotation: 2,
            distanceApart: 2,
            yPosition: 10,
            ...overrides.eyebrows
        },
        nose: { type: 1, size: 4, yPosition: 10, ...overrides.nose },
        mouth: {
            type: 1,
            color: 0,
            size: 4,
            squash: 3,
            yPosition: 10,
            ...overrides.mouth
        },
        beard: {
            type: 0,
            color: 0,
            mustache: { type: 0, size: 4, yPosition: 10 },
            ...overrides.beard
        },
        glasses: { type: 0, color: 0, size: 4, yPosition: 10, ...overrides.glasses },
        mole: { on: false, size: 4, xPosition: 2, yPosition: 10, ...overrides.mole }
    };
}

function rawWiiPaletteQWvah(overrides = {}) {
    return {
        ...portableMii({
            hair: { type: 68, color: 0 },
            face: { type: 0, color: 4 },
            eyes: { type: 2, color: 0, rotation: 4, yPosition: 12 },
            eyebrows: { type: 6, color: 0, rotation: 6, yPosition: 7 },
            mouth: { type: 23, color: 0, yPosition: 13 },
            beard: {
                type: 0,
                color: 0,
                mustache: { type: 0, size: 4, yPosition: 10 }
            },
            glasses: { type: 0, color: 0, size: 4, yPosition: 10 }
        }),
        id: "QWvah",
        console: "Wii",
        official: true,
        published: true,
        private: false,
        officialSource: "Nintendo",
        meta: {
            ...portableMii().meta,
            console: "Wii"
        },
        ...overrides
    };
}

test("source-backed LTD conversion is deterministic and fully verified", async () => {
    const first = await canonicalizeMiiToLtd(portableMii(), { recordId: "portable-record" });
    const repeat = await canonicalizeMiiToLtd(portableMii(), { recordId: "portable-record" });

    assert.ok(first.bytes.length > 152);
    assert.deepEqual(repeat.bytes, first.bytes);
    assert.equal(first.storedFields.ltdSha256, getLtdSha256(first.bytes));
    assert.equal(first.storedFields.ltdVersion, 2);
    assert.equal(first.storedFields.ltdProvenance.profilePolicy, LTD_PROFILE_POLICY_ID);
    assert.equal(first.storedFields.ltdProvenance.createIdPolicy, LTD_CREATE_ID_POLICY_ID);
    assert.equal(first.storedFields.ltdProvenance.byteExactSourceClaimed, false);
    assert.equal(first.storedFields.ltdProvenance.appearanceProjectionExact, true);
    assert.equal(first.report.status, "converted");
    assert.equal(first.report.targetFormat, "ltd");
    assert.equal(first.report.verification.comparedBytes, 152);
    assert.equal(first.report.verification.appearanceProjectionExact, true);
    assert.deepEqual(first.report.verification.mismatchOffsets, []);
    assert.equal(first.parsed.version, 2);
    assert.equal(first.parsed.header.hasCanvas, false);
    assert.equal(first.parsed.header.hasUgcTexture, false);
    assert.equal(first.parsed.canvasTexturePayload.byteLength, 0);
    assert.equal(first.parsed.ugcTexturePayload.byteLength, 0);
    assert.equal(first.storedFields.facepaintUsage, "none");
    assert.equal(first.storedFields.facepaintCoverage.opaquePixels, 0);
    assert.equal(first.storedFields.facepaintCoverage.source, "ltd-ugc-bc1-alpha");
    assert.deepEqual(
        Object.fromEntries(Object.entries(first.parsed.personalityAndVoice)
            .filter(([, value]) => typeof value === "number")),
        {
            sociability: 4,
            audaciousness: 4,
            activeness: 4,
            commonsense: 4,
            gaiety: 4,
            voiceFormant: 28,
            voiceSpeed: 25,
            voiceIntonation: 0,
            voicePitch: 28,
            voiceTension: 5,
            voicePresetTypeHash: 0x232634c7,
            faceGenderHash: 0x0ddcbe76,
            pronounTypeHash: 0x3be5d8d4,
            clothStyleHash: 0x0ddcbe76,
            birthdayYear: 2008,
            birthdayDay: 1,
            birthdayDirectAge: -1,
            birthdayMonth: 1
        }
    );
    assert.deepEqual(first.parsed.loveGender.raw, [0, 1, 0]);

    const createId = Buffer.from(first.parsed.charInfo.uuidRaw, "hex");
    assert.equal(createId[6] >> 4, 4, "generated CreateId must be RFC 4122 version 4");
    assert.equal(createId[8] >> 6, 2, "generated CreateId must use the RFC 4122 variant");
});

test("generated LTD satisfies the strict ShareMii game-import contract", async () => {
    const canonical = await canonicalizeMiiToLtd(portableMii(), { recordId: "import-safe" });
    const parsed = assertGeneratedLtdShareMiiCompatibility(canonical.bytes);

    assert.equal(canonical.bytes.length, 434);
    assert.equal(parsed.personalityAndVoice.birthdayDirectAge, -1);
    assert.equal(parsed.personalityAndVoice.voicePresetTypeHash, 0x232634c7);
    assert.equal(parsed.personalityAndVoice.faceGenderHash, 0x0ddcbe76);
    assert.equal(parsed.personalityAndVoice.pronounTypeHash, 0x3be5d8d4);
    assert.equal(parsed.personalityAndVoice.clothStyleHash, 0x0ddcbe76);

    // The old profile was structurally valid, so ordinary LTD round-trip tests
    // could not catch it. ShareMii copies these zero hashes into enum arrays.
    const oldUnsafe = Buffer.from(canonical.bytes);
    const sections = canonical.parsed.serializedSections;
    oldUnsafe.fill(
        0,
        sections.personalityAndVoice.offset,
        sections.personalityAndVoice.offset + sections.personalityAndVoice.byteLength
    );
    oldUnsafe.fill(
        0,
        sections.sexuality.offset,
        sections.sexuality.offset + sections.sexuality.byteLength
    );
    assert.throws(
        () => assertGeneratedLtdShareMiiCompatibility(oldUnsafe),
        error => error instanceof LtdCanonicalError
            && error.code === "LTD_SHAREMII_IMPORT_UNSAFE"
            && /personalityAndVoice\.sociability/.test(error.message)
    );

    for (const [field, relativeOffset] of [
        ["voicePresetTypeHash", 40],
        ["faceGenderHash", 44],
        ["pronounTypeHash", 48],
        ["clothStyleHash", 52],
        ["birthdayDirectAge", 64]
    ]) {
        const unsafe = Buffer.from(canonical.bytes);
        unsafe.writeInt32LE(0, sections.personalityAndVoice.offset + relativeOffset);
        assert.throws(
            () => assertGeneratedLtdShareMiiCompatibility(unsafe),
            error => error instanceof LtdCanonicalError
                && error.code === "LTD_SHAREMII_IMPORT_UNSAFE"
                && error.message.includes(`personalityAndVoice.${field}`),
            field
        );
    }
});

test("the reported Maddie dashboard LTD is rejected by the compatibility and native-safety gates", () => {
    const fixturePath = path.join(
        testDirectory,
        "..",
        "erroringFiles",
        "2026-08-12T17-15-32-325Z_miiDashboard_Maddie_7bee6930.ltd"
    );
    if (!fs.existsSync(fixturePath)) return;
    assert.throws(
        () => assertGeneratedLtdShareMiiCompatibility(fs.readFileSync(fixturePath)),
        error => error instanceof LtdCanonicalError
            && error.code === "LTD_SHAREMII_IMPORT_UNSAFE"
            && /byteLength must be 434, got 436/.test(error.message)
    );
    assert.throws(
        () => assertNativeLtdShareMiiImportSafety(fs.readFileSync(fixturePath)),
        error => error instanceof LtdCanonicalError
            && error.code === "LTD_SHAREMII_IMPORT_UNSAFE"
            && /voicePresetTypeHash/.test(error.message)
    );
});

test("generated ShareMii gender enums follow source gender while voice uses the title default", async () => {
    const female = await canonicalizeMiiToLtd(
        portableMii({ general: { gender: 1 } }),
        { recordId: "import-safe-female" }
    );
    const profile = female.parsed.personalityAndVoice;
    assert.equal(female.parsed.charInfo.gender, 1);
    assert.equal(profile.voicePresetTypeHash, 0x232634c7);
    assert.equal(profile.faceGenderHash, 0x3b1f8b15);
    assert.equal(profile.pronounTypeHash, 0x25af6ee5);
    assert.equal(profile.clothStyleHash, 0x3b1f8b15);
    assert.doesNotThrow(() => assertGeneratedLtdShareMiiCompatibility(female.bytes));

    const male = getShareMiiImportSafePersonality(0);
    for (const unknown of [undefined, null, -1, 2, "1", NaN]) {
        const fallback = getShareMiiImportSafePersonality(unknown);
        assert.equal(fallback.voicePresetTypeHash, male.voicePresetTypeHash);
        assert.equal(fallback.faceGenderHash, male.faceGenderHash);
        assert.equal(fallback.pronounTypeHash, male.pronounTypeHash);
        assert.equal(fallback.clothStyleHash, male.clothStyleHash);
    }
});

test("old generated zero-profile LTD is regenerated and rejected as an unsafe native upload", async () => {
    const canonical = await canonicalizeMiiToLtd(portableMii(), { recordId: "profile-upgrade" });
    const oldUnsafe = Buffer.from(canonical.bytes);
    const sections = canonical.parsed.serializedSections;
    oldUnsafe.fill(
        0,
        sections.personalityAndVoice.offset,
        sections.personalityAndVoice.offset + sections.personalityAndVoice.byteLength
    );
    oldUnsafe.fill(
        0,
        sections.sexuality.offset,
        sections.sexuality.offset + sections.sexuality.byteLength
    );
    const oldGenerated = {
        ...portableMii(),
        id: "profile-upgrade",
        ltdData: oldUnsafe,
        ltdSha256: getLtdSha256(oldUnsafe),
        ltdProvenance: {
            ...canonical.storedFields.ltdProvenance,
            profilePolicy: "render-only-zero-v3/1"
        }
    };

    assert.equal(isStoredLtdCanonicalizationCurrent(oldGenerated), false);
    assert.equal(isStoredLtdCanonicalizationCurrent({
        ...oldGenerated,
        ltdProvenance: canonical.storedFields.ltdProvenance
    }), false, "an unsafe payload cannot bypass regeneration by claiming the current policy");
    const upgraded = await canonicalizeMiiToLtd(oldGenerated, { recordId: "profile-upgrade" });
    assert.notDeepEqual(upgraded.bytes, oldUnsafe);
    assert.equal(upgraded.replacesStoredLtd.reason, "sharemii-import-safety-profile-upgrade");
    assert.equal(upgraded.replacesStoredLtd.policy, LTD_PROFILE_POLICY_ID);
    assert.doesNotThrow(() => assertGeneratedLtdShareMiiCompatibility(upgraded.bytes));

    assert.throws(
        () => assertNativeLtdShareMiiImportSafety(oldUnsafe),
        error => error instanceof LtdCanonicalError
            && error.code === "LTD_SHAREMII_IMPORT_UNSAFE"
            && /voicePresetTypeHash/.test(error.message)
    );
    await assert.rejects(
        parseNativeLtdUpload(makeTrustedMiiBytesInput(oldUnsafe, { declaredLtd: true })),
        error => error instanceof LtdCanonicalError
            && error.code === "LTD_SHAREMII_IMPORT_UNSAFE"
    );
});

test("the prior safe v3 generated envelope upgrades to the ShareMii 3.0-compatible v2 envelope", async () => {
    const canonical = await canonicalizeMiiToLtd(portableMii(), { recordId: "v3-envelope-upgrade" });
    const priorV3 = Buffer.alloc(436, 0);
    priorV3[0] = 3;
    canonical.bytes.copy(priorV3, 4, 5, 425);
    canonical.bytes.copy(priorV3, 424, 425, 428);
    priorV3.fill(0xa3, 428, 432);
    priorV3.fill(0xa4, 432, 436);

    const priorParsed = (await import("miijs")).default.parseLtdContainer(priorV3);
    assert.equal(priorParsed.version, 3);
    assert.equal(priorParsed.personalityAndVoice.sociability, 4);

    const stored = {
        ...portableMii(),
        ...canonical.storedFields,
        ltdData: priorV3,
        ltdSha256: getLtdSha256(priorV3),
        ltdVersion: 3,
        ltdProvenance: {
            ...canonical.storedFields.ltdProvenance,
            profilePolicy: "sharemii-import-safe-v3/3"
        }
    };
    assert.equal(isStoredLtdCanonicalizationCurrent(stored), false);
    const upgraded = await canonicalizeMiiToLtd(stored, { recordId: "v3-envelope-upgrade" });
    assert.equal(upgraded.bytes.length, 434);
    assert.equal(upgraded.parsed.version, 2);
    assert.equal(upgraded.storedFields.ltdProvenance.profilePolicy, LTD_PROFILE_POLICY_ID);
    assert.equal(upgraded.replacesStoredLtd.reason, "sharemii-import-safety-profile-upgrade");
});

test("native v3 facepaint exports as a payload-exact ShareMii 3.0-compatible v2 envelope", async () => {
    const fixturePath = path.resolve(testDirectory, "..", "ltd-renderer", "dcmp", "mii0.ltd");
    if (!fs.existsSync(fixturePath)) return;
    const native = fs.readFileSync(fixturePath);
    const source = miijs.parseLtdContainer(native);
    const compatible = buildShareMiiV3CompatibleLtdDownload(native);
    const parsed = miijs.parseLtdContainer(compatible);

    assert.equal(native.length, 10307);
    assert.equal(compatible.length, 10305);
    assert.equal(getLtdSha256(compatible), "d1d0bd6d88303f2bdf33905c9a4bc3206ecc8c7af871acdc4b6328269300b81f");
    assert.equal(parsed.version, 2);
    assert.deepEqual([...compatible.subarray(0, 5)], [2, 1, 1, 0, 0]);
    assert.deepEqual(parsed.personalityAndVoice, source.personalityAndVoice);
    assert.equal(parsed.displayName, source.displayName);
    assert.equal(parsed.pronunciation, source.pronunciation);
    assert.deepEqual(parsed.loveGender.raw, source.loveGender.raw.slice(0, 3));
    assert.deepEqual(
        Buffer.from(parsed.canvasTexturePayload.data),
        Buffer.from(source.canvasTexturePayload.data)
    );
    assert.deepEqual(
        Buffer.from(parsed.ugcTexturePayload.data),
        Buffer.from(source.ugcTexturePayload.data)
    );
    assert.deepEqual(
        compatible.subarray(5, 161),
        native.subarray(4, 160),
        "ShareMii 3.0's hard-coded [5:161] slice must receive the exact native Mii block"
    );
    const decoded = await miijs.Mii.create(compatible);
    assert.deepEqual(Buffer.from(await decoded.encode(miijs.MiiFormats.LTD)), compatible);

    const v2FixturePath = path.resolve(testDirectory, "..", "ltd-renderer", "dcmp", "mii1.ltd");
    if (fs.existsSync(v2FixturePath)) {
        const nativeV2 = fs.readFileSync(v2FixturePath);
        assert.deepEqual(buildShareMiiV3CompatibleLtdDownload(nativeV2), nativeV2);
    }
});

test("native v3 compatibility export rejects unrepresentable state and old-importer sentinel collisions", () => {
    const fixturePath = path.resolve(testDirectory, "..", "ltd-renderer", "dcmp", "mii0.ltd");
    if (!fs.existsSync(fixturePath)) return;
    const native = fs.readFileSync(fixturePath);
    const parsed = miijs.parseLtdContainer(native);

    const fourthSexualityByte = Buffer.from(native);
    fourthSexualityByte[parsed.serializedSections.sexuality.offset + 3] = 1;
    assert.throws(
        () => buildShareMiiV3CompatibleLtdDownload(fourthSexualityByte),
        error => error instanceof LtdCanonicalError
            && error.code === "LTD_SHAREMII_IMPORT_UNSAFE"
            && /v3-only sexuality or texture state/.test(error.message)
    );

    const oneTextureFlag = Buffer.from(native);
    oneTextureFlag[2] = 0;
    assert.throws(
        () => buildShareMiiV3CompatibleLtdDownload(oneTextureFlag),
        error => error instanceof LtdCanonicalError
            && error.code === "LTD_SHAREMII_IMPORT_UNSAFE"
            && /UGC texture payload is present while its header flag is false/.test(error.message)
    );

    const collidingMetadata = Buffer.from(native);
    collidingMetadata.fill(
        0xa3,
        parsed.serializedSections.pronunciation.offset + 32,
        parsed.serializedSections.pronunciation.offset + 35
    );
    assert.throws(
        () => buildShareMiiV3CompatibleLtdDownload(collidingMetadata),
        error => error instanceof LtdCanonicalError
            && error.code === "LTD_SHAREMII_IMPORT_UNSAFE"
            && /texture sentinel collision/.test(error.message)
    );
});

test("record identity changes container bytes without changing the appearance hash", async () => {
    const first = await canonicalizeMiiToLtd(portableMii(), { recordId: "record-a" });
    const second = await canonicalizeMiiToLtd(portableMii(), { recordId: "record-b" });
    const changedAppearance = await canonicalizeMiiToLtd(
        portableMii({ hair: { type: 7 } }),
        { recordId: "record-a" }
    );

    assert.notDeepEqual(second.bytes, first.bytes);
    assert.notEqual(second.storedFields.ltdSha256, first.storedFields.ltdSha256);
    assert.equal(second.storedFields.ltdAppearanceHash, first.storedFields.ltdAppearanceHash);
    assert.notEqual(changedAppearance.storedFields.ltdAppearanceHash, first.storedFields.ltdAppearanceHash);
});

test("the raw-Wii palette table is source-backed and is not inferred for ordinary records", async () => {
    const raw = rawWiiPaletteQWvah();
    const normalized = applyRawWiiPaletteSchema(raw, { recordId: "fixture" });
    const ordinary = await canonicalizeMiiToLtd(
        { ...raw, id: "ordinary-record" },
        { recordId: "ordinary-record" }
    );
    const ordinaryCharInfo = ordinary.fields.ltd.charInfo;

    assert.equal(normalized.fields.hair.color, 8);
    assert.equal(normalized.fields.eyebrows.color, 8);
    assert.equal(normalized.fields.beard.color, 8);
    assert.equal(normalized.fields.eyes.color, 8);
    assert.equal(normalized.fields.mouth.color, 19);
    assert.equal(normalized.fields.glasses.color, 8);
    assert.equal(normalized.transformations.length, 6);
    assert.ok(normalized.transformations.every(item => item.sourceBacked === true));
    assert.equal(ordinaryCharInfo.hairColorPrimary, 0);
    assert.equal(ordinaryCharInfo.eyeColor, 0);
    assert.equal(ordinaryCharInfo.mouthColor, 0);
    assert.equal(LTD_HISTORICAL_SCHEMA_POLICY_ID, "infinimii-explicit-historical-schema-v1");
});

test("the exact 18-key source fingerprint rejects a replaced QWvah record", async () => {
    const raw = rawWiiPaletteQWvah();
    const reordered = Object.fromEntries(Object.entries(raw).reverse());
    assert.equal(getHistoricalSourceRecordSha256(reordered), getHistoricalSourceRecordSha256(raw));
    assert.equal(
        getHistoricalSourceRecordSha256({ ...raw, uploader: "excluded-audit-field" }),
        getHistoricalSourceRecordSha256(raw)
    );
    assert.notEqual(
        getHistoricalSourceRecordSha256({ ...raw, hair: { ...raw.hair, type: 69 } }),
        getHistoricalSourceRecordSha256(raw)
    );

    const stale = await canonicalizeMiiToLtd(
        { ...raw, id: "pre-policy-record" },
        { recordId: "pre-policy-record" }
    );
    await assert.rejects(
        canonicalizeMiiToLtd({
            ...raw,
            hair: { ...raw.hair, type: 69 },
            ltdData: stale.bytes,
            ltdSha256: stale.storedFields.ltdSha256,
            ltdProvenance: stale.storedFields.ltdProvenance
        }, { recordId: "QWvah" }),
        error => error instanceof LtdCanonicalError
            && error.code === "LTD_HISTORICAL_SOURCE_MISMATCH"
    );
});

test("a generated LTD is accepted as a byte-exact native upload", async () => {
    const canonical = await canonicalizeMiiToLtd(portableMii(), { recordId: "native-round-trip" });
    const native = await parseNativeLtdUpload(canonical.bytes);

    assert.ok(native);
    assert.deepEqual(native.bytes, canonical.bytes);
    assert.deepEqual(native.fields.ltdData, canonical.bytes);
    assert.equal(native.fields.ltdSha256, canonical.storedFields.ltdSha256);
    assert.equal(native.fields.ltdAppearanceHash, canonical.storedFields.ltdAppearanceHash);
    assert.equal(native.fields.ltdProvenance.kind, "native-upload");
    assert.equal(native.fields.ltdProvenance.byteExact, true);
    assert.equal(native.fields.console, "LTD");
    assert.equal(native.fields.meta.console, "LTD");
    assert.equal(native.fields.ltdCharInfo.uuid, undefined);
    assert.equal(native.fields.ltdCharInfo.nameBytes, undefined);

    for (const encoded of [canonical.bytes.toString("base64"), canonical.bytes.toString("hex")]) {
        const pasted = await parseNativeLtdUpload(encoded);
        assert.deepEqual(pasted.bytes, canonical.bytes);
        assert.equal(pasted.fields.ltdProvenance.byteExact, true);
    }
});

test("native upload parsing reads only explicitly trusted paths", async t => {
    const tempDirectory = await fs.promises.mkdtemp(path.join(os.tmpdir(), "infinimii-ltd-test-"));
    t.after(() => fs.promises.rm(tempDirectory, { recursive: true, force: true }));
    const filePath = path.join(tempDirectory, "portable.ltd");
    const canonical = await canonicalizeMiiToLtd(portableMii(), { recordId: "trusted-file" });
    await fs.promises.writeFile(filePath, canonical.bytes);

    assert.equal(await parseNativeLtdUpload(filePath), null);
    assert.equal(await parseNativeLtdUpload({
        kind: "trusted-mii-file",
        path: filePath,
        declaredLtd: true
    }), null, "a JSON-forgeable object shape must not authorize filesystem access");
    const parsed = await parseNativeLtdUpload(makeTrustedMiiFileInput(filePath, {
        declaredLtd: true
    }));
    assert.deepEqual(parsed.bytes, canonical.bytes);
});

test("declared malformed and oversized LTD data fails closed", async () => {
    await assert.rejects(
        parseNativeLtdUpload("data:application/x-ltd;base64,AA=="),
        error => error instanceof LtdCanonicalError && error.code === "INVALID_LTD"
    );
    assert.equal(await parseNativeLtdUpload(Buffer.from([0])), null);
    assert.equal(
        await parseNativeLtdUpload(`data:application/octet-stream;base64,${Buffer.alloc(74).toString("base64")}`),
        null,
        "generic octet-stream data must remain eligible for a non-LTD decoder"
    );
    await assert.rejects(
        parseNativeLtdUpload(Buffer.alloc(LTD_MAX_BYTES + 1)),
        error => error instanceof LtdCanonicalError && error.code === "LTD_TOO_LARGE"
    );
});

test("stored LTD bytes are reused exactly and a mismatched stored hash is rejected", async () => {
    const canonical = await canonicalizeMiiToLtd(portableMii(), { recordId: "stored" });
    const stored = {
        ...portableMii(),
        ltdData: { type: "Buffer", data: [...canonical.bytes] },
        ltdSha256: canonical.storedFields.ltdSha256,
        ltdProvenance: canonical.storedFields.ltdProvenance
    };

    assert.deepEqual(getStoredLtdBytes(stored), canonical.bytes);
    const reused = await canonicalizeMiiToLtd(stored, { recordId: "stored" });
    assert.deepEqual(reused.bytes, canonical.bytes);
    await assert.rejects(
        canonicalizeMiiToLtd({ ...stored, ltdSha256: "0".repeat(64) }, { recordId: "stored" }),
        error => error instanceof LtdCanonicalError && error.code === "LTD_HASH_MISMATCH"
    );
});

test("lazy canonicalization prefers the complete stored record over a card projection", async () => {
    const full = portableMii({ hair: { type: 7 }, face: { type: 2 } });
    const partial = { ...portableMii(), id: "lazy-record" };
    const merged = mergeStoredMiiForCanonicalization(partial, { ...full, id: "lazy-record" });
    const [fromMerged, fromFull, fromPartial] = await Promise.all([
        canonicalizeMiiToLtd(merged, { recordId: "lazy-record" }),
        canonicalizeMiiToLtd(full, { recordId: "lazy-record" }),
        canonicalizeMiiToLtd(partial, { recordId: "lazy-record" })
    ]);
    assert.deepEqual(fromMerged.bytes, fromFull.bytes);
    assert.notEqual(fromMerged.storedFields.ltdAppearanceHash, fromPartial.storedFields.ltdAppearanceHash);
});
