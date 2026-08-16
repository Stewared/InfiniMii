import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import miijs from "miijs";

import {
    MII_ERA_ORDER,
    MII_ERA_VALUES,
    assignMiiEra,
    classifyMiiEra,
    getMiiEraSemanticSnapshot,
    getMiiEraRuntimeResolution,
    getMiiEraSourceExpectation,
    hasAuthenticatedNativeLtdEvidence,
    resolveMiiEraForRuntime,
    validateMiiEraClassification
} from "../miiEra.js";
import {
    getBackfillOfficialCategoryExpectation,
    validateBackfillLtdEraEvidence,
    validateBackfillOfficialCategoryEra
} from "../miiEraBackfillValidation.js";
import {
    canonicalizeMiiToLtd,
    isGeneratedLtdShareMiiCompatibility,
    makeTrustedMiiBytesInput,
    parseNativeLtdUpload
} from "../ltdCanonical.js";

const fixture = name => fs.readFileSync(new URL(`../testFiles/${name}`, import.meta.url));

function nativeLtdFixture() {
    const repositoryRoot = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
    const candidates = [
        path.join(repositoryRoot, "ltd-renderer", "dcmp", "mii2.ltd"),
        path.join(repositoryRoot, "ltd-renderer", "dcmp", "mii0.ltd")
    ];
    const externalFixture = candidates.find(candidate => fs.existsSync(candidate));
    return externalFixture ? fs.readFileSync(externalFixture) : null;
}

function nativeLtdV2Fixture() {
    const repositoryRoot = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
    const candidates = [
        path.join(repositoryRoot, "ltd-renderer", "dcmp", "mii1.ltd"),
        path.join(repositoryRoot, "ltd-renderer", "dcmp", "mii3.ltd")
    ];
    const externalFixture = candidates.find(candidate => fs.existsSync(candidate));
    return externalFixture ? fs.readFileSync(externalFixture) : null;
}

test("known native v2 LTD remains distinct from the generated compatibility envelope", { skip: !nativeLtdV2Fixture() }, async () => {
    const bytes = nativeLtdV2Fixture();
    const native = await parseNativeLtdUpload(makeTrustedMiiBytesInput(bytes, { declaredLtd: true }));
    assert.equal(native.parsed.version, 2);
    assert.equal(isGeneratedLtdShareMiiCompatibility(bytes), false);
    assert.equal(hasAuthenticatedNativeLtdEvidence(native.fields), true);
    assert.equal((await validateBackfillLtdEraEvidence(native.fields, "LTD", {
        storedBytes: Buffer.from(native.fields.ltdData),
        storedSha256: native.fields.ltdSha256
    })).valid, true);
});

test("era order is fixed and classification stops at the first lossless candidate", async () => {
    assert.deepEqual(MII_ERA_VALUES, ["RCD", "CFCD", "FFCD", "CHARINFO", "LTD"]);
    assert.equal(MII_ERA_ORDER[1].format, miijs.MiiFormats.CFCD);
    assert.equal(MII_ERA_ORDER[2].format, miijs.MiiFormats.FFCD);

    const called = [];
    const result = await classifyMiiEra({ general: { favoriteColor: 0 } }, {
        attemptEra: async (_mii, candidate) => {
            called.push(candidate.era);
            return candidate.era === "CFCD";
        }
    });

    assert.equal(result.era, "CFCD");
    assert.deepEqual(called, ["RCD", "CFCD"]);
    assert.deepEqual(result.attempts.map(attempt => attempt.era), called);
});

test("a failed encoder does not prevent trying the next era", async () => {
    const result = await classifyMiiEra({ general: { favoriteColor: 0 } }, {
        attemptEra: async (_mii, candidate) => {
            if (candidate.era === "RCD") throw Object.assign(new Error("not encodable"), { code: "RANGE" });
            return candidate.era === "CFCD";
        }
    });

    assert.equal(result.era, "CFCD");
    assert.equal(result.attempts[0].error.code, "RANGE");
    assert.equal(result.attempts.length, 2);
});

test("semantic comparison ignores wire provenance but retains real application data", () => {
    const base = {
        general: { favoriteColor: 2, gender: 0, height: 64, weight: 64 },
        meta: { name: "Same", creatorName: "Creator", miiId: "AAAA", originalDevice: 1 },
        face: {}, hair: {}, eyes: {}, eyebrows: {}, nose: {}, mouth: {}, beard: {}, glasses: {}, mole: {}
    };
    const provenanceChanged = structuredClone(base);
    provenanceChanged.meta.miiId = "BBBB";
    provenanceChanged.meta.originalDevice = 4;
    provenanceChanged.meta.creationTimestamp = new Date("2020-01-01T00:00:00Z");
    assert.deepEqual(getMiiEraSemanticSnapshot(provenanceChanged), getMiiEraSemanticSnapshot(base));

    const appChanged = structuredClone(base);
    appChanged.tl = { catchphrase: "changed" };
    assert.notDeepEqual(getMiiEraSemanticSnapshot(appChanged), getMiiEraSemanticSnapshot(base));
});

test("real Wii, Tomodachi Life, and 3DS fixtures classify in priority order", async () => {
    const wii = await miijs.Mii.create(fixture("MadisonWii.mii"));
    const tl = await miijs.Mii.create(fixture("TomodachiLifeCodename.jpg"));
    const ffcd = await miijs.Mii.create(fixture("MadisonChild3DSDecrypted.bin"));

    assert.equal((await classifyMiiEra(wii.fields)).era, "RCD");
    assert.equal((await classifyMiiEra(tl.fields)).era, "CFCD");
    assert.equal((await classifyMiiEra(ffcd.fields)).era, "CFCD");
});

test("a Switch-only palette value reaches CHARINFO", async () => {
    const source = await miijs.Mii.create(fixture("MadisonChild3DSDecrypted.bin"));
    const charInfo = await miijs.Mii.create(await source.encode(miijs.MiiFormats.CHARINFO));
    charInfo.fields.hair.color = 50;
    const normalized = await miijs.Mii.create(await charInfo.encode(miijs.MiiFormats.CHARINFO));

    const result = await classifyMiiEra(normalized.fields);
    assert.equal(result.era, "CHARINFO");
    assert.deepEqual(
        result.attempts.map(attempt => attempt.era),
        ["RCD", "CFCD", "FFCD", "CHARINFO"]
    );
});

test("native LTD requires the exact LTD byte round trip", { skip: !nativeLtdFixture() }, async () => {
    const reparsed = await parseNativeLtdUpload(makeTrustedMiiBytesInput(nativeLtdFixture(), { declaredLtd: true }));

    const result = await classifyMiiEra(reparsed.fields);
    assert.equal(result.era, "LTD");
    assert.equal(result.attempts.at(-1).lossless, true);
});

test("a generated LTD cannot manufacture source-era evidence", async () => {
    const source = await miijs.Mii.create(fixture("MadisonChild3DSDecrypted.bin"));
    const charInfo = await miijs.Mii.create(await source.encode(miijs.MiiFormats.CHARINFO));
    charInfo.fields.hair.color = 50;
    charInfo.fields.mt = { warCry: "This must survive" };

    const result = await classifyMiiEra(charInfo.fields);
    assert.equal(result.era, null);
    assert.equal(result.attempts.at(-1).era, "CHARINFO");
    assert.deepEqual(result.attempts.at(-1).appDataMismatchKeys, ["mt"]);

    const assigned = structuredClone(charInfo.fields);
    await assert.rejects(
        assignMiiEra(assigned),
        error => error?.code === "MII_ERA_NOT_LOSSLESS"
    );
});

test("official category and source markers impose deterministic era precedence", async () => {
    const cases = [
        {
            fields: {
                official: true,
                officialCategories: ["Switch/Miitopia", "3DS/Mii Maker", "Wii/Wii Sports"]
            },
            era: "RCD",
            basis: "official-wii-or-ds-category"
        },
        {
            fields: { officialCategories: ["DS/Kuruma de DS"] },
            era: "RCD"
        },
        {
            fields: { officialCategories: ["Promo", "3DS/Tomodachi Life"] },
            era: "CFCD"
        },
        {
            fields: { officialCategories: ["Switch/Miitopia", "3DS/Mii Maker"] },
            era: "CFCD"
        },
        {
            fields: { officialCategories: ["Wii U/Wii Fit U"] },
            era: "FFCD"
        },
        {
            fields: { officialCategories: ["Wii U/Wii Fit U", "Switch/Miitopia"] },
            era: "CHARINFO"
        },
        {
            fields: { officialCategories: ["Switch/Switch Sports"] },
            era: "CHARINFO"
        }
    ];

    for (const fixtureCase of cases) {
        const expectation = getMiiEraSourceExpectation(fixtureCase.fields);
        assert.equal(expectation.era, fixtureCase.era);
        if (fixtureCase.basis) assert.equal(expectation.basis, fixtureCase.basis);
        const result = await classifyMiiEra(fixtureCase.fields, {
            attemptEra: async () => {
                throw new Error("authoritative category must short-circuit codec probing");
            }
        });
        assert.equal(result.era, fixtureCase.era);
        assert.equal(validateMiiEraClassification(fixtureCase.fields, result).valid, true);
    }
});

test("category matching uses exact roots and does not trust ordinary tags", () => {
    assert.equal(getMiiEraSourceExpectation({ officialCategories: ["Wii U/Mii Maker"] }).era, "FFCD");
    assert.equal(getMiiEraSourceExpectation({ officialCategories: ["Other/Wii"] }), null);
    assert.equal(getMiiEraSourceExpectation({ tags: ["Wii"] }), null);
    assert.equal(getMiiEraSourceExpectation({ tags: ["Tomodachi Life"] }), null);
});

test("the backfill independently validates raw official-category precedence", () => {
    const cases = [
        [{ officialCategories: ["Switch/X", "3DS/Y", "Wii/Z"] }, "RCD"],
        [{ officialCategories: ["Nintendo DS/X"] }, "RCD"],
        [{ officialCategories: ["Switch/X", "3DS/Y"] }, "CFCD"],
        [{ officialCategories: ["Switch/X", "Wii U/Y"] }, "CHARINFO"],
        [{ officialCategories: ["Wii U/X"] }, "FFCD"]
    ];
    for (const [fields, expectedEra] of cases) {
        assert.equal(getBackfillOfficialCategoryExpectation(fields).era, expectedEra);
        assert.equal(validateBackfillOfficialCategoryEra(fields, expectedEra).valid, true);
        const wrongEra = expectedEra === "RCD" ? "CHARINFO" : "RCD";
        const rejected = validateBackfillOfficialCategoryEra(fields, wrongEra);
        assert.equal(rejected.valid, false);
        assert.equal(rejected.violation.code, "raw-official-category-era-mismatch");
    }
    assert.equal(getBackfillOfficialCategoryExpectation({ officialCategories: ["Other/Wii"] }), null);
    assert.equal(getBackfillOfficialCategoryExpectation({ tags: ["Wii"] }), null);
});

test("only authenticated native-upload bytes are eligible for LTD", { skip: !nativeLtdFixture() }, async () => {
    const source = await miijs.Mii.create(fixture("MadisonChild3DSDecrypted.bin"));
    const reparsedNative = await parseNativeLtdUpload(makeTrustedMiiBytesInput(nativeLtdFixture(), { declaredLtd: true }));
    const trustedNativeFields = reparsedNative.fields;
    assert.equal(hasAuthenticatedNativeLtdEvidence(trustedNativeFields), true);
    assert.equal((await classifyMiiEra(trustedNativeFields)).era, "LTD");
    const trustedBytes = Buffer.from(trustedNativeFields.ltdData);
    assert.equal((await validateBackfillLtdEraEvidence(trustedNativeFields, "LTD", {
        storedBytes: trustedBytes,
        storedSha256: trustedNativeFields.ltdSha256
    })).valid, true);

    for (const mutation of [
        { ltdProvenance: { ...trustedNativeFields.ltdProvenance, byteExact: false } },
        { ltdProvenance: { ...trustedNativeFields.ltdProvenance, kind: "canonical-regenerated-charinfo" } },
        { ltdSha256: "0".repeat(64) },
        { ltdData: undefined }
    ]) {
        const forged = { ...trustedNativeFields, ...mutation };
        assert.equal(hasAuthenticatedNativeLtdEvidence(forged), false);
        const result = await classifyMiiEra(forged);
        assert.equal(result.era, null);
        assert.equal(validateMiiEraClassification(forged, result).valid, false);
    }

    const regenerated = await canonicalizeMiiToLtd(source.fields, { recordId: "forged-generated-evidence" });
    const relabeledGenerated = {
        ...source.fields,
        ...regenerated.storedFields,
        console: "LTD",
        meta: { ...source.fields.meta, console: "LTD" },
        ltdCharInfo: { allegedNativeProjection: true },
        ltdConversionReport: undefined,
        ltdProvenance: {
            kind: "native-upload",
            codec: trustedNativeFields.ltdProvenance.codec,
            sourceFormat: "ltd",
            byteExact: true
        }
    };
    assert.equal(hasAuthenticatedNativeLtdEvidence(relabeledGenerated), false);
    assert.notEqual((await classifyMiiEra(relabeledGenerated)).era, "LTD");
    assert.equal((await validateBackfillLtdEraEvidence(relabeledGenerated, "LTD", {
        storedBytes: Buffer.from(relabeledGenerated.ltdData),
        storedSha256: relabeledGenerated.ltdSha256
    })).valid, false);

    const garbage = Buffer.alloc(437, 0xa5);
    const garbageHash = crypto.createHash("sha256")
        .update(garbage)
        .digest("hex");
    const forgedGarbage = {
        console: "LTD",
        meta: { console: "LTD" },
        ltdVersion: 2,
        ltdSha256: garbageHash,
        ltdCharInfo: { allegedNativeProjection: true },
        ltdProvenance: {
            kind: "native-upload",
            codec: trustedNativeFields.ltdProvenance.codec,
            sourceFormat: "ltd",
            byteExact: true
        }
    };
    assert.equal((await validateBackfillLtdEraEvidence(forgedGarbage, "LTD", {
        storedBytes: garbage,
        storedSha256: garbageHash
    })).valid, false);
});

test("generated CharInfo conversion metadata is not source-era authority", async () => {
    const source = await miijs.Mii.create(fixture("MadisonChild3DSDecrypted.bin"));
    const canonical = await canonicalizeMiiToLtd(source.fields, { recordId: "generated-not-source" });
    const generated = { ...source.fields, ...canonical.storedFields };
    assert.equal(getMiiEraSourceExpectation(generated), null);
    assert.equal((await classifyMiiEra(generated)).era, "CFCD");
});

test("runtime era resolution repairs stale LTD rows from authoritative non-LTD evidence", () => {
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
    const resolution = getMiiEraRuntimeResolution(twoCnagShape);
    assert.deepEqual(resolution, {
        era: "CFCD",
        basis: "tomodachi-life-source-marker",
        storedEra: "LTD",
        corrected: true
    });
    assert.equal(resolveMiiEraForRuntime(twoCnagShape), "CFCD");

    assert.equal(resolveMiiEraForRuntime({
        era: "LTD",
        officialCategories: ["Wii/Wii Sports"]
    }), "RCD");
    assert.equal(resolveMiiEraForRuntime({
        era: "LTD",
        console: "Mii Studio",
        ltdProvenance: { kind: "canonical-regenerated-charinfo", sourceFormat: "charinfo" }
    }), "CHARINFO");
});

test("runtime era resolution keeps an unresolved explicit LTD claim fail-closed", () => {
    assert.equal(resolveMiiEraForRuntime({ era: "LTD" }), "LTD");
});

test("runtime era resolution keeps authenticated LTD source evidence", { skip: !nativeLtdFixture() }, async () => {
    const native = await parseNativeLtdUpload(makeTrustedMiiBytesInput(nativeLtdFixture(), { declaredLtd: true }));
    assert.equal(resolveMiiEraForRuntime(native.fields), "LTD");
});

test("an official Wii category outranks even valid native LTD evidence", { skip: !nativeLtdFixture() }, async () => {
    const reparsed = await parseNativeLtdUpload(makeTrustedMiiBytesInput(nativeLtdFixture(), { declaredLtd: true }));
    reparsed.fields.officialCategories = ["Switch/Miitopia", "Wii/Wii Sports"];
    assert.equal((await classifyMiiEra(reparsed.fields)).era, "RCD");
});
