import assert from "node:assert/strict";
import test from "node:test";

import {
    createMiiDownloadPolicyToken,
    getMiiDownloadPolicyPayloadHash,
    verifyMiiDownloadPolicyToken
} from "../miiDownloadPolicyToken.js";

const SECRET = "test-only-download-policy-secret";
const NOW = 1_800_000_000_000;
const MII = {
    meta: { name: "Policy Mii", creatorName: "InfiniMii" },
    general: { favoriteColor: 4, height: 64, weight: 64 },
    face: { type: 0, color: 1 }
};

test("policy payload hashes are stable across object key order", () => {
    const reordered = {
        face: { color: 1, type: 0 },
        general: { weight: 64, height: 64, favoriteColor: 4 },
        meta: { creatorName: "InfiniMii", name: "Policy Mii" }
    };
    assert.equal(getMiiDownloadPolicyPayloadHash(MII), getMiiDownloadPolicyPayloadHash(reordered));
});

test("a valid token preserves the LTD-only policy for its exact Mii payload", () => {
    const token = createMiiDownloadPolicyToken(MII, { secret: SECRET, now: NOW });
    const result = verifyMiiDownloadPolicyToken(token, MII, { secret: SECRET, now: NOW + 1 });
    assert.equal(result.valid, true);
    assert.equal(result.ltdOnly, true);
    assert.equal(result.era, "LTD");
});

test("tampering with a signed policy token fails closed", () => {
    const token = createMiiDownloadPolicyToken(MII, { secret: SECRET, now: NOW });
    const tampered = `${token.slice(0, -1)}${token.endsWith("a") ? "b" : "a"}`;
    const result = verifyMiiDownloadPolicyToken(tampered, MII, { secret: SECRET, now: NOW + 1 });
    assert.equal(result.present, true);
    assert.equal(result.valid, false);
});

test("a token cannot be replayed for a different Mii payload", () => {
    const token = createMiiDownloadPolicyToken(MII, { secret: SECRET, now: NOW });
    const changed = structuredClone(MII);
    changed.general.favoriteColor = 9;
    const result = verifyMiiDownloadPolicyToken(token, changed, { secret: SECRET, now: NOW + 1 });
    assert.equal(result.valid, false);
    assert.equal(result.reason, "wrong-payload");
});

test("an omitted token makes no server-attested policy claim", () => {
    const result = verifyMiiDownloadPolicyToken("", MII, { secret: SECRET, now: NOW });
    assert.deepEqual(result, {
        present: false,
        valid: false,
        ltdOnly: false,
        era: "",
        reason: "missing"
    });
});

test("expired policy tokens fail closed", () => {
    const token = createMiiDownloadPolicyToken(MII, { secret: SECRET, now: NOW, ttlMs: 10 });
    const result = verifyMiiDownloadPolicyToken(token, MII, { secret: SECRET, now: NOW + 10 });
    assert.equal(result.valid, false);
    assert.equal(result.reason, "expired");
});
