import assert from "node:assert/strict";
import test from "node:test";

import {
    CURRENT_MII_IDENTITY_HASH_PATTERN,
    areMiisTheSame,
    getMiiIdentityHash,
    getMiiIdentityHashCandidates,
    getMiiIdentityLookupHashCandidates,
    hasCurrentMiiIdentityHashVersion,
    setMiiIdentityHash
} from "../miiIdentityHash.js";

const APPEARANCE_A = "a1".repeat(32);
const APPEARANCE_B = "b2".repeat(32);

test("LTD identity hashes use the exact canonical appearance digest", () => {
    const first = {
        ltdAppearanceHash: APPEARANCE_A,
        hair: { type: 1 },
        general: { gender: 0, height: 60, weight: 70 }
    };
    const sameAppearance = {
        ltdAppearanceHash: APPEARANCE_A.toUpperCase(),
        hair: { type: 99 },
        general: { gender: 1, height: 1, weight: 2 }
    };
    const differentAppearance = { ...first, ltdAppearanceHash: APPEARANCE_B };

    assert.match(getMiiIdentityHash(first), /^mii-ltd-face-v1:[0-9a-f]{64}$/);
    assert.equal(getMiiIdentityHash(sameAppearance), getMiiIdentityHash(first));
    assert.notEqual(getMiiIdentityHash(differentAppearance), getMiiIdentityHash(first));
    assert.equal(areMiisTheSame(first, sameAppearance), true);
    assert.equal(areMiisTheSame(first, differentAppearance), false);
});

test("official LTD identity includes normalized general fields", () => {
    const first = {
        ltdAppearanceHash: APPEARANCE_A,
        general: { weight: 70, gender: 0, height: 60 }
    };
    const reordered = {
        ltdAppearanceHash: APPEARANCE_A,
        general: { height: 60, weight: 70, gender: 0 }
    };
    const changed = {
        ltdAppearanceHash: APPEARANCE_A,
        general: { height: 61, weight: 70, gender: 0 }
    };

    const hash = getMiiIdentityHash(first, { includeGeneral: true });
    assert.match(hash, /^mii-ltd-face-general-v1:[0-9a-f]{64}$/);
    assert.equal(hash, getMiiIdentityHash(reordered, { includeGeneral: true }));
    assert.notEqual(hash, getMiiIdentityHash(changed, { includeGeneral: true }));
    const lookupCandidates = getMiiIdentityHashCandidates(first, { includeGeneral: true });
    assert.match(lookupCandidates[0], /^mii-ltd-face-general-v1:[0-9a-f]{64}$/);
    assert.match(lookupCandidates[1], /^mii-face-general-v2:[0-9a-f]{64}$/);
    const storedHashPrefilter = getMiiIdentityLookupHashCandidates(first);
    assert.match(storedHashPrefilter[0], /^mii-ltd-face-v1:[0-9a-f]{64}$/);
    assert.match(storedHashPrefilter[1], /^mii-face-v4:[0-9a-f]{64}$/);
});

test("invalid LTD appearance digests cannot opt into the LTD identity namespace", () => {
    const hash = getMiiIdentityHash({
        ltdAppearanceHash: "not-a-sha256",
        meta: { name: "Fallback" },
        general: { gender: 0 },
        hair: { type: 1 }
    });
    assert.match(hash, /^mii-face-v4:[0-9a-f]{64}$/);
});

test("current-version detection and assignment include LTD identities", () => {
    const mii = { ltdAppearanceHash: APPEARANCE_A };
    assert.equal(setMiiIdentityHash(mii), mii);
    assert.equal(mii.miiHash, getMiiIdentityHash(mii));
    assert.equal(hasCurrentMiiIdentityHashVersion(mii.miiHash), true);
    assert.equal(hasCurrentMiiIdentityHashVersion(`mii-ltd-face-general-v1:${"0".repeat(64)}`), true);
    assert.equal(hasCurrentMiiIdentityHashVersion(`old:${"0".repeat(64)}`), false);
    assert.match(`mii-ltd-face-v1:${"0".repeat(64)}`, new RegExp(`^${CURRENT_MII_IDENTITY_HASH_PATTERN}`));
});

test("LTD records retain a classic-compatible duplicate candidate during migration", () => {
    const mii = {
        ltdAppearanceHash: APPEARANCE_A,
        meta: { name: "Duplicate" },
        general: { gender: 0, height: 64, weight: 64, favoriteColor: 1 },
        face: { type: 0, color: 0 },
        hair: { type: 1, color: 2 },
        eyes: { type: 2, color: 8 },
        eyebrows: { type: 2, color: 8 },
        nose: { type: 1 },
        mouth: { type: 1, color: 19 },
        beard: { type: 0, mustache: { type: 0 } },
        glasses: { type: 0 },
        mole: { on: false }
    };
    const hashes = getMiiIdentityHashCandidates(mii);
    assert.equal(hashes.length, 2);
    assert.match(hashes[0], /^mii-ltd-face-v1:/);
    assert.match(hashes[1], /^mii-face-v4:/);
});
