import test from "node:test";
import assert from "node:assert/strict";

import {
    DEFAULT_BACKFILL_LIMIT,
    GENERATED_LTD_PROVENANCE_KIND,
    buildGeneratedLtdCandidateFilter,
    parseBackfillArgs,
    runGeneratedLtdBackfill
} from "../scripts/backfillGeneratedLtdShareMiiSafety.js";

const CURRENT_POLICY = "current-test-policy";

function fakeMiis(records) {
    const query = {
        select() { return this; },
        sort() { return this; },
        limit(value) {
            this.limitValue = value;
            return this;
        },
        async lean() { return records.slice(0, this.limitValue); }
    };
    return {
        async countDocuments(filter) {
            assert.deepEqual(filter, buildGeneratedLtdCandidateFilter());
            return records.length;
        },
        find(filter) {
            assert.deepEqual(filter, buildGeneratedLtdCandidateFilter());
            return query;
        }
    };
}

function generated(id, state) {
    return {
        _id: id,
        id,
        state,
        ltdData: Buffer.from(id),
        ltdProvenance: { kind: GENERATED_LTD_PROVENANCE_KIND }
    };
}

const silentLogger = {
    log() {},
    warn() {},
    error() {}
};

test("backfill CLI is dry-run by default and validates its bound", () => {
    assert.deepEqual(parseBackfillArgs([]), {
        apply: false,
        help: false,
        limit: DEFAULT_BACKFILL_LIMIT
    });
    assert.deepEqual(parseBackfillArgs(["--apply", "--limit=25"]), {
        apply: true,
        help: false,
        limit: 25
    });
    assert.throws(() => parseBackfillArgs(["--limit", "0"]), /between 1 and/);
    assert.throws(() => parseBackfillArgs(["--surprise"]), /Unknown argument/);
});

test("dry-run identifies unsafe generated payloads without persisting", async () => {
    const records = [generated("old", "old"), generated("current", "current")];
    const persistValues = [];
    const summary = await runGeneratedLtdBackfill({
        Miis: fakeMiis(records),
        ensureCanonicalLtdForMii: async (record, { persist }) => {
            persistValues.push(persist);
            return record.state === "old"
                ? { replacesStoredLtd: { reason: "upgrade" } }
                : { bytes: record.ltdData };
        },
        assertGeneratedLtdShareMiiCompatibility() {
            assert.fail("dry-run must not validate an applied result");
        },
        currentProfilePolicyId: CURRENT_POLICY,
        logger: silentLogger
    });

    assert.deepEqual(persistValues, [false, false]);
    assert.equal(summary.mode, "dry-run");
    assert.equal(summary.wouldUpgrade, 1);
    assert.equal(summary.alreadyCurrent, 1);
    assert.equal(summary.upgraded, 0);
    assert.equal(summary.errors, 0);
});

test("apply reuses canonical CAS persistence and never processes native provenance", async () => {
    const records = [
        generated("old", "old"),
        generated("current", "current"),
        {
            id: "native",
            ltdData: Buffer.from("native"),
            ltdProvenance: { kind: "native-upload" }
        },
        generated("broken", "broken")
    ];
    const calls = [];
    const validated = [];
    const summary = await runGeneratedLtdBackfill({
        Miis: fakeMiis(records),
        ensureCanonicalLtdForMii: async (record, { persist }) => {
            calls.push([record.id, persist]);
            if (record.state === "broken") throw new Error("fixture failure");
            if (record.state === "current") return { bytes: record.ltdData };
            if (!persist) return { replacesStoredLtd: { reason: "upgrade" } };
            return {
                bytes: Buffer.from("safe"),
                storedFields: {
                    ltdProvenance: {
                        kind: GENERATED_LTD_PROVENANCE_KIND,
                        profilePolicy: CURRENT_POLICY
                    }
                }
            };
        },
        assertGeneratedLtdShareMiiCompatibility(bytes) {
            validated.push(bytes.toString());
        },
        currentProfilePolicyId: CURRENT_POLICY,
        apply: true,
        logger: silentLogger
    });

    assert.deepEqual(calls, [
        ["old", false],
        ["old", true],
        ["current", false],
        ["broken", false]
    ]);
    assert.deepEqual(validated, ["safe"]);
    assert.equal(summary.upgraded, 1);
    assert.equal(summary.alreadyCurrent, 1);
    assert.equal(summary.skippedProvenanceMismatch, 1);
    assert.equal(summary.errors, 1);
});

test("apply refuses to make a partial migration when the safety limit is too low", async () => {
    let findCalled = false;
    const Miis = {
        async countDocuments() { return 2; },
        find() {
            findCalled = true;
            assert.fail("a partial apply must stop before records are loaded");
        }
    };

    await assert.rejects(
        runGeneratedLtdBackfill({
            Miis,
            ensureCanonicalLtdForMii: async () => assert.fail("must not canonicalize"),
            assertGeneratedLtdShareMiiCompatibility: () => assert.fail("must not validate"),
            currentProfilePolicyId: CURRENT_POLICY,
            apply: true,
            limit: 1,
            logger: silentLogger
        }),
        /Refusing a partial apply/
    );
    assert.equal(findCalled, false);
});
