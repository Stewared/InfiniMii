import "../setEnvs.js";

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { cleanupMongoResources, connectionPromise, Miis } from "../database.js";
import {
    validateBackfillLtdEraEvidence,
    validateBackfillOfficialCategoryEra
} from "../miiEraBackfillValidation.js";
import { getStoredLtdBytes, getLtdSha256 } from "../ltdCanonical.js";
import {
    MII_ERA_VALUES,
    classifyMiiEra,
    hasAuthenticatedNativeLtdEvidence,
    validateMiiEraClassification
} from "../miiEra.js";

// `npm run backfill:mii-era` is read-only. Write mode deliberately requires a
// full-corpus pass, an exclusive preimage backup, and an explicit acknowledgement
// that standalone MongoDB cannot make a multi-document migration atomic.
const DEFAULT_BATCH_SIZE = 100;
const FULL_CORPUS_EXPECTED_LTD_RANGE = Object.freeze({ min: 4, max: 7 });

function parsePositiveInteger(value, flag) {
    const parsed = Number(value);
    if (!Number.isSafeInteger(parsed) || parsed < 1) {
        throw new Error(`${flag} must be a positive integer`);
    }
    return parsed;
}

function parseArgs(argv) {
    const options = {
        write: false,
        after: "",
        id: "",
        limit: Infinity,
        batchSize: DEFAULT_BATCH_SIZE,
        onlyMissing: false,
        backup: "",
        acknowledgeNonAtomic: false
    };

    for (let index = 0; index < argv.length; index += 1) {
        const argument = argv[index];
        const nextValue = flag => {
            const value = argv[index + 1];
            if (!value || value.startsWith("--")) throw new Error(`${flag} requires a value`);
            index += 1;
            return value;
        };
        if (argument === "--write") options.write = true;
        else if (argument === "--acknowledge-non-atomic") options.acknowledgeNonAtomic = true;
        else if (argument === "--backup") options.backup = nextValue("--backup");
        else if (argument.startsWith("--backup=")) options.backup = argument.slice("--backup=".length);
        else if (argument === "--only-missing") options.onlyMissing = true;
        else if (argument === "--after") options.after = nextValue("--after");
        else if (argument.startsWith("--after=")) options.after = argument.slice("--after=".length);
        else if (argument === "--id") options.id = nextValue("--id");
        else if (argument.startsWith("--id=")) options.id = argument.slice("--id=".length);
        else if (argument === "--limit") options.limit = parsePositiveInteger(nextValue("--limit"), "--limit");
        else if (argument.startsWith("--limit=")) {
            options.limit = parsePositiveInteger(argument.slice("--limit=".length), "--limit");
        } else if (argument === "--batch-size") {
            options.batchSize = parsePositiveInteger(nextValue("--batch-size"), "--batch-size");
        } else if (argument.startsWith("--batch-size=")) {
            options.batchSize = parsePositiveInteger(argument.slice("--batch-size=".length), "--batch-size");
        } else {
            throw new Error(`Unknown argument: ${argument}`);
        }
    }

    if (options.id && options.after) throw new Error("--id and --after cannot be combined");
    if (options.write && (options.id || options.after || options.onlyMissing || Number.isFinite(options.limit))) {
        throw new Error("--write requires an unfiltered full-corpus validation; remove --id, --after, --only-missing, and --limit");
    }
    if (options.write && !options.backup) throw new Error("--write requires --backup PATH");
    if (options.write && !options.acknowledgeNonAtomic) {
        throw new Error("--write requires --acknowledge-non-atomic on standalone MongoDB");
    }
    if (!options.write && (options.backup || options.acknowledgeNonAtomic)) {
        throw new Error("--backup and --acknowledge-non-atomic are valid only with --write");
    }
    return options;
}

function currentValueFilter(document) {
    if (document.updatedAt) return { updatedAt: document.updatedAt };
    return { updatedAt: { $exists: false } };
}

function databaseQuery(options) {
    // The collection currently also contains one collection-metadata document.
    // A real Mii has the schema-required public id; keep non-Mii bookkeeping
    // records out of both the classification report and the write transaction.
    const query = { id: { $type: "string", $ne: "" } };
    if (options.id) query.id = options.id;
    else if (options.after) query.id = { $type: "string", $gt: options.after };
    if (options.onlyMissing) {
        query.$or = [
            { era: { $exists: false } },
            { era: null },
            { era: { $nin: MII_ERA_VALUES } }
        ];
    }
    return query;
}

async function commitBatch(entries, { lastFullyCommittedId }) {
    if (entries.length === 0) return;
    const operations = entries.map(entry => entry.operation);
    let result;
    try {
        result = await Miis.bulkWrite(operations, {
            ordered: true,
            writeConcern: { w: "majority", j: true }
        });
    } catch (error) {
        throw new Error(
            `Era backfill batch failed after ${JSON.stringify(lastFullyCommittedId)}. The failing batch may be partially applied; preserve the preimage backup, stabilize writers, and rerun the full dry-run and full backfill without --after.`,
            { cause: error }
        );
    }
    const matched = Number(result?.matchedCount ?? result?.nMatched ?? 0);
    if (matched !== entries.length) {
        throw new Error(
            `Era backfill matched ${matched}/${entries.length} records after ${JSON.stringify(lastFullyCommittedId)}; a Mii changed concurrently and this batch may be partially applied. Preserve the preimage backup and rerun the complete migration without --after.`
        );
    }
}

function writePreimageBackup(backupPath, entries, metadata) {
    const resolved = path.resolve(backupPath);
    const parent = path.dirname(resolved);
    if (!fs.existsSync(parent) || !fs.statSync(parent).isDirectory()) {
        throw new Error(`Backup parent directory does not exist: ${parent}`);
    }
    const lines = [
        JSON.stringify({ schema: "infinimii-mii-era-preimage-v1", ...metadata }),
        ...entries.map(entry => JSON.stringify(entry.preimage))
    ];
    const bytes = Buffer.from(`${lines.join("\n")}\n`, "utf8");
    const handle = fs.openSync(resolved, "wx");
    try {
        fs.writeFileSync(handle, bytes);
        fs.fsyncSync(handle);
    } finally {
        fs.closeSync(handle);
    }
    return Object.freeze({
        path: resolved,
        byteLength: bytes.length,
        sha256: crypto.createHash("sha256").update(bytes).digest("hex")
    });
}

async function main() {
    const options = parseArgs(process.argv.slice(2));
    await connectionPromise;

    const counts = Object.fromEntries(MII_ERA_VALUES.map(era => [era, 0]));
    const changedCounts = Object.fromEntries(MII_ERA_VALUES.map(era => [era, 0]));
    const unclassified = [];
    const operations = [];
    const validationFailures = [];
    const plannedLtdIds = [];
    const nativeLtdEligibleIds = [];
    const storedLtdIds = [];
    const staleStoredLtdReclassifications = [];
    const sourceExpectationCounts = {};
    const sourceExpectationMismatchCounts = {};
    const officialCategoryValidationCounts = {};
    const officialCategoryMismatchCounts = {};
    const categorizedButUnofficialIds = [];
    let processed = 0;
    let unchanged = 0;
    let lastScannedId = options.after || null;

    console.log(JSON.stringify({
        event: "start",
        mode: options.write ? "write" : "dry-run",
        order: MII_ERA_VALUES,
        query: databaseQuery(options),
        batchSize: options.batchSize,
        limit: Number.isFinite(options.limit) ? options.limit : null,
        after: options.after || null,
        writeSafety: options.write ? {
            fullCorpusRequired: true,
            preimageBackupRequired: true,
            multiDocumentAtomic: false
        } : null
    }));

    const cursor = Miis.find(databaseQuery(options))
        .select("+ltdData")
        .sort({ id: 1 })
        .lean()
        .cursor();

    for await (const document of cursor) {
        if (processed >= options.limit) break;
        const id = String(document.id || "").trim();
        const mongoId = String(document._id);
        const recordKey = id || `mongo:${mongoId}`;
        if (String(document.era || "").trim().toUpperCase() === "LTD") {
            storedLtdIds.push(recordKey);
        }
        const result = await classifyMiiEra(document);
        const classifierValidation = validateMiiEraClassification(document, result);
        const categoryValidation = validateBackfillOfficialCategoryEra(document, result.era);
        const storedLtdBytes = getStoredLtdBytes(document);
        const ltdValidation = await validateBackfillLtdEraEvidence(document, result.era, {
            storedBytes: storedLtdBytes,
            storedSha256: storedLtdBytes ? getLtdSha256(storedLtdBytes) : null
        });
        const violations = [
            ...classifierValidation.violations,
            ...(categoryValidation.violation ? [categoryValidation.violation] : []),
            ...(ltdValidation.violation ? [ltdValidation.violation] : [])
        ];
        const validation = {
            valid: violations.length === 0,
            expectation: classifierValidation.expectation,
            categoryExpectation: categoryValidation.expectation,
            violations
        };
        processed += 1;
        if (id) lastScannedId = id;
        if (hasAuthenticatedNativeLtdEvidence(document)) nativeLtdEligibleIds.push(recordKey);
        if (categoryValidation.checked) {
            const basis = categoryValidation.expectation.basis;
            officialCategoryValidationCounts[basis] = (officialCategoryValidationCounts[basis] || 0) + 1;
            if (document.official !== true) categorizedButUnofficialIds.push(recordKey);
            if (!categoryValidation.valid) {
                officialCategoryMismatchCounts[basis] = (officialCategoryMismatchCounts[basis] || 0) + 1;
            }
        }
        if (validation.expectation) {
            const basis = validation.expectation.basis;
            sourceExpectationCounts[basis] = (sourceExpectationCounts[basis] || 0) + 1;
            if (!validation.valid) {
                sourceExpectationMismatchCounts[basis] = (sourceExpectationMismatchCounts[basis] || 0) + 1;
            }
        }

        if (!validation.valid) {
            const record = {
                id: id || null,
                mongoId,
                recordKey,
                era: result.era,
                expectation: validation.expectation,
                categoryExpectation: validation.categoryExpectation,
                violations: validation.violations
            };
            validationFailures.push(record);
            console.log(JSON.stringify({ event: "validation-failure", ...record }));
            continue;
        }

        if (!result.era) {
            const record = { id: id || null, mongoId, recordKey, attempts: result.attempts };
            unclassified.push(record);
            console.log(JSON.stringify({ event: "unclassified", ...record }));
        } else {
            if (String(document.era || "").trim().toUpperCase() === "LTD" && result.era !== "LTD") {
                const successfulAttempt = result.attempts.find(attempt => attempt.lossless === true);
                staleStoredLtdReclassifications.push({
                    id: recordKey,
                    targetEra: result.era,
                    basis: result.authority?.basis || successfulAttempt?.reason || "lossless-round-trip"
                });
            }
            if (result.era === "LTD") plannedLtdIds.push(recordKey);
            counts[result.era] += 1;
            if (document.era === result.era) {
                unchanged += 1;
            } else {
                changedCounts[result.era] += 1;
                operations.push({
                    recordKey,
                    operation: { updateOne: {
                        filter: { _id: document._id, ...currentValueFilter(document) },
                        update: { $set: { era: result.era } }
                    } },
                    preimage: {
                        mongoId,
                        id,
                        hadEra: Object.prototype.hasOwnProperty.call(document, "era"),
                        era: document.era ?? null,
                        targetEra: result.era,
                        updatedAt: document.updatedAt instanceof Date
                            ? document.updatedAt.toISOString()
                            : (document.updatedAt ?? null)
                    }
                });
            }
        }

        if (processed % options.batchSize === 0) {
            console.log(JSON.stringify({
                event: "scan-checkpoint",
                mode: options.write ? "write" : "dry-run",
                processed,
                lastScannedId,
                unclassified: unclassified.length,
                validationFailures: validationFailures.length
            }));
        }
    }

    const sortedPlannedLtdIds = [...plannedLtdIds].sort();
    const sortedNativeLtdEligibleIds = [...nativeLtdEligibleIds].sort();
    const nativeLtdSet = new Set(sortedNativeLtdEligibleIds);
    const plannedLtdSet = new Set(sortedPlannedLtdIds);
    const unauthenticatedPlannedLtdIds = sortedPlannedLtdIds.filter(id => !nativeLtdSet.has(id));
    const nativeLtdClassifiedElsewhereIds = sortedNativeLtdEligibleIds.filter(id => !plannedLtdSet.has(id));
    const allPlannedLtdAuthenticated = unauthenticatedPlannedLtdIds.length === 0;
    const ltdEvidenceSetsEqual = allPlannedLtdAuthenticated && nativeLtdClassifiedElsewhereIds.length === 0;
    if (!allPlannedLtdAuthenticated) {
        validationFailures.push({
            code: "unauthenticated-planned-ltd",
            unauthenticatedPlannedLtdIds
        });
    }

    const fullCorpusValidation = (
        !options.id
        && !options.after
        && !options.onlyMissing
        && !Number.isFinite(options.limit)
    );
    const ltdCountWithinExpectedRange = (
        !fullCorpusValidation
        || (
            sortedPlannedLtdIds.length >= FULL_CORPUS_EXPECTED_LTD_RANGE.min
            && sortedPlannedLtdIds.length <= FULL_CORPUS_EXPECTED_LTD_RANGE.max
        )
    );
    if (!ltdCountWithinExpectedRange) {
        validationFailures.push({
            code: "full-corpus-ltd-count-outside-audited-range",
            plannedLtdCount: sortedPlannedLtdIds.length,
            expectedRange: FULL_CORPUS_EXPECTED_LTD_RANGE
        });
    }

    const summary = {
        event: options.write ? "plan" : "complete",
        mode: options.write ? "write" : "dry-run",
        processed,
        distribution: counts,
        wouldChange: changedCounts,
        unchanged,
        unclassifiedCount: unclassified.length,
        unclassified,
        validationFailureCount: validationFailures.length,
        validationFailures,
        plannedLtdCount: sortedPlannedLtdIds.length,
        plannedLtdIds: sortedPlannedLtdIds,
        storedLtdCount: storedLtdIds.length,
        storedLtdIds: storedLtdIds.sort(),
        staleStoredLtdCount: staleStoredLtdReclassifications.length,
        staleStoredLtdReclassifications: staleStoredLtdReclassifications
            .sort((left, right) => left.id.localeCompare(right.id)),
        nativeLtdEligibleCount: sortedNativeLtdEligibleIds.length,
        nativeLtdEligibleIds: sortedNativeLtdEligibleIds,
        allPlannedLtdAuthenticated,
        ltdEvidenceSetsEqual,
        unauthenticatedPlannedLtdIds,
        nativeLtdClassifiedElsewhereIds,
        sourceExpectationCounts,
        sourceExpectationMismatchCounts,
        officialCategoryValidationCounts,
        officialCategoryMismatchCounts,
        categorizedButUnofficialCount: categorizedButUnofficialIds.length,
        categorizedButUnofficialIds: categorizedButUnofficialIds.sort(),
        fullCorpusValidation,
        fullCorpusExpectedLtdRange: FULL_CORPUS_EXPECTED_LTD_RANGE,
        ltdCountWithinExpectedRange,
        lastScannedId
    };
    console.log(JSON.stringify(summary));

    // Phase one validates the complete corpus before mutation. MongoDB is a
    // standalone here, so phase two is explicitly non-atomic and recoverable
    // from the exclusive preimage backup plus an idempotent full rerun.
    if (validationFailures.length > 0) {
        process.exitCode = 2;
        return;
    }
    if (options.write && unclassified.length > 0) {
        process.exitCode = 2;
        return;
    }
    if (options.write) {
        const backup = writePreimageBackup(options.backup, operations, {
            classifier: "infinimii-source-authority-semantic-round-trip-v2",
            createdAt: new Date().toISOString(),
            operationCount: operations.length
        });
        console.log(JSON.stringify({ event: "preimage-backup", ...backup }));
        let written = 0;
        let lastFullyCommittedId = null;
        for (let index = 0; index < operations.length; index += options.batchSize) {
            const batch = operations.slice(index, index + options.batchSize);
            await commitBatch(batch, {
                lastFullyCommittedId
            });
            written += batch.length;
            lastFullyCommittedId = batch.at(-1)?.recordKey || lastFullyCommittedId;
            console.log(JSON.stringify({
                event: "write-checkpoint",
                written,
                lastFullyCommittedId,
                remaining: operations.length - written
            }));
        }
        console.log(JSON.stringify({ ...summary, event: "complete", written, backup }));
    }
}

main()
    .catch(error => {
        console.error(error?.stack || error);
        process.exitCode = 1;
    })
    .finally(() => cleanupMongoResources());
