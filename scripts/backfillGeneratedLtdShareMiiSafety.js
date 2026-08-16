import path from "node:path";
import { fileURLToPath } from "node:url";

export const GENERATED_LTD_PROVENANCE_KIND = "canonical-regenerated-charinfo";
export const DEFAULT_BACKFILL_LIMIT = 2000;
export const MAX_BACKFILL_LIMIT = 10000;

export function parseBackfillArgs(argv = []) {
    let apply = false;
    let limit = DEFAULT_BACKFILL_LIMIT;
    let help = false;

    for (let index = 0; index < argv.length; index++) {
        const argument = argv[index];
        if (argument === "--apply") {
            apply = true;
            continue;
        }
        if (argument === "--help" || argument === "-h") {
            help = true;
            continue;
        }

        let rawLimit;
        if (argument === "--limit") {
            rawLimit = argv[++index];
        } else if (argument.startsWith("--limit=")) {
            rawLimit = argument.slice("--limit=".length);
        } else {
            throw new Error(`Unknown argument: ${argument}`);
        }

        if (!/^\d+$/.test(String(rawLimit || ""))) {
            throw new Error("--limit must be a positive integer");
        }
        limit = Number(rawLimit);
        if (!Number.isSafeInteger(limit) || limit < 1 || limit > MAX_BACKFILL_LIMIT) {
            throw new Error(`--limit must be between 1 and ${MAX_BACKFILL_LIMIT}`);
        }
    }

    return { apply, help, limit };
}

export function buildGeneratedLtdCandidateFilter() {
    return {
        "ltdProvenance.kind": GENERATED_LTD_PROVENANCE_KIND,
        ltdData: { $exists: true, $ne: null }
    };
}

export async function runGeneratedLtdBackfill({
    Miis,
    ensureCanonicalLtdForMii,
    assertGeneratedLtdShareMiiCompatibility,
    currentProfilePolicyId,
    apply = false,
    limit = DEFAULT_BACKFILL_LIMIT,
    logger = console
}) {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > MAX_BACKFILL_LIMIT) {
        throw new Error(`limit must be between 1 and ${MAX_BACKFILL_LIMIT}`);
    }

    const filter = buildGeneratedLtdCandidateFilter();
    const totalCandidates = await Miis.countDocuments(filter);
    if (apply && totalCandidates > limit) {
        throw new Error(
            `Refusing a partial apply: ${totalCandidates} generated LTD records exceed --limit ${limit}. `
            + "Raise --limit after reviewing the dry-run."
        );
    }
    const records = await Miis.find(filter)
        .select("+ltdData")
        .sort({ _id: 1 })
        .limit(limit)
        .lean();
    const summary = {
        mode: apply ? "apply" : "dry-run",
        totalCandidates,
        selected: records.length,
        alreadyCurrent: 0,
        wouldUpgrade: 0,
        upgraded: 0,
        skippedProvenanceMismatch: 0,
        errors: 0,
        limited: totalCandidates > records.length
    };

    for (const record of records) {
        const id = String(record?.id || record?._id || "unknown");
        if (record?.ltdProvenance?.kind !== GENERATED_LTD_PROVENANCE_KIND) {
            summary.skippedProvenanceMismatch++;
            logger.warn(`[ltd-safety-backfill] Skipping ${id}: provenance is no longer generated.`);
            continue;
        }

        try {
            const preview = await ensureCanonicalLtdForMii(record, { persist: false });
            if (!preview?.replacesStoredLtd) {
                summary.alreadyCurrent++;
                continue;
            }

            if (!apply) {
                summary.wouldUpgrade++;
                continue;
            }

            const canonical = await ensureCanonicalLtdForMii(record, { persist: true });
            assertGeneratedLtdShareMiiCompatibility(canonical.bytes);
            if (canonical?.storedFields?.ltdProvenance?.kind !== GENERATED_LTD_PROVENANCE_KIND) {
                throw new Error("canonicalizer returned non-generated provenance");
            }
            if (canonical.storedFields.ltdProvenance.profilePolicy !== currentProfilePolicyId) {
                throw new Error("canonicalizer did not persist the current ShareMii profile policy");
            }
            summary.upgraded++;
        } catch (error) {
            summary.errors++;
            logger.error(`[ltd-safety-backfill] Failed ${id}: ${error.message}`);
        }
    }

    return summary;
}

function printUsage(logger = console) {
    logger.log("Usage: node scripts/backfillGeneratedLtdShareMiiSafety.js [--apply] [--limit N]");
    logger.log("Dry-run is the default. --apply enables compare-and-swap persistence.");
}

function printSummary(summary, logger = console) {
    logger.log(`[ltd-safety-backfill] Mode: ${summary.mode}`);
    logger.log(`[ltd-safety-backfill] Generated LTD records: ${summary.totalCandidates}`);
    logger.log(`[ltd-safety-backfill] Selected (limit-bound): ${summary.selected}`);
    logger.log(`[ltd-safety-backfill] Already current: ${summary.alreadyCurrent}`);
    logger.log(`[ltd-safety-backfill] Would upgrade: ${summary.wouldUpgrade}`);
    logger.log(`[ltd-safety-backfill] Upgraded: ${summary.upgraded}`);
    logger.log(`[ltd-safety-backfill] Provenance mismatches skipped: ${summary.skippedProvenanceMismatch}`);
    logger.log(`[ltd-safety-backfill] Errors: ${summary.errors}`);
    if (summary.limited) {
        logger.warn("[ltd-safety-backfill] Candidate count exceeded --limit; raise --limit to inspect the complete set.");
    }
}

export async function main(argv = process.argv.slice(2), logger = console) {
    const options = parseBackfillArgs(argv);
    if (options.help) {
        printUsage(logger);
        return { help: true };
    }

    await import("../setEnvs.js");
    const database = await import("../database.js");
    const canonical = await import("../ltdCanonical.js");

    try {
        await database.connectionPromise;
        logger.log("[ltd-safety-backfill] Connected to MongoDB.");
        if (!options.apply) {
            logger.log("[ltd-safety-backfill] DRY RUN: no records will be changed.");
        }

        const summary = await runGeneratedLtdBackfill({
            Miis: database.Miis,
            ensureCanonicalLtdForMii: canonical.ensureCanonicalLtdForMii,
            assertGeneratedLtdShareMiiCompatibility: canonical.assertGeneratedLtdShareMiiCompatibility,
            currentProfilePolicyId: canonical.LTD_PROFILE_POLICY_ID,
            apply: options.apply,
            limit: options.limit,
            logger
        });
        printSummary(summary, logger);
        if (summary.errors > 0) process.exitCode = 1;
        return summary;
    } finally {
        await database.cleanupMongoResources();
    }
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : "";
const currentPath = path.resolve(fileURLToPath(import.meta.url));
if (invokedPath.toLowerCase() === currentPath.toLowerCase()) {
    main().catch((error) => {
        console.error("[ltd-safety-backfill] Fatal error:", error);
        process.exitCode = 1;
    });
}
