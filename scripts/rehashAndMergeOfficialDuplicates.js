import "../setEnvs.js";
import fs from "fs";
import mongoose from "mongoose";
import { connectionPromise, Miis, Settings, Users } from "../database.js";
import { getMiiIdentityHash } from "../miiIdentityHash.js";

const shouldWrite = process.argv.includes("--write");
const dryRun = !shouldWrite;
const BATCH_SIZE = 100;
const BLANK_MII_ID = "00000";

function normalizeMiiIdInput(rawId) {
    return typeof rawId === "string" ? rawId.trim() : "";
}

function normalizeCategoryPaths(rawCategories) {
    const source = Array.isArray(rawCategories) ? rawCategories : [rawCategories];
    return [...new Set(source
        .map(category => typeof category === "string" ? category.trim() : "")
        .filter(Boolean))];
}

function replaceArrayValuesUnique(values, oldValues, newValue) {
    const oldValueSet = oldValues instanceof Set
        ? oldValues
        : new Set((Array.isArray(oldValues) ? oldValues : [oldValues]).map(normalizeMiiIdInput).filter(Boolean));
    const nextValue = normalizeMiiIdInput(newValue);
    const seen = new Set();
    const nextValues = [];

    for (const rawValue of Array.isArray(values) ? values : []) {
        const normalized = normalizeMiiIdInput(rawValue);
        const candidate = oldValueSet.has(normalized) ? nextValue : normalized;
        if (!candidate || seen.has(candidate)) continue;
        seen.add(candidate);
        nextValues.push(candidate);
    }

    return nextValues;
}

function compareUploadAge(a, b) {
    const uploadedA = Number.isFinite(Number(a?.uploadedOn)) ? Number(a.uploadedOn) : Number.MAX_SAFE_INTEGER;
    const uploadedB = Number.isFinite(Number(b?.uploadedOn)) ? Number(b.uploadedOn) : Number.MAX_SAFE_INTEGER;
    if (uploadedA !== uploadedB) return uploadedA - uploadedB;
    return String(a?._id || "").localeCompare(String(b?._id || ""));
}

function getMiiAssetPaths(miiId, isPrivate) {
    const qr3dsDir = isPrivate ? "privateMiiQRs" : "miiQRs";
    const qrWiiDir = isPrivate ? "privateMiiQRsWii" : "miiQRsWii";

    return {
        imgPath: isPrivate ? `./static/privateMiiImgs/${miiId}.png` : `./static/miiImgs/${miiId}.png`,
        qrPath: `./static/${qr3dsDir}/${miiId}.png`,
        qrWiiPath: `./static/${qrWiiDir}/${miiId}.png`
    };
}

async function deleteMiiAssets(miiId, isPrivate) {
    const { imgPath, qrPath, qrWiiPath } = getMiiAssetPaths(miiId, isPrivate);
    await Promise.all([
        fs.promises.unlink(imgPath).catch(() => {}),
        fs.promises.unlink(qrPath).catch(() => {}),
        fs.promises.unlink(qrWiiPath).catch(() => {})
    ]);
}

async function flushBulkOps(model, bulkOps) {
    if (bulkOps.length === 0) return;
    if (!dryRun) {
        await model.bulkWrite(bulkOps, { ordered: false });
    }
    bulkOps.length = 0;
}

async function rehashAllMiis(summary) {
    const cursor = Miis.find({}).cursor();
    const bulkOps = [];

    for await (const mii of cursor) {
        const miiHash = getMiiIdentityHash(mii);
        if (!miiHash || mii.miiHash === miiHash) continue;

        summary.miiHashesUpdated++;
        bulkOps.push({
            updateOne: {
                filter: { _id: mii._id },
                update: { $set: { miiHash } }
            }
        });

        if (bulkOps.length >= BATCH_SIZE) {
            await flushBulkOps(Miis, bulkOps);
        }
    }

    await flushBulkOps(Miis, bulkOps);
}

async function findOfficialDuplicateGroups() {
    const officialMiis = await Miis.find({ official: true })
        .sort({ uploadedOn: 1, _id: 1 })
        .lean();
    const byHash = new Map();

    for (const mii of officialMiis) {
        const officialHash = getMiiIdentityHash(mii, { includeGeneral: true });
        if (!officialHash) continue;
        if (!byHash.has(officialHash)) byHash.set(officialHash, []);
        byHash.get(officialHash).push(mii);
    }

    return [...byHash.values()].filter(group => group.length > 1);
}

async function replaceDuplicateReferences(duplicateIds, survivorId, summary) {
    const duplicateIdSet = new Set(duplicateIds);
    const usersWithVotes = await Users.find({ votedFor: { $in: duplicateIds } })
        .select("username votedFor")
        .lean();

    const voteOps = usersWithVotes
        .map((user) => {
            const nextVotes = replaceArrayValuesUnique(user.votedFor, duplicateIdSet, survivorId);
            if (JSON.stringify(nextVotes) === JSON.stringify(Array.isArray(user.votedFor) ? user.votedFor : [])) {
                return null;
            }
            return {
                updateOne: {
                    filter: { username: user.username },
                    update: { $set: { votedFor: nextVotes } }
                }
            };
        })
        .filter(Boolean);

    summary.usersMovedToOlderOfficial += voteOps.length;
    if (voteOps.length > 0 && !dryRun) {
        await Users.bulkWrite(voteOps, { ordered: false });
    }

    const pfpUserCount = await Users.countDocuments({ miiPfp: { $in: duplicateIds } });
    summary.profilePicturesMovedToOlderOfficial += pfpUserCount;
    if (pfpUserCount > 0 && !dryRun) {
        await Users.updateMany(
            { miiPfp: { $in: duplicateIds } },
            { $set: { miiPfp: survivorId } }
        );
    }

    const settings = await Settings.findById("global").lean();
    const settingsUpdates = {};

    if (duplicateIdSet.has(normalizeMiiIdInput(settings?.highlightedMii))) {
        settingsUpdates.highlightedMii = survivorId;
    }

    if (duplicateIdSet.has(normalizeMiiIdInput(settings?.defaultUserPfpMii))) {
        settingsUpdates.defaultUserPfpMii = survivorId || BLANK_MII_ID;
    }

    if (Object.keys(settingsUpdates).length > 0) {
        summary.settingsReferencesMovedToOlderOfficial++;
        if (!dryRun) {
            await Settings.findByIdAndUpdate("global", settingsUpdates, { upsert: true });
        }
    }
}

async function countUsersWhoVotedForMii(miiId) {
    const normalizedMiiId = normalizeMiiIdInput(miiId);
    if (!normalizedMiiId) return 0;
    return Users.countDocuments({ votedFor: normalizedMiiId });
}

async function mergeOfficialDuplicateGroup(group, summary) {
    const sorted = [...group].sort(compareUploadAge);
    const survivor = sorted[0];
    const duplicates = sorted.slice(1);
    const duplicateIds = duplicates.map(mii => normalizeMiiIdInput(mii.id)).filter(Boolean);
    if (!survivor?.id || duplicateIds.length === 0) return;

    summary.officialDuplicateGroupsMerged++;
    summary.officialDuplicatesDeleted += duplicateIds.length;

    const mergedCategories = normalizeCategoryPaths([
        ...(survivor.officialCategories || []),
        ...duplicates.flatMap(mii => mii.officialCategories || [])
    ]);
    const survivorCategories = normalizeCategoryPaths(survivor.officialCategories || []);
    const categoriesChanged = JSON.stringify(mergedCategories) !== JSON.stringify(survivorCategories);

    if (categoriesChanged) {
        summary.officialCategoryMerges++;
        if (!dryRun) {
            await Miis.updateOne(
                { id: survivor.id, official: true },
                { $set: { officialCategories: mergedCategories } }
            );
        }
    }

    await replaceDuplicateReferences(duplicateIds, survivor.id, summary);

    if (!dryRun) {
        await Promise.all(duplicates.map(mii => deleteMiiAssets(mii.id, Boolean(mii.private))));
        await Miis.deleteMany({ id: { $in: duplicateIds }, official: true });
    }

    const survivorVoteUsers = dryRun
        ? await Users.countDocuments({ $or: [{ votedFor: survivor.id }, { votedFor: { $in: duplicateIds } }] })
        : await countUsersWhoVotedForMii(survivor.id);
    const survivorVotes = Math.max(1, survivorVoteUsers + 1);

    summary.officialVoteCountsUpdated++;
    if (!dryRun) {
        await Miis.updateOne(
            { id: survivor.id, official: true },
            { $set: { votes: survivorVotes } }
        );
    }

    summary.mergedOfficialDuplicateDetails.push({
        kept: survivor.id,
        deleted: duplicateIds,
        categories: mergedCategories,
        votes: survivorVotes
    });
}

async function mergeOfficialDuplicates(summary) {
    const duplicateGroups = await findOfficialDuplicateGroups();
    for (const group of duplicateGroups) {
        await mergeOfficialDuplicateGroup(group, summary);
    }
}

async function updateAverageMiiVotes(summary) {
    const averageVoteCount = await countUsersWhoVotedForMii("average");
    const averageMii = await Miis.findOne({ id: "average" }).select("id votes").lean();
    summary.averageVoteUsers = averageVoteCount;

    if (!averageMii) {
        summary.averageMiiMissing = true;
        return;
    }

    if (Number(averageMii.votes) === averageVoteCount) return;

    summary.averageVotesBefore = Number.isFinite(Number(averageMii.votes)) ? Number(averageMii.votes) : null;
    summary.averageVotesAfter = averageVoteCount;
    if (!dryRun) {
        await Miis.updateOne(
            { id: "average" },
            { $set: { votes: averageVoteCount } }
        );
    }
}

async function main() {
    await connectionPromise;

    const summary = {
        dryRun,
        miiHashesUpdated: 0,
        officialDuplicateGroupsMerged: 0,
        officialDuplicatesDeleted: 0,
        officialCategoryMerges: 0,
        usersMovedToOlderOfficial: 0,
        profilePicturesMovedToOlderOfficial: 0,
        settingsReferencesMovedToOlderOfficial: 0,
        officialVoteCountsUpdated: 0,
        averageVoteUsers: 0,
        averageMiiMissing: false,
        averageVotesBefore: null,
        averageVotesAfter: null,
        mergedOfficialDuplicateDetails: []
    };

    await rehashAllMiis(summary);
    await mergeOfficialDuplicates(summary);
    await updateAverageMiiVotes(summary);

    console.log(JSON.stringify(summary, null, 2));
}

main()
    .catch((error) => {
        console.error("[rehash] Failed:", error);
        process.exitCode = 1;
    })
    .finally(async () => {
        await mongoose.disconnect();
    });
