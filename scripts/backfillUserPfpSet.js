import "../setEnvs.js";
import mongoose from "mongoose";
import { connectionPromise, Users } from "../database.js";

const DEFAULT_USER_PFP_MII_ID = "QfK19";
const shouldWrite = process.argv.includes("--write");
const dryRun = !shouldWrite;

async function countUsersWithDefaultPfp() {
    return Users.countDocuments({ miiPfp: DEFAULT_USER_PFP_MII_ID });
}

async function countUsersWithCustomPfp() {
    return Users.countDocuments({
        $or: [
            { miiPfp: { $ne: DEFAULT_USER_PFP_MII_ID } },
            { miiPfp: { $exists: false } },
            { miiPfp: null },
            { miiPfp: "" }
        ]
    });
}

async function main() {
    await connectionPromise;

    const [defaultPfpUsers, customPfpUsers] = await Promise.all([
        countUsersWithDefaultPfp(),
        countUsersWithCustomPfp()
    ]);

    const summary = {
        dryRun,
        defaultPfpUsersSetFalse: defaultPfpUsers,
        customPfpUsersSetTrue: customPfpUsers
    };

    if (!dryRun) {
        const [defaultResult, customResult] = await Promise.all([
            Users.updateMany(
                { miiPfp: DEFAULT_USER_PFP_MII_ID },
                { $set: { pfpSet: false } }
            ),
            Users.updateMany(
                {
                    $or: [
                        { miiPfp: { $ne: DEFAULT_USER_PFP_MII_ID } },
                        { miiPfp: { $exists: false } },
                        { miiPfp: null },
                        { miiPfp: "" }
                    ]
                },
                { $set: { pfpSet: true } }
            )
        ]);

        summary.defaultPfpUsersModified = defaultResult.modifiedCount || 0;
        summary.customPfpUsersModified = customResult.modifiedCount || 0;
    }

    console.log(JSON.stringify(summary, null, 2));
}

main()
    .catch((error) => {
        console.error("[pfpSet] Failed:", error);
        process.exitCode = 1;
    })
    .finally(async () => {
        await mongoose.disconnect();
    });
