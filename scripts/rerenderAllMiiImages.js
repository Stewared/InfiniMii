import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import "../setEnvs.js";
import { cleanupMongoResources, connectionPromise, Miis } from "../database.js";
import { writeStoredMiiImage } from "../miiImageRenderer.js";

const MODULE_DIRECTORY = path.dirname(fileURLToPath(import.meta.url));
const ROOT_DIRECTORY = path.resolve(MODULE_DIRECTORY, "..");
const PUBLIC_DIRECTORY = path.join(ROOT_DIRECTORY, "static", "miiImgs");
const PRIVATE_DIRECTORY = path.join(ROOT_DIRECTORY, "static", "privateMiiImgs");
const WORKER_COUNT = Math.max(1, Math.min(
    Number.parseInt(process.env.TOMODACHI_NATIVE_RENDER_CONCURRENCY || "4", 10) || 4,
    16
));

function imagePathFor(mii) {
    const id = String(mii?.id || "");
    if (!/^[A-Za-z0-9_-]+$/.test(id)) throw new Error(`Unsafe Mii id ${JSON.stringify(id)}`);
    return path.join(mii.private ? PRIVATE_DIRECTORY : PUBLIC_DIRECTORY, `${id}.png`);
}

async function main() {
    await connectionPromise;
    await Promise.all([
        fs.promises.mkdir(PUBLIC_DIRECTORY, { recursive: true }),
        fs.promises.mkdir(PRIVATE_DIRECTORY, { recursive: true })
    ]);
    const validMiiFilter = { id: { $regex: /^[A-Za-z0-9_-]+$/ } };
    const [totalMiis, skippedInvalidRecords] = await Promise.all([
        Miis.countDocuments(validMiiFilter),
        Miis.countDocuments({ $nor: [validMiiFilter] })
    ]);
    if (skippedInvalidRecords > 0) {
        console.warn(`[rerender-all] Skipping ${skippedInvalidRecords} invalid Mongo record(s) with no usable Mii id.`);
    }
    let completed = 0;
    const failures = [];
    const activeRenders = new Set();

    async function renderOne(mii) {
        try {
            await writeStoredMiiImage(mii, imagePathFor(mii));
        } catch (error) {
            failures.push({
                id: String(mii?.id || ""),
                error: String(error?.message || error).slice(0, 1000)
            });
        }
        completed += 1;
        if (completed % 100 === 0 || completed === totalMiis) {
            console.log(`[rerender-all] ${completed}/${totalMiis}`);
        }
    }

    const cursor = Miis.find(validMiiFilter).lean().cursor({ batchSize: 100 });
    for await (const mii of cursor) {
        const task = renderOne(mii).finally(() => activeRenders.delete(task));
        activeRenders.add(task);
        if (activeRenders.size >= WORKER_COUNT) await Promise.race(activeRenders);
    }
    await Promise.all(activeRenders);
    if (failures.length > 0) {
        console.error(JSON.stringify({ failures }, null, 2));
        throw new Error(`${failures.length} Mii image render(s) failed`);
    }
    console.log(JSON.stringify({
        rendered: completed,
        workers: WORKER_COUNT,
        skippedInvalidRecords
    }));
}

main()
    .finally(() => cleanupMongoResources())
    .catch(error => {
        console.error(error?.stack || error);
        process.exitCode = 1;
    });
