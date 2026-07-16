import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT_DIRECTORY = path.dirname(fileURLToPath(import.meta.url));
const STATIC_DIRECTORY = path.join(ROOT_DIRECTORY, "static");
const ACTIVE_ASSET_DIRECTORIES = Object.freeze([
    "miiImgs",
    "miiQRs",
    "miiQRsWii",
    "miiQRsTomodachi",
    "privateMiiImgs",
    "privateMiiQRs",
    "privateMiiQRsWii",
    "privateMiiQRsTomodachi"
]);

export function ensureMiiAssetDirectories() {
    for (const directory of ACTIVE_ASSET_DIRECTORIES) {
        fs.mkdirSync(path.join(STATIC_DIRECTORY, directory), { recursive: true });
    }
}

export function getMiiAssetPaths(miiId, isPrivate) {
    const id = String(miiId);
    const directories = isPrivate
        ? {
            image: "privateMiiImgs",
            qr3ds: "privateMiiQRs",
            qrWii: "privateMiiQRsWii",
            qrTomodachi: "privateMiiQRsTomodachi",
            qrMiitopia: "privateMiiQRsMiitopia"
        }
        : {
            image: "miiImgs",
            qr3ds: "miiQRs",
            qrWii: "miiQRsWii",
            qrTomodachi: "miiQRsTomodachi",
            qrMiitopia: "miiQRsMiitopia"
        };

    return {
        imgPath: path.join(STATIC_DIRECTORY, directories.image, `${id}.png`),
        qrPath: path.join(STATIC_DIRECTORY, directories.qr3ds, `${id}.png`),
        qrWiiPath: path.join(STATIC_DIRECTORY, directories.qrWii, `${id}.png`),
        qrTomodachiPath: path.join(STATIC_DIRECTORY, directories.qrTomodachi, `${id}.png`),
        qrMiitopiaPath: path.join(STATIC_DIRECTORY, directories.qrMiitopia, `${id}.png`)
    };
}

export async function deleteMiiAssets(miiId, isPrivate) {
    const paths = Object.values(getMiiAssetPaths(miiId, isPrivate));
    await Promise.all(paths.map(filePath => fs.promises.rm(filePath, { force: true })));
}

async function moveFileIfPresent(sourcePath, destinationPath) {
    try {
        await fs.promises.access(sourcePath, fs.constants.F_OK);
        await fs.promises.rm(destinationPath, { force: true });
        await fs.promises.rename(sourcePath, destinationPath);
    } catch (error) {
        if (error?.code !== "ENOENT") throw error;
    }
}

export async function moveMiiAssets(miiId, fromPrivate, toPrivate) {
    const sourcePaths = getMiiAssetPaths(miiId, fromPrivate);
    const destinationPaths = getMiiAssetPaths(miiId, toPrivate);
    await Promise.all(Object.keys(sourcePaths).map(key =>
        moveFileIfPresent(sourcePaths[key], destinationPaths[key])
    ));
    return destinationPaths;
}
