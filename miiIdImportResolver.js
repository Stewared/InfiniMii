import { toMiiDataOnly } from "./miiDataUtils.js";

/**
 * Resolve an InfiniMii ID without weakening private-record authorization.
 * Lookups are injected so the access boundary can be tested without starting
 * the site or sharing a live database with the test runner.
 */
export async function resolveMiiIdForImportWithLookups(id, req, {
    findPublishedMii,
    findPrivateMii,
    isMiiHiddenFromViewer = () => false,
    canModerate = () => false
} = {}) {
    const trimmedId = typeof id === "string" ? id.trim() : "";
    if (!trimmedId) {
        return { error: "No Mii ID provided" };
    }
    if (typeof findPublishedMii !== "function" || typeof findPrivateMii !== "function") {
        throw new TypeError("Mii ID resolution requires public and private record lookups.");
    }

    const publishedMii = await findPublishedMii(trimmedId);
    if (publishedMii) {
        if (isMiiHiddenFromViewer(publishedMii, req?.user)) {
            return { error: "Invalid Mii ID - Mii not found" };
        }
        return { mii: toMiiDataOnly(publishedMii), record: publishedMii };
    }

    const privateMii = await findPrivateMii(trimmedId);
    if (!privateMii) {
        return { error: "Invalid Mii ID - Mii not found" };
    }

    const isOwner = req?.user && privateMii.uploader === req.user.username;
    const isModerator = req?.user && canModerate(req.user);
    if (!isOwner && !isModerator) {
        return { error: "You do not have permission to use this private Mii" };
    }

    return { mii: toMiiDataOnly(privateMii), record: privateMii };
}
