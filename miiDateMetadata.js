function toIsoTimestamp(value) {
    if (value === undefined || value === null || value === "") return undefined;
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? undefined : date.toISOString();
}

/**
 * Resolve dates that are safe to present as InfiniMii publication metadata.
 * `isExternal` must be derived from the validated external-source helper.
 */
export function resolveMiiDateMetadata(mii, { isExternal = false, pageUpdatedAt } = {}) {
    const uploadedIso = toIsoTimestamp(mii?.uploadedOn);
    const recordUpdatedIso = toIsoTimestamp(mii?.updatedAt);
    const pageUpdatedIso = toIsoTimestamp(pageUpdatedAt);

    if (isExternal) {
        return Object.freeze({
            isExternal: true,
            publishedIso: undefined,
            // An InfiniMii record update remains accurate page metadata, but an
            // import/upload timestamp is not the external source's publish date.
            modifiedIso: recordUpdatedIso
        });
    }

    return Object.freeze({
        isExternal: false,
        publishedIso: uploadedIso,
        modifiedIso: pageUpdatedIso || recordUpdatedIso || uploadedIso
    });
}
