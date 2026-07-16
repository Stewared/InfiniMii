export const MII_DATA_TOP_LEVEL_KEYS = Object.freeze([
    "console",
    "meta",
    "perms",
    "general",
    "face",
    "hair",
    "eyes",
    "eyebrows",
    "nose",
    "mouth",
    "beard",
    "glasses",
    "mole",
    "tl",
    "mt",
    "miitopia"
]);

export const OPTIONAL_MII_DATA_TOP_LEVEL_KEYS = Object.freeze([
    "console",
    "tl",
    "mt",
    "miitopia"
]);

export const OPTIONAL_MII_DATA_TOP_LEVEL_KEY_SET = new Set(OPTIONAL_MII_DATA_TOP_LEVEL_KEYS);

export function cloneSerializable(value) {
    if (value === undefined) return undefined;
    try {
        return structuredClone(value);
    } catch {
        return JSON.parse(JSON.stringify(value));
    }
}

export function isPlainObjectValue(value) {
    return Boolean(
        value
        && typeof value === "object"
        && !Buffer.isBuffer(value)
        && !(value instanceof ArrayBuffer)
        && !ArrayBuffer.isView(value)
    );
}

export function toMiiDataOnly(input) {
    if (!isPlainObjectValue(input)) return input;

    const source = input.fields && isPlainObjectValue(input.fields) ? input.fields : input;
    const miiData = {};
    let foundMiiField = false;

    for (const key of MII_DATA_TOP_LEVEL_KEYS) {
        if (!Object.prototype.hasOwnProperty.call(source, key)) continue;
        foundMiiField = true;
        miiData[key] = cloneSerializable(source[key]);
    }

    return foundMiiField ? miiData : cloneSerializable(source);
}
