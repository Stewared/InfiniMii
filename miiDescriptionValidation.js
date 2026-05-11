export const MII_DESCRIPTION_MAX_LENGTH = 350;

export function normalizeMiiDescription(value) {
    return String(value ?? "").trim();
}

export function getMiiDescriptionValidationError(value, { required = true } = {}) {
    if (typeof value !== "string") {
        return "Description must be a string";
    }

    const normalizedValue = normalizeMiiDescription(value);
    if (required && normalizedValue.length === 0) {
        return "Description is required.";
    }

    if (normalizedValue.length > MII_DESCRIPTION_MAX_LENGTH) {
        return `Description must be ${MII_DESCRIPTION_MAX_LENGTH} characters or fewer.`;
    }

    return "";
}
