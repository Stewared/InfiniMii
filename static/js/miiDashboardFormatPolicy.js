((globalScope) => {
    function normalizeFormatValues(formats) {
        const values = [];
        const seen = new Set();

        for (const format of Array.isArray(formats) ? formats : []) {
            const rawValue = format && typeof format === 'object' ? format.value : format;
            const value = String(rawValue || '').trim().toLowerCase();
            if (!value || seen.has(value)) continue;
            seen.add(value);
            values.push(value);
        }

        return values;
    }

    function getAllowedFormats(result, configuredFormats) {
        const configured = normalizeFormatValues(configuredFormats);
        if (!result || !Array.isArray(result.allowedExportFormats)) return configured;

        const configuredSet = new Set(configured);
        return normalizeFormatValues(result.allowedExportFormats)
            .filter((format) => configuredSet.has(format));
    }

    function isLtdOnly(formats) {
        const normalized = normalizeFormatValues(formats);
        return normalized.length === 1 && normalized[0] === 'ltd';
    }

    globalScope.InfiniMiiDashboardFormatPolicy = Object.freeze({
        getAllowedFormats,
        isLtdOnly,
        normalizeFormatValues
    });
})(globalThis);
