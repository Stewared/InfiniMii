import FormData from "form-data";
import https from "https";
import os from "os";
import { inspect } from "node:util";

const monitoringState = globalThis.__infinimiiMonitoringState ?? {
    consoleErrorInstalled: false,
    invalidWebhookUrlLogged: false,
    invalidWebhookUrlsLogged: {},
    rawConsoleError: console.error.bind(console),
    rawConsoleWarn: console.warn.bind(console)
};

globalThis.__infinimiiMonitoringState = monitoringState;
if (!monitoringState.invalidWebhookUrlsLogged) {
    monitoringState.invalidWebhookUrlsLogged = {};
}

const rawConsoleError = monitoringState.rawConsoleError;
const rawConsoleWarn = monitoringState.rawConsoleWarn;
const DEFAULT_SITE_ORIGIN = "https://infinimii.com";

function truncate(text, maxLength) {
    const stringValue = String(text ?? "");
    if (stringValue.length <= maxLength) return stringValue;

    const suffix = "...(truncated)";
    return `${stringValue.slice(0, Math.max(0, maxLength - suffix.length))}${suffix}`;
}

function getWebhookUrl(envName = "hookUrl") {
    const webhookEnvName = typeof envName === "string" && envName.trim()
        ? envName.trim()
        : "hookUrl";
    const configuredHookUrl = typeof process.env[webhookEnvName] === "string"
        ? process.env[webhookEnvName].trim()
        : "";

    if (!configuredHookUrl) return null;

    try {
        return new URL(configuredHookUrl);
    } catch (error) {
        const hasLoggedInvalidUrl = webhookEnvName === "hookUrl"
            ? monitoringState.invalidWebhookUrlLogged
            : monitoringState.invalidWebhookUrlsLogged[webhookEnvName];
        if (!hasLoggedInvalidUrl) {
            monitoringState.invalidWebhookUrlsLogged[webhookEnvName] = true;
            if (webhookEnvName === "hookUrl") {
                monitoringState.invalidWebhookUrlLogged = true;
            }
            rawConsoleError(`[monitoring] Invalid ${webhookEnvName}. Webhook notifications are disabled.`, error);
        }
        return null;
    }
}

function getResolvedSiteBaseUrl() {
    const configuredBaseUrl = typeof process.env.baseUrl === "string"
        ? process.env.baseUrl.trim()
        : "";

    try {
        return new URL(configuredBaseUrl || DEFAULT_SITE_ORIGIN);
    } catch {
        return new URL(DEFAULT_SITE_ORIGIN);
    }
}

function buildSitePageUrl(pathname = "/") {
    return new URL(pathname, getResolvedSiteBaseUrl()).toString();
}

function buildUserPageUrl(username) {
    const normalizedUsername = String(username ?? "").trim();
    if (!normalizedUsername) return null;
    return buildSitePageUrl(`/user/${encodeURIComponent(normalizedUsername)}`);
}

function buildMiiPageUrl(miiId) {
    const normalizedMiiId = String(miiId ?? "").trim();
    if (!normalizedMiiId) return null;
    return buildSitePageUrl(`/mii/${encodeURIComponent(normalizedMiiId)}`);
}

function isRelevantSitePagePath(pathname) {
    const normalizedPath = String(pathname ?? "").trim().toLowerCase();
    if (!normalizedPath.startsWith("/")) return false;
    if (normalizedPath === "/") return true;

    if (
        normalizedPath.startsWith("/miiimgs/")
        || normalizedPath.startsWith("/privatemiiimgs/")
        || normalizedPath.startsWith("/miiqrs/")
        || normalizedPath.startsWith("/miiqrswii/")
        || normalizedPath.startsWith("/miiqrstomodachi/")
        // MT QR image routes are temporarily disabled on the InfiniMii site.
        // || normalizedPath.startsWith("/miiqrsmiitopia/")
        || normalizedPath.startsWith("/privatemiiqrs/")
        || normalizedPath.startsWith("/privatemiiqrswii/")
        || normalizedPath.startsWith("/privatemiiqrstomodachi/")
        // || normalizedPath.startsWith("/privatemiiqrsmiitopia/")
        || normalizedPath.startsWith("/static/")
        || normalizedPath === "/favicon.ico"
    ) {
        return false;
    }

    return !/\.(png|jpe?g|gif|webp|svg|ico|txt|xml|json|css|js|woff2?|map)$/i.test(normalizedPath);
}

function normalizeSitePageUrl(urlLike) {
    if (!urlLike) return null;

    const baseUrl = getResolvedSiteBaseUrl();
    const candidateValue = String(urlLike).trim();
    if (!candidateValue || candidateValue.startsWith("attachment://")) {
        return null;
    }

    try {
        const parsed = new URL(candidateValue, baseUrl);
        const canTreatAsSiteUrl = candidateValue.startsWith("/")
            || parsed.origin === baseUrl.origin
            || parsed.origin === DEFAULT_SITE_ORIGIN;

        if (!canTreatAsSiteUrl || !isRelevantSitePagePath(parsed.pathname)) {
            return null;
        }

        return new URL(parsed.pathname + parsed.search + parsed.hash, baseUrl).toString();
    } catch {
        return null;
    }
}

function extractMarkdownUrls(text) {
    const matches = [];
    const normalizedText = String(text ?? "");
    const regex = /\[[^\]]+\]\((https?:\/\/[^)\s]+|\/[^)\s]+)\)/g;

    let match;
    while ((match = regex.exec(normalizedText)) !== null) {
        matches.push(match[1]);
    }

    return matches;
}

function extractBareUrls(text) {
    const matches = [];
    const normalizedText = String(text ?? "");
    const regex = /https?:\/\/[^\s<>()]+/g;

    let match;
    while ((match = regex.exec(normalizedText)) !== null) {
        matches.push(match[0]);
    }

    return matches;
}

function extractEndpointUrlFromText(text) {
    const normalizedText = String(text ?? "");
    const endpointMatch = normalizedText.match(/(?:^|\n)Endpoint:\s*(\/[^\s\n]+)/);
    return endpointMatch ? endpointMatch[1] : null;
}

function extractMiiIdFromAssetUrl(urlLike) {
    const normalized = String(urlLike ?? "").trim();
    if (!normalized) return null;

    let match = normalized.match(/^attachment:\/\/([^/.]+)\.(?:png|jpe?g|gif|webp)$/i);
    if (match) return match[1];

    match = normalized.match(/\/(?:miiImgs|privateMiiImgs|miiQRs|privateMiiQRs|miiQRsWii|privateMiiQRsWii)\/([^/.]+)\.(?:png|jpe?g|gif|webp)$/i);
    if (match) {
        try {
            return decodeURIComponent(match[1]);
        } catch {
            return match[1];
        }
    }

    return null;
}

function extractPlainFieldValue(value) {
    const normalizedValue = String(value ?? "").trim();
    if (!normalizedValue) return "";

    const markdownMatch = normalizedValue.match(/^\[([^\]]+)\]\(([^)]+)\)$/);
    if (markdownMatch) {
        return markdownMatch[1].trim();
    }

    return normalizedValue.replace(/`/g, "").trim();
}

function scoreWebhookPageUrl(url, { source = "unknown", fieldName = "", title = "" } = {}) {
    let score = 0;

    try {
        const pathname = new URL(url).pathname.toLowerCase();
        if (pathname.startsWith("/mii/")) {
            score += 100;
        } else if (pathname.startsWith("/user/")) {
            score += 90;
        } else if (pathname.startsWith("/managecategories")) {
            score += 80;
        } else if (pathname.startsWith("/search")) {
            score += 75;
        } else if (pathname.startsWith("/official")) {
            score += 70;
        } else if (pathname.startsWith("/settings")) {
            score += 65;
        } else {
            score += 50;
        }
    } catch {
        score += 10;
    }

    if (source === "existing") score += 1000;
    if (source === "footer") score += 45;
    if (source === "field") score += 25;
    if (source === "description") score += 20;
    if (source === "fallback") score += 10;

    const normalizedFieldName = String(fieldName ?? "").trim().toLowerCase();
    const normalizedTitle = String(title ?? "").trim().toLowerCase();
    if (normalizedFieldName === "mii") score += 25;
    if (normalizedFieldName === "mii name") score += 15;
    if (normalizedFieldName === "new username") score += 22;
    if (normalizedFieldName === "user" || normalizedFieldName === "username") score += 20;
    if (normalizedFieldName === "uploader" || normalizedFieldName === "uploaded by" || normalizedFieldName === "published by") score += 12;

    const isUserCentricTitle = [
        "user",
        "username",
        "password",
        "email",
        "account",
        "ban",
        "role",
        "pfp"
    ].some((token) => normalizedTitle.includes(token));
    const isUserField = [
        "new username",
        "user",
        "username",
        "existing account",
        "uploader",
        "uploaded by",
        "published by",
        "official source",
        "contributed by"
    ].includes(normalizedFieldName);

    if (isUserCentricTitle && isUserField) {
        score += 40;
    }

    return score;
}

function getTitleMappedWebhookUrl(title, description = "") {
    const normalizedTitle = String(title ?? "").trim().toLowerCase();
    const normalizedDescription = String(description ?? "");

    if (!normalizedTitle) return null;

    if (normalizedTitle.includes("mii tag")) {
        return buildSitePageUrl("/search");
    }

    if (normalizedTitle.includes("category") || normalizedTitle.includes("categories")) {
        return buildSitePageUrl("/manageCategories");
    }

    if (normalizedTitle === "server console error") {
        return buildSitePageUrl("/");
    }

    if (normalizedTitle === "password reset complete") {
        const resetUserMatch = normalizedDescription.match(/^User\s+(.+?)\s+successfully reset their password$/i);
        if (resetUserMatch) {
            return buildUserPageUrl(resetUserMatch[1]);
        }
    }

    return null;
}

function resolveRelevantEmbedUrl(embed) {
    if (!embed || typeof embed !== "object") return null;

    const candidates = [];
    const addCandidate = (urlLike, options = {}) => {
        const normalizedUrl = normalizeSitePageUrl(urlLike);
        if (!normalizedUrl) return;
        candidates.push({
            url: normalizedUrl,
            score: scoreWebhookPageUrl(normalizedUrl, {
                ...options,
                title: embed.title
            })
        });
    };

    if (embed.url) {
        addCandidate(embed.url, { source: "existing" });
    }

    const fields = Array.isArray(embed.fields) ? embed.fields : [];
    for (const field of fields) {
        const fieldName = String(field?.name ?? "");
        const fieldValue = String(field?.value ?? "");

        for (const markdownUrl of extractMarkdownUrls(fieldValue)) {
            addCandidate(markdownUrl, { source: "field", fieldName });
        }

        for (const bareUrl of extractBareUrls(fieldValue)) {
            addCandidate(bareUrl, { source: "field", fieldName });
        }
    }

    const description = String(embed.description ?? "");
    for (const markdownUrl of extractMarkdownUrls(description)) {
        addCandidate(markdownUrl, { source: "description" });
    }
    for (const bareUrl of extractBareUrls(description)) {
        addCandidate(bareUrl, { source: "description" });
    }
    addCandidate(extractEndpointUrlFromText(description), { source: "description" });

    const footerText = String(embed.footer?.text ?? "");
    for (const markdownUrl of extractMarkdownUrls(footerText)) {
        addCandidate(markdownUrl, { source: "footer" });
    }
    for (const bareUrl of extractBareUrls(footerText)) {
        addCandidate(bareUrl, { source: "footer" });
    }

    const prioritizedUserFieldNames = [
        "New Username",
        "User",
        "Username",
        "Existing Account",
        "Uploader",
        "Uploaded by",
        "Published by",
        "Official Source",
        "Contributed by"
    ];

    for (const prioritizedFieldName of prioritizedUserFieldNames) {
        const matchingField = fields.find((field) => String(field?.name ?? "").trim().toLowerCase() === prioritizedFieldName.toLowerCase());
        if (!matchingField) continue;

        const userUrl = buildUserPageUrl(extractPlainFieldValue(matchingField.value));
        addCandidate(userUrl, { source: "fallback", fieldName: prioritizedFieldName });
        if (userUrl) break;
    }

    const miiImageSources = [
        embed.image?.url,
        embed.thumbnail?.url
    ];

    for (const source of miiImageSources) {
        const inferredMiiUrl = buildMiiPageUrl(extractMiiIdFromAssetUrl(source));
        addCandidate(inferredMiiUrl, { source: "fallback", fieldName: "Mii" });
    }

    addCandidate(getTitleMappedWebhookUrl(embed.title, description), { source: "fallback" });

    if (candidates.length === 0) {
        return null;
    }

    candidates.sort((left, right) => right.score - left.score);
    return candidates[0].url;
}

function normalizeWebhookPayloadJson(payloadJson) {
    try {
        const payload = JSON.parse(payloadJson);
        if (!payload || typeof payload !== "object" || !Array.isArray(payload.embeds)) {
            return payloadJson;
        }

        payload.embeds = payload.embeds.map((embed) => {
            if (!embed || typeof embed !== "object") return embed;

            const normalizedEmbed = { ...embed };
            const resolvedUrl = resolveRelevantEmbedUrl(normalizedEmbed);
            if (resolvedUrl) {
                normalizedEmbed.url = resolvedUrl;
            }

            return normalizedEmbed;
        });

        return JSON.stringify(payload);
    } catch {
        return payloadJson;
    }
}

function normalizeAttachmentData(data) {
    if (Buffer.isBuffer(data)) return data;
    if (data instanceof Uint8Array) return Buffer.from(data);
    if (data instanceof ArrayBuffer) return Buffer.from(new Uint8Array(data));
    return data;
}

function formatConsoleArg(arg) {
    if (arg instanceof Error) {
        return arg.stack || `${arg.name}: ${arg.message}`;
    }

    if (typeof arg === "string") {
        return arg;
    }

    return inspect(arg, {
        depth: 5,
        breakLength: 120,
        maxArrayLength: 50,
        maxStringLength: 8000
    });
}

function getConsoleCallsite() {
    const stackLines = new Error().stack?.split("\n").slice(2) || [];
    const callsite = stackLines.find(line => !line.includes("monitoring.js"));
    return callsite ? callsite.trim() : null;
}

function buildConsoleErrorWebhookPayload(args) {
    const timestamp = new Date().toISOString();
    const summarySource = args.find(arg => arg instanceof Error)
        || args.find(arg => typeof arg === "string" && arg.trim())
        || args[0];

    const summary = summarySource instanceof Error
        ? `${summarySource.name}: ${summarySource.message}`
        : truncate(formatConsoleArg(summarySource ?? "console.error called"), 4096);

    const callsite = getConsoleCallsite();
    const detailLines = [
        `Timestamp: ${timestamp}`,
        `Host: ${os.hostname()}`,
        `PID: ${process.pid}`,
        `Environment: ${process.env.NODE_ENV || "development"}`,
        `Base URL: ${process.env.baseUrl || "not set"}`,
        ...(callsite ? [`Callsite: ${callsite}`] : []),
        "",
        "console.error arguments:",
        ...args.map((arg, index) => `\n[${index}] ${formatConsoleArg(arg)}`)
    ];

    return {
        payloadJson: JSON.stringify({
            embeds: [{
                type: "rich",
                title: "Server console error",
                description: truncate(summary, 4096),
                color: 0xed4245,
                fields: [
                    {
                        name: "Host",
                        value: truncate(os.hostname(), 1024),
                        inline: true
                    },
                    {
                        name: "Environment",
                        value: truncate(process.env.NODE_ENV || "development", 1024),
                        inline: true
                    },
                    {
                        name: "PID",
                        value: String(process.pid),
                        inline: true
                    },
                    ...(callsite ? [{
                        name: "Callsite",
                        value: truncate(callsite, 1024),
                        inline: false
                    }] : [])
                ],
                timestamp
            }]
        }),
        attachments: [{
            data: Buffer.from(truncate(detailLines.join("\n"), 50000), "utf8"),
            filename: `console-error-${Date.now()}.txt`,
            contentType: "text/plain; charset=utf-8"
        }]
    };
}

function appendAttachments(formData, attachments) {
    attachments.forEach((attachment, index) => {
        try {
            const normalizedData = normalizeAttachmentData(attachment?.data);
            const isReadableStream = normalizedData && typeof normalizedData.pipe === "function" && typeof normalizedData.on === "function";
            const isAcceptableData = Buffer.isBuffer(normalizedData) || typeof normalizedData === "string" || isReadableStream;

            if (!isAcceptableData) {
                rawConsoleWarn(`Skipping Discord attachment at index ${index}: unsupported data type`);
                return;
            }

            formData.append(`files[${index}]`, normalizedData, {
                filename: attachment?.filename || `attachment-${index}.bin`,
                contentType: attachment?.contentType || "application/octet-stream"
            });
        } catch (attachmentError) {
            rawConsoleError(`Error adding Discord attachment at index ${index}:`, attachmentError);
        }
    });
}

function sendWebhookPayload(payloadJson, attachments = [], options = {}) {
    const webhookUrl = getWebhookUrl(options?.webhookEnv);
    if (!webhookUrl) return Promise.resolve(false);

    return new Promise((resolve, reject) => {
        try {
            const normalizedPayloadJson = normalizeWebhookPayloadJson(payloadJson);
            const formData = new FormData();
            formData.append("payload_json", normalizedPayloadJson);
            appendAttachments(formData, attachments);

            const req = https.request({
                hostname: webhookUrl.hostname,
                port: webhookUrl.port || undefined,
                path: webhookUrl.pathname + webhookUrl.search,
                method: "POST",
                headers: formData.getHeaders()
            }, (res) => {
                res.resume();

                if (res.statusCode !== 200 && res.statusCode !== 204) {
                    reject(new Error(`Discord webhook returned status ${res.statusCode}`));
                    return;
                }

                resolve(true);
            });

            req.on("error", reject);
            formData.pipe(req);
        } catch (error) {
            reject(error);
        }
    });
}

function installConsoleErrorWebhook() {
    if (monitoringState.consoleErrorInstalled) return;

    console.error = (...args) => {
        rawConsoleError(...args);

        try {
            const { payloadJson, attachments } = buildConsoleErrorWebhookPayload(args);
            void sendWebhookPayload(payloadJson, attachments).catch((error) => {
                rawConsoleError("[monitoring] Failed to forward console.error to the webhook:", error);
            });
        } catch (error) {
            rawConsoleError("[monitoring] Failed to prepare console.error webhook payload:", error);
        }
    };

    monitoringState.consoleErrorInstalled = true;
}

function getDelayUntilNextUtcOccurrence(hourUtc, minuteUtc = 0, from = new Date()) {
    const nextOccurrence = new Date(from);
    nextOccurrence.setUTCHours(hourUtc, minuteUtc, 0, 0);

    if (nextOccurrence <= from) {
        nextOccurrence.setUTCDate(nextOccurrence.getUTCDate() + 1);
    }

    return Math.max(1000, nextOccurrence.getTime() - from.getTime());
}

function scheduleDailyWebhookReminder({ hourUtc, minuteUtc = 0, label = "daily reminder", task }) {
    if (typeof task !== "function") {
        throw new TypeError("scheduleDailyWebhookReminder requires a task function.");
    }

    let timer = null;

    const scheduleNext = () => {
        timer = setTimeout(async () => {
            try {
                await task(new Date());
            } catch (error) {
                console.error(`[monitoring] ${label} failed:`, error);
            } finally {
                scheduleNext();
            }
        }, getDelayUntilNextUtcOccurrence(hourUtc, minuteUtc));

        if (typeof timer.unref === "function") {
            timer.unref();
        }
    };

    scheduleNext();

    return () => {
        if (timer) clearTimeout(timer);
    };
}

installConsoleErrorWebhook();

export {
    rawConsoleError,
    scheduleDailyWebhookReminder,
    sendWebhookPayload
};
