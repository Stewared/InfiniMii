import FormData from "form-data";
import https from "https";
import os from "os";
import { inspect } from "node:util";

const monitoringState = globalThis.__infinimiiMonitoringState ?? {
    consoleErrorInstalled: false,
    invalidWebhookUrlLogged: false,
    rawConsoleError: console.error.bind(console),
    rawConsoleWarn: console.warn.bind(console)
};

globalThis.__infinimiiMonitoringState = monitoringState;

const rawConsoleError = monitoringState.rawConsoleError;
const rawConsoleWarn = monitoringState.rawConsoleWarn;

function truncate(text, maxLength) {
    const stringValue = String(text ?? "");
    if (stringValue.length <= maxLength) return stringValue;

    const suffix = "...(truncated)";
    return `${stringValue.slice(0, Math.max(0, maxLength - suffix.length))}${suffix}`;
}

function getWebhookUrl() {
    const configuredHookUrl = typeof process.env.hookUrl === "string"
        ? process.env.hookUrl.trim()
        : "";

    if (!configuredHookUrl) return null;

    try {
        return new URL(configuredHookUrl);
    } catch (error) {
        if (!monitoringState.invalidWebhookUrlLogged) {
            monitoringState.invalidWebhookUrlLogged = true;
            rawConsoleError("[monitoring] Invalid hookUrl. Webhook notifications are disabled.", error);
        }
        return null;
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

function sendWebhookPayload(payloadJson, attachments = []) {
    const webhookUrl = getWebhookUrl();
    if (!webhookUrl) return Promise.resolve(false);

    return new Promise((resolve, reject) => {
        try {
            const formData = new FormData();
            formData.append("payload_json", payloadJson);
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
