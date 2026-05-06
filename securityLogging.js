import fs from "fs";
import path from "path";

const DAY_MS = 24 * 60 * 60 * 1000;
const DEFAULT_RETENTION_DAYS = 21;
const LOG_FILE_NAME_PATTERN = /^requests-(\d{4}-\d{2}-\d{2})\.log$/;
const LOG_HEADER_LINE = [
    "timestamp_utc",
    "ip",
    "username",
    "method",
    "endpoint",
    "status",
    "outcome",
    "duration_ms",
    "content_length",
    "referer",
    "user_agent"
].join("\t");

function getUtcDayKey(date) {
    return date.toISOString().slice(0, 10);
}

function getUtcDayStartMs(date) {
    return Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate());
}

function getLogFileName(dayKey) {
    return `requests-${dayKey}.log`;
}

function sanitizeLogField(value, {
    fallback = "-",
    maxLength = 512
} = {}) {
    if (value === null || value === undefined) {
        return fallback;
    }

    const normalized = String(value)
        .replace(/\t/g, "    ")
        .replace(/[\r\n]+/g, " ")
        .trim();

    if (!normalized) {
        return fallback;
    }

    if (normalized.length <= maxLength) {
        return normalized;
    }

    return `${normalized.slice(0, Math.max(0, maxLength - 3))}...`;
}

function formatDurationMs(durationMs) {
    const numericDuration = Number(durationMs);
    if (!Number.isFinite(numericDuration) || numericDuration < 0) {
        return "-";
    }

    return String(Math.round(numericDuration));
}

function getRequestEndpoint(req) {
    const originalUrl = typeof req?.originalUrl === "string" ? req.originalUrl : "";
    const [pathOnly] = originalUrl.split("?");
    if (pathOnly) {
        return pathOnly;
    }

    const directPath = typeof req?.path === "string" ? req.path : "";
    return directPath || "/";
}

async function fileHasContents(filePath) {
    try {
        const stats = await fs.promises.stat(filePath);
        return stats.size > 0;
    } catch (error) {
        if (error?.code === "ENOENT") {
            return false;
        }
        throw error;
    }
}

function waitForDrain(stream) {
    return new Promise((resolve, reject) => {
        const handleDrain = () => {
            stream.off("error", handleError);
            resolve();
        };
        const handleError = (error) => {
            stream.off("drain", handleDrain);
            reject(error);
        };

        stream.once("drain", handleDrain);
        stream.once("error", handleError);
    });
}

function endStream(stream) {
    return new Promise((resolve, reject) => {
        stream.end((error) => {
            if (error) {
                reject(error);
                return;
            }
            resolve();
        });
    });
}

export class DailyTabSeparatedRequestLogger {
    constructor({
        logDirPath,
        retentionDays = DEFAULT_RETENTION_DAYS,
        consoleLike = console,
        now = () => new Date()
    }) {
        this.logDirPath = logDirPath;
        this.retentionDays = Math.max(1, Math.floor(Number(retentionDays) || DEFAULT_RETENTION_DAYS));
        this.consoleLike = consoleLike;
        this.now = now;
        this.currentDayKey = "";
        this.currentStream = null;
        this.writeQueue = Promise.resolve();
        this.ensureDirectoryPromise = null;
        this.cleanupTimer = null;
    }

    async initialize() {
        await this.ensureLogDirectory();
        await this.cleanupExpiredLogs();
    }

    startRetentionCleanupTimer({
        intervalMs = DAY_MS
    } = {}) {
        if (this.cleanupTimer) {
            return this.cleanupTimer;
        }

        const normalizedIntervalMs = Math.max(1, Math.floor(Number(intervalMs) || DAY_MS));
        this.cleanupTimer = setInterval(() => {
            this.cleanupExpiredLogs().catch((error) => {
                this.consoleLike.error("[requestLogs] Failed to clean up expired request logs:", error);
            });
        }, normalizedIntervalMs);
        this.cleanupTimer.unref?.();
        return this.cleanupTimer;
    }

    stopRetentionCleanupTimer() {
        if (!this.cleanupTimer) {
            return;
        }

        clearInterval(this.cleanupTimer);
        this.cleanupTimer = null;
    }

    async close() {
        this.stopRetentionCleanupTimer();
        await this.writeQueue.catch(() => {});

        if (!this.currentStream) {
            return;
        }

        const stream = this.currentStream;
        this.currentStream = null;
        this.currentDayKey = "";
        await endStream(stream);
    }

    appendEntry(entry) {
        const queuedWrite = this.writeQueue.then(async () => {
            await this.ensureLogDirectory();

            const timestamp = entry?.timestamp instanceof Date ? entry.timestamp : this.now();
            await this.rotateStreamIfNeeded(timestamp);
            await this.writeToCurrentStream(this.formatEntry({
                ...entry,
                timestamp
            }));
        });

        this.writeQueue = queuedWrite.catch((error) => {
            this.consoleLike.error("[requestLogs] Failed to append request log entry:", error);
        });

        return queuedWrite;
    }

    async cleanupExpiredLogs(referenceDate = this.now()) {
        await this.ensureLogDirectory();

        const entries = await fs.promises.readdir(this.logDirPath, { withFileTypes: true });
        const cutoffDayStartMs = getUtcDayStartMs(referenceDate) - (this.retentionDays * DAY_MS);

        await Promise.all(entries.map(async (entry) => {
            if (!entry.isFile()) {
                return;
            }

            const match = LOG_FILE_NAME_PATTERN.exec(entry.name);
            if (!match) {
                return;
            }

            const logDate = new Date(`${match[1]}T00:00:00.000Z`);
            if (Number.isNaN(logDate.getTime())) {
                return;
            }

            if (logDate.getTime() < cutoffDayStartMs) {
                await fs.promises.unlink(path.join(this.logDirPath, entry.name)).catch((error) => {
                    if (error?.code !== "ENOENT") {
                        throw error;
                    }
                });
            }
        }));
    }

    async ensureLogDirectory() {
        if (!this.ensureDirectoryPromise) {
            this.ensureDirectoryPromise = fs.promises.mkdir(this.logDirPath, { recursive: true });
        }

        await this.ensureDirectoryPromise;
    }

    formatEntry(entry) {
        const fields = [
            sanitizeLogField(entry.timestamp.toISOString(), { maxLength: 64 }),
            sanitizeLogField(entry.ip, { maxLength: 120 }),
            sanitizeLogField(entry.username, { maxLength: 120 }),
            sanitizeLogField(entry.method, { maxLength: 16 }),
            sanitizeLogField(entry.endpoint, { maxLength: 512 }),
            sanitizeLogField(entry.status, { maxLength: 16 }),
            sanitizeLogField(entry.outcome, { maxLength: 32 }),
            sanitizeLogField(formatDurationMs(entry.durationMs), { maxLength: 16 }),
            sanitizeLogField(entry.contentLength, { maxLength: 32 }),
            sanitizeLogField(entry.referer, { maxLength: 512 }),
            sanitizeLogField(entry.userAgent, { maxLength: 512 })
        ];

        return `${fields.join("\t")}\n`;
    }

    async rotateStreamIfNeeded(referenceDate) {
        const nextDayKey = getUtcDayKey(referenceDate);
        if (this.currentStream && this.currentDayKey === nextDayKey) {
            return;
        }

        const nextFilePath = path.join(this.logDirPath, getLogFileName(nextDayKey));
        const shouldWriteHeader = !(await fileHasContents(nextFilePath));
        const previousStream = this.currentStream;

        this.currentStream = null;
        this.currentDayKey = "";

        if (previousStream) {
            await endStream(previousStream);
        }

        const nextStream = fs.createWriteStream(nextFilePath, {
            flags: "a",
            encoding: "utf8"
        });
        nextStream.on("error", (error) => {
            this.consoleLike.error("[requestLogs] Log stream error:", error);
        });

        this.currentStream = nextStream;
        this.currentDayKey = nextDayKey;

        if (shouldWriteHeader) {
            await this.writeToCurrentStream(`${LOG_HEADER_LINE}\n`);
        }
    }

    async writeToCurrentStream(text) {
        if (!this.currentStream) {
            throw new Error("Request log stream is not initialized.");
        }

        if (!this.currentStream.write(text, "utf8")) {
            await waitForDrain(this.currentStream);
        }
    }
}

export function createRequestLoggingMiddleware({
    requestLogger,
    getClientIpAddress,
    consoleLike = console
}) {
    return (req, res, next) => {
        const startedAtNs = process.hrtime.bigint();
        let didFlush = false;

        const flushLog = (outcome) => {
            if (didFlush) {
                return;
            }

            didFlush = true;

            const durationMs = Number(process.hrtime.bigint() - startedAtNs) / 1_000_000;
            void requestLogger.appendEntry({
                timestamp: new Date(),
                ip: getClientIpAddress(req),
                username: req?.requestLogContext?.username ?? req?.user?.username,
                method: req.method,
                endpoint: getRequestEndpoint(req),
                status: res.statusCode,
                outcome,
                durationMs,
                contentLength: res.getHeader("content-length"),
                referer: req.get("referer"),
                userAgent: req.get("user-agent")
            }).catch((error) => {
                consoleLike.error("[requestLogs] Failed to queue request log entry:", error);
            });
        };

        res.on("finish", () => {
            flushLog("finish");
        });

        res.on("close", () => {
            if (!res.writableEnded) {
                flushLog("aborted");
            }
        });

        next();
    };
}

export function setRequestLogContext(req, context = {}) {
    if (!req || typeof req !== "object") {
        return;
    }

    const existingContext = req.requestLogContext && typeof req.requestLogContext === "object"
        ? req.requestLogContext
        : {};

    req.requestLogContext = {
        ...existingContext,
        ...context
    };
}
