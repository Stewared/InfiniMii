import { spawn } from "node:child_process";


export const LTD_RENDER_WORKER_PROTOCOL = "infinimii-ltd-render-worker";
export const LTD_RENDER_WORKER_PROTOCOL_VERSION = 1;

const MAX_PROTOCOL_LINE_CHARS = 1024 * 1024;
const MAX_WORKER_DIAGNOSTIC_CHARS = 64 * 1024;


function appendBounded(current, chunk, maximum = MAX_WORKER_DIAGNOSTIC_CHARS) {
    if (current.length >= maximum) return current;
    return (current + String(chunk)).slice(0, maximum);
}


export class PersistentRenderWorkerError extends Error {
    constructor(code, message, options = {}) {
        super(message, options);
        this.name = "PersistentRenderWorkerError";
        this.code = code;
        this.workerUnavailable = true;
        if (typeof options.diagnostics === "string" && options.diagnostics) {
            this.diagnostics = options.diagnostics.slice(-MAX_WORKER_DIAGNOSTIC_CHARS);
        }
    }
}


function validateReadyMessage(message) {
    return message !== null
        && typeof message === "object"
        && !Array.isArray(message)
        && message.protocol === LTD_RENDER_WORKER_PROTOCOL
        && message.protocol_version === LTD_RENDER_WORKER_PROTOCOL_VERSION
        && message.kind === "ready"
        && message.native === false;
}


function validateResponse(message, requestId) {
    return message !== null
        && typeof message === "object"
        && !Array.isArray(message)
        && message.protocol === LTD_RENDER_WORKER_PROTOCOL
        && message.protocol_version === LTD_RENDER_WORKER_PROTOCOL_VERSION
        && message.request_id === requestId
        && Number.isInteger(message.code)
        && typeof message.stdout === "string"
        && typeof message.stderr === "string"
        && typeof message.restart_required === "boolean";
}


class PersistentRenderWorker {
    constructor({ command, workerScript, cwd, startupTimeoutMs }) {
        this.command = command;
        this.workerScript = workerScript;
        this.cwd = cwd;
        this.startupTimeoutMs = startupTimeoutMs;
        this.child = null;
        this.healthy = true;
        this.ready = false;
        this.stdoutBuffer = "";
        this.workerStderr = "";
        this.pending = null;
        this.startPromise = null;
        this.startResolve = null;
        this.startReject = null;
        this.startTimer = null;
    }

    async start() {
        if (this.ready) return;
        if (this.startPromise) return await this.startPromise;
        this.startPromise = new Promise((resolve, reject) => {
            this.startResolve = resolve;
            this.startReject = reject;
        });
        let child;
        try {
            child = spawn(this.command, [this.workerScript], {
                cwd: this.cwd,
                shell: false,
                windowsHide: true,
                stdio: ["pipe", "pipe", "pipe"]
            });
        } catch (error) {
            this.#fail(new PersistentRenderWorkerError(
                "WORKER_START_FAILED",
                "Could not start the persistent LTD render worker.",
                { cause: error, diagnostics: `${error?.name || "Error"}: ${error?.message || error}` }
            ));
            return await this.startPromise;
        }
        this.child = child;
        // A warm worker must not keep a command-line/test process alive after
        // all real work is complete. Request/startup timers remain referenced
        // while a caller is actively awaiting a response.
        child.unref?.();
        child.stdin.unref?.();
        child.stdout.unref?.();
        child.stderr.unref?.();
        child.stdout.setEncoding("utf8");
        child.stderr.setEncoding("utf8");
        child.stdout.on("data", chunk => this.#onStdout(chunk));
        child.stderr.on("data", chunk => {
            this.workerStderr = appendBounded(this.workerStderr, chunk);
        });
        child.once("error", error => this.#fail(new PersistentRenderWorkerError(
            "WORKER_START_FAILED",
            "The persistent LTD render worker process failed.",
            { cause: error, diagnostics: `${error?.name || "Error"}: ${error?.message || error}` }
        )));
        child.once("close", (code, signal) => this.#fail(new PersistentRenderWorkerError(
            "WORKER_EXITED",
            "The persistent LTD render worker exited unexpectedly.",
            { diagnostics: `exitCode=${code ?? "unknown"}; signal=${signal || "none"}\n${this.workerStderr}` }
        )));
        this.startTimer = setTimeout(() => this.#fail(new PersistentRenderWorkerError(
            "WORKER_START_TIMEOUT",
            "The persistent LTD render worker did not become ready in time.",
            { diagnostics: this.workerStderr }
        )), this.startupTimeoutMs);
        return await this.startPromise;
    }

    #onStdout(chunk) {
        if (!this.healthy) return;
        this.stdoutBuffer += chunk;
        if (this.stdoutBuffer.length > MAX_PROTOCOL_LINE_CHARS && !this.stdoutBuffer.includes("\n")) {
            this.#fail(new PersistentRenderWorkerError(
                "WORKER_PROTOCOL_ERROR",
                "The persistent LTD render worker emitted an oversized protocol line."
            ));
            return;
        }
        while (this.healthy) {
            const newline = this.stdoutBuffer.indexOf("\n");
            if (newline < 0) break;
            const line = this.stdoutBuffer.slice(0, newline);
            this.stdoutBuffer = this.stdoutBuffer.slice(newline + 1);
            if (line.length > MAX_PROTOCOL_LINE_CHARS) {
                this.#fail(new PersistentRenderWorkerError(
                    "WORKER_PROTOCOL_ERROR",
                    "The persistent LTD render worker emitted an oversized protocol line."
                ));
                return;
            }
            let message;
            try {
                message = JSON.parse(line);
            } catch (error) {
                this.#fail(new PersistentRenderWorkerError(
                    "WORKER_PROTOCOL_ERROR",
                    "The persistent LTD render worker emitted invalid JSON.",
                    { cause: error, diagnostics: line.slice(-4096) }
                ));
                return;
            }
            if (!this.ready) {
                if (!validateReadyMessage(message)) {
                    this.#fail(new PersistentRenderWorkerError(
                        "WORKER_PROTOCOL_ERROR",
                        "The persistent LTD render worker handshake did not match."
                    ));
                    return;
                }
                this.ready = true;
                clearTimeout(this.startTimer);
                this.startResolve?.();
                this.startResolve = null;
                this.startReject = null;
                continue;
            }
            if (!this.pending || !validateResponse(message, this.pending.requestId)) {
                this.#fail(new PersistentRenderWorkerError(
                    "WORKER_PROTOCOL_ERROR",
                    "The persistent LTD render worker returned an unexpected response."
                ));
                return;
            }
            const pending = this.pending;
            this.pending = null;
            clearTimeout(pending.timer);
            // The worker is allowed to stay unreferenced while idle, but an
            // in-flight render must keep even a short-lived Node caller alive
            // until its response has been consumed.
            this.child?.unref?.();
            this.child?.stdin?.unref?.();
            this.child?.stdout?.unref?.();
            this.child?.stderr?.unref?.();
            pending.resolve({
                code: message.code,
                stdout: message.stdout,
                stderr: message.stderr,
                elapsedMs: Number(message.elapsed_ms),
                restartWorker: message.restart_required,
                persistentWorker: true
            });
        }
    }

    #fail(error) {
        if (!this.healthy) return;
        this.healthy = false;
        this.ready = false;
        clearTimeout(this.startTimer);
        if (this.startReject) this.startReject(error);
        this.startResolve = null;
        this.startReject = null;
        if (this.pending) {
            clearTimeout(this.pending.timer);
            this.pending.reject(error);
            this.pending = null;
        }
        if (this.child && !this.child.killed) this.child.kill("SIGKILL");
    }

    async execute(request, timeoutMs) {
        await this.start();
        if (!this.healthy || !this.ready || !this.child?.stdin?.writable) {
            throw new PersistentRenderWorkerError(
                "WORKER_UNAVAILABLE",
                "The persistent LTD render worker is unavailable.",
                { diagnostics: this.workerStderr }
            );
        }
        if (this.pending) throw new Error("a persistent render worker cannot run concurrent requests");
        const encoded = `${JSON.stringify(request)}\n`;
        if (encoded.length > MAX_PROTOCOL_LINE_CHARS) {
            throw new PersistentRenderWorkerError(
                "WORKER_PROTOCOL_ERROR",
                "The persistent LTD render request is too large."
            );
        }
        return await new Promise((resolve, reject) => {
            this.child.ref?.();
            this.child.stdin.ref?.();
            this.child.stdout.ref?.();
            this.child.stderr.ref?.();
            const timer = setTimeout(() => this.#fail(new PersistentRenderWorkerError(
                "WORKER_REQUEST_TIMEOUT",
                "The persistent LTD render worker timed out.",
                { diagnostics: this.workerStderr }
            )), timeoutMs);
            this.pending = { requestId: request.request_id, resolve, reject, timer };
            this.child.stdin.write(encoded, "utf8", error => {
                if (error) this.#fail(new PersistentRenderWorkerError(
                    "WORKER_WRITE_FAILED",
                    "Could not send a request to the persistent LTD render worker.",
                    { cause: error, diagnostics: `${error?.name || "Error"}: ${error?.message || error}` }
                ));
            });
        });
    }

    close() {
        this.#fail(new PersistentRenderWorkerError(
            "WORKER_CLOSED",
            "The persistent LTD render worker was closed."
        ));
    }
}


export class PersistentRenderWorkerPool {
    constructor({
        command,
        workerScript,
        cwd,
        maxWorkers = 2,
        startupTimeoutMs = 30_000
    }) {
        if (typeof command !== "string" || !command) throw new TypeError("command is required");
        if (typeof workerScript !== "string" || !workerScript) throw new TypeError("workerScript is required");
        if (typeof cwd !== "string" || !cwd) throw new TypeError("cwd is required");
        if (!Number.isInteger(maxWorkers) || maxWorkers < 1) throw new TypeError("maxWorkers must be positive");
        this.options = { command, workerScript, cwd, startupTimeoutMs };
        this.maxWorkers = maxWorkers;
        this.workers = new Set();
        this.idle = [];
        this.waiters = [];
        this.requestSequence = 0;
        this.closed = false;
    }

    #newWorker() {
        const worker = new PersistentRenderWorker(this.options);
        this.workers.add(worker);
        return worker;
    }

    async #acquire() {
        if (this.closed) throw new PersistentRenderWorkerError("WORKER_POOL_CLOSED", "Worker pool is closed.");
        while (this.idle.length) {
            const worker = this.idle.pop();
            if (worker.healthy) return worker;
            this.workers.delete(worker);
        }
        if (this.workers.size < this.maxWorkers) return this.#newWorker();
        return await new Promise((resolve, reject) => this.waiters.push({ resolve, reject }));
    }

    #release(worker, reusable) {
        if (!reusable || !worker.healthy || this.closed) {
            this.workers.delete(worker);
            worker.close();
        }
        const waiter = this.waiters.shift();
        if (waiter) {
            if (this.closed) {
                waiter.reject(new PersistentRenderWorkerError("WORKER_POOL_CLOSED", "Worker pool is closed."));
            } else if (reusable && worker.healthy) {
                waiter.resolve(worker);
            } else {
                waiter.resolve(this.#newWorker());
            }
        } else if (reusable && worker.healthy && !this.closed) {
            this.idle.push(worker);
        }
    }

    async run(request, { timeoutMs = 120_000 } = {}) {
        const worker = await this.#acquire();
        const requestId = `${process.pid}-${Date.now().toString(36)}-${++this.requestSequence}`;
        try {
            const result = await worker.execute({
                ...request,
                protocol: LTD_RENDER_WORKER_PROTOCOL,
                protocol_version: LTD_RENDER_WORKER_PROTOCOL_VERSION,
                request_id: requestId
            }, timeoutMs);
            this.#release(worker, !result.restartWorker);
            return result;
        } catch (error) {
            this.#release(worker, false);
            throw error;
        }
    }

    close() {
        if (this.closed) return;
        this.closed = true;
        for (const waiter of this.waiters.splice(0)) {
            waiter.reject(new PersistentRenderWorkerError("WORKER_POOL_CLOSED", "Worker pool is closed."));
        }
        for (const worker of this.workers) worker.close();
        this.workers.clear();
        this.idle.length = 0;
    }
}
