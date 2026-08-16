import { spawn } from "node:child_process";


export const LTD_NATIVE_RUNTIME_PROTOCOL = "infinimii.ltd-native-runtime";
export const LTD_NATIVE_RUNTIME_PROTOCOL_VERSION = 1;
export const LTD_NATIVE_RENDER_ORCHESTRATOR_ABI_VERSION = 4;
export const LTD_NATIVE_RENDER_ORCHESTRATOR_CONTRACT_SHA256 =
    "3be14b1a393a6cc0f7ecfd72624b106550813319debac4341c3f424a3de7c1fa";

const MAX_REQUEST_BYTES = 64 * 1024;
const MAX_RESPONSE_LINE_CHARS = 4 * 1024 * 1024;
const MAX_DIAGNOSTIC_CHARS = 64 * 1024;


function appendBounded(current, chunk, maximum = MAX_DIAGNOSTIC_CHARS) {
    if (current.length >= maximum) return current;
    return (current + String(chunk)).slice(0, maximum);
}


function isRecord(value) {
    return value !== null && typeof value === "object" && !Array.isArray(value);
}


export function hasPinnedNativeRenderOrchestrator(modules) {
    const orchestrator = isRecord(modules) ? modules.render_orchestrator : null;
    return isRecord(orchestrator)
        && orchestrator.linked === true
        && orchestrator.abi_matches === true
        && orchestrator.abi_version === LTD_NATIVE_RENDER_ORCHESTRATOR_ABI_VERSION
        && orchestrator.contract_matches === true
        && orchestrator.contract_sha256 === LTD_NATIVE_RENDER_ORCHESTRATOR_CONTRACT_SHA256
        && orchestrator.activation_ready === true;
}


function validateEnvelope(message, { requestId, operation }) {
    return isRecord(message)
        && message.protocol === LTD_NATIVE_RUNTIME_PROTOCOL
        && message.version === LTD_NATIVE_RUNTIME_PROTOCOL_VERSION
        && message.request_id === requestId
        && message.op === operation
        && typeof message.ok === "boolean";
}


export class NativeLtdRuntimeError extends Error {
    constructor(code, message, options = {}) {
        super(message, options);
        this.name = "NativeLtdRuntimeError";
        this.code = code;
        this.workerUnavailable = options.workerUnavailable === true;
        if (typeof options.diagnostics === "string" && options.diagnostics) {
            this.diagnostics = options.diagnostics.slice(-MAX_DIAGNOSTIC_CHARS);
        }
    }
}


class NativeLtdRuntimeProcess {
    constructor({ command, commandArgs, cwd, startupTimeoutMs, nextRequestId }) {
        this.command = command;
        this.commandArgs = commandArgs;
        this.cwd = cwd;
        this.startupTimeoutMs = startupTimeoutMs;
        this.nextRequestId = nextRequestId;
        this.child = null;
        this.healthy = true;
        this.ready = false;
        this.readiness = null;
        this.stdoutBuffer = "";
        this.workerStderr = "";
        this.pending = null;
        this.handshake = null;
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
            child = spawn(this.command, this.commandArgs, {
                cwd: this.cwd,
                shell: false,
                windowsHide: true,
                stdio: ["pipe", "pipe", "pipe"]
            });
        } catch (error) {
            this.#fail(new NativeLtdRuntimeError(
                "NATIVE_RUNTIME_START_FAILED",
                "Could not start the native LTD runtime.",
                {
                    cause: error,
                    diagnostics: `${error?.name || "Error"}: ${error?.message || error}`,
                    workerUnavailable: true
                }
            ));
            return await this.startPromise;
        }
        this.child = child;
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
        child.once("error", error => this.#fail(new NativeLtdRuntimeError(
            "NATIVE_RUNTIME_START_FAILED",
            "The native LTD runtime process failed.",
            {
                cause: error,
                diagnostics: `${error?.name || "Error"}: ${error?.message || error}`,
                workerUnavailable: true
            }
        )));
        child.once("close", (code, signal) => this.#fail(new NativeLtdRuntimeError(
            "NATIVE_RUNTIME_EXITED",
            "The native LTD runtime exited unexpectedly.",
            {
                diagnostics: `exitCode=${code ?? "unknown"}; signal=${signal || "none"}\n${this.workerStderr}`,
                workerUnavailable: true
            }
        )));
        this.startTimer = setTimeout(() => this.#fail(new NativeLtdRuntimeError(
            "NATIVE_RUNTIME_START_TIMEOUT",
            "The native LTD runtime did not complete its handshake in time.",
            { diagnostics: this.workerStderr, workerUnavailable: true }
        )), this.startupTimeoutMs);
        this.#beginHandshake("hello");
        return await this.startPromise;
    }

    #writeRequest(operation, requestId, fields = {}) {
        const request = {
            ...fields,
            protocol: LTD_NATIVE_RUNTIME_PROTOCOL,
            version: LTD_NATIVE_RUNTIME_PROTOCOL_VERSION,
            request_id: requestId,
            op: operation
        };
        const encoded = `${JSON.stringify(request)}\n`;
        if (Buffer.byteLength(encoded, "utf8") > MAX_REQUEST_BYTES) {
            throw new NativeLtdRuntimeError(
                "NATIVE_RUNTIME_REQUEST_TOO_LARGE",
                "The native LTD runtime request exceeds its 64 KiB protocol limit."
            );
        }
        this.child.stdin.write(encoded, "utf8", error => {
            if (error) this.#fail(new NativeLtdRuntimeError(
                "NATIVE_RUNTIME_WRITE_FAILED",
                "Could not send a request to the native LTD runtime.",
                {
                    cause: error,
                    diagnostics: `${error?.name || "Error"}: ${error?.message || error}`,
                    workerUnavailable: true
                }
            ));
        });
    }

    #beginHandshake(operation) {
        const requestId = this.nextRequestId();
        this.handshake = { operation, requestId };
        try {
            this.#writeRequest(operation, requestId);
        } catch (error) {
            this.#fail(error);
        }
    }

    #onStdout(chunk) {
        if (!this.healthy) return;
        this.stdoutBuffer += chunk;
        if (this.stdoutBuffer.length > MAX_RESPONSE_LINE_CHARS && !this.stdoutBuffer.includes("\n")) {
            this.#fail(new NativeLtdRuntimeError(
                "NATIVE_RUNTIME_PROTOCOL_ERROR",
                "The native LTD runtime emitted an oversized protocol line.",
                { workerUnavailable: true }
            ));
            return;
        }
        while (this.healthy) {
            const newline = this.stdoutBuffer.indexOf("\n");
            if (newline < 0) break;
            const line = this.stdoutBuffer.slice(0, newline);
            this.stdoutBuffer = this.stdoutBuffer.slice(newline + 1);
            if (line.length > MAX_RESPONSE_LINE_CHARS) {
                this.#fail(new NativeLtdRuntimeError(
                    "NATIVE_RUNTIME_PROTOCOL_ERROR",
                    "The native LTD runtime emitted an oversized protocol line.",
                    { workerUnavailable: true }
                ));
                return;
            }
            let message;
            try {
                message = JSON.parse(line);
            } catch (error) {
                this.#fail(new NativeLtdRuntimeError(
                    "NATIVE_RUNTIME_PROTOCOL_ERROR",
                    "The native LTD runtime emitted invalid JSON.",
                    {
                        cause: error,
                        diagnostics: line.slice(-4096),
                        workerUnavailable: true
                    }
                ));
                return;
            }
            if (this.handshake) {
                this.#consumeHandshake(message);
                continue;
            }
            if (!this.pending || !validateEnvelope(message, {
                requestId: this.pending.requestId,
                operation: this.pending.operation
            })) {
                this.#fail(new NativeLtdRuntimeError(
                    "NATIVE_RUNTIME_PROTOCOL_ERROR",
                    "The native LTD runtime returned an unexpected response.",
                    { workerUnavailable: true }
                ));
                return;
            }
            const pending = this.pending;
            this.pending = null;
            clearTimeout(pending.timer);
            this.#unrefChild();
            if (message.ok) {
                if (!("result" in message)) {
                    this.#fail(new NativeLtdRuntimeError(
                        "NATIVE_RUNTIME_PROTOCOL_ERROR",
                        "The native LTD runtime omitted its result.",
                        { workerUnavailable: true }
                    ));
                    return;
                }
                pending.resolve(message.result);
            } else {
                const code = typeof message?.error?.code === "string"
                    ? message.error.code
                    : "NATIVE_RUNTIME_REQUEST_FAILED";
                const detail = typeof message?.error?.message === "string"
                    ? message.error.message
                    : "The native LTD runtime rejected the request.";
                pending.reject(new NativeLtdRuntimeError(code, detail, {
                    diagnostics: this.workerStderr,
                    workerUnavailable: false
                }));
            }
        }
    }

    #consumeHandshake(message) {
        const handshake = this.handshake;
        if (!validateEnvelope(message, {
            requestId: handshake.requestId,
            operation: handshake.operation
        }) || !message.ok || !isRecord(message.result)) {
            this.#fail(new NativeLtdRuntimeError(
                "NATIVE_RUNTIME_PROTOCOL_ERROR",
                "The native LTD runtime handshake did not match.",
                { workerUnavailable: true }
            ));
            return;
        }
        if (handshake.operation === "hello") {
            if (
                !Number.isInteger(message.result.native_process_id)
                || message.result.native_process_id < 1
                || message.result.process_model !== "persistent-stdin-stdout-jsonl"
                || typeof message.result.runtime_version !== "string"
                || !message.result.runtime_version
            ) {
                this.#fail(new NativeLtdRuntimeError(
                    "NATIVE_RUNTIME_PROTOCOL_ERROR",
                    "The native LTD runtime hello response is invalid.",
                    { workerUnavailable: true }
                ));
                return;
            }
            this.#beginHandshake("readiness");
            return;
        }
        if (
            handshake.operation !== "readiness"
            || message.result.protocol_ready !== true
            || typeof message.result.activation_ready !== "boolean"
            || !hasPinnedNativeRenderOrchestrator(message.result.render_modules)
        ) {
            this.#fail(new NativeLtdRuntimeError(
                "NATIVE_RUNTIME_PROTOCOL_ERROR",
                "The native LTD runtime readiness response is invalid.",
                { workerUnavailable: true }
            ));
            return;
        }
        this.readiness = message.result;
        this.handshake = null;
        this.ready = true;
        clearTimeout(this.startTimer);
        this.#unrefChild();
        this.startResolve?.();
        this.startResolve = null;
        this.startReject = null;
    }

    #unrefChild() {
        this.child?.unref?.();
        this.child?.stdin?.unref?.();
        this.child?.stdout?.unref?.();
        this.child?.stderr?.unref?.();
    }

    #fail(error) {
        if (!this.healthy) return;
        this.healthy = false;
        this.ready = false;
        clearTimeout(this.startTimer);
        this.handshake = null;
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

    async execute(fields, timeoutMs) {
        await this.start();
        if (!this.healthy || !this.ready || !this.child?.stdin?.writable) {
            throw new NativeLtdRuntimeError(
                "NATIVE_RUNTIME_UNAVAILABLE",
                "The native LTD runtime is unavailable.",
                { diagnostics: this.workerStderr, workerUnavailable: true }
            );
        }
        if (!isRecord(fields) || typeof fields.op !== "string" || !fields.op) {
            throw new TypeError("a native LTD runtime operation is required");
        }
        if (
            fields.op === "render_ltd"
            && this.readiness?.activation_ready !== true
        ) {
            throw new NativeLtdRuntimeError(
                "NATIVE_RUNTIME_NOT_READY",
                "This native LTD runtime worker is not activated for rendering.",
                { workerUnavailable: true }
            );
        }
        if (this.pending) throw new Error("a native LTD runtime process cannot run concurrent requests");
        const operation = fields.op;
        const requestId = this.nextRequestId();
        return await new Promise((resolve, reject) => {
            this.child.ref?.();
            this.child.stdin.ref?.();
            this.child.stdout.ref?.();
            this.child.stderr.ref?.();
            const timer = setTimeout(() => this.#fail(new NativeLtdRuntimeError(
                "NATIVE_RUNTIME_REQUEST_TIMEOUT",
                "The native LTD runtime timed out.",
                { diagnostics: this.workerStderr, workerUnavailable: true }
            )), timeoutMs);
            this.pending = { operation, requestId, resolve, reject, timer };
            try {
                const { protocol: _protocol, version: _version, request_id: _requestId, ...payload } = fields;
                this.#writeRequest(operation, requestId, payload);
            } catch (error) {
                clearTimeout(timer);
                this.pending = null;
                this.#unrefChild();
                reject(error);
            }
        });
    }

    close() {
        this.#fail(new NativeLtdRuntimeError(
            "NATIVE_RUNTIME_CLOSED",
            "The native LTD runtime was closed.",
            { workerUnavailable: true }
        ));
    }
}


export class NativeLtdRuntimePool {
    constructor({
        command,
        commandArgs = [],
        cwd,
        maxWorkers = 2,
        startupTimeoutMs = 30_000
    }) {
        if (typeof command !== "string" || !command) throw new TypeError("command is required");
        if (!Array.isArray(commandArgs) || commandArgs.some(value => typeof value !== "string")) {
            throw new TypeError("commandArgs must contain only strings");
        }
        if (typeof cwd !== "string" || !cwd) throw new TypeError("cwd is required");
        if (!Number.isInteger(maxWorkers) || maxWorkers < 1) throw new TypeError("maxWorkers must be positive");
        this.options = { command, commandArgs: [...commandArgs], cwd, startupTimeoutMs };
        this.maxWorkers = maxWorkers;
        this.workers = new Set();
        this.idle = [];
        this.waiters = [];
        this.requestSequence = 0;
        this.closed = false;
    }

    #nextRequestId() {
        return `${process.pid}-${Date.now().toString(36)}-${++this.requestSequence}`;
    }

    #newWorker() {
        const worker = new NativeLtdRuntimeProcess({
            ...this.options,
            nextRequestId: () => this.#nextRequestId()
        });
        this.workers.add(worker);
        return worker;
    }

    async #acquire() {
        if (this.closed) {
            throw new NativeLtdRuntimeError(
                "NATIVE_RUNTIME_POOL_CLOSED",
                "The native LTD runtime pool is closed.",
                { workerUnavailable: true }
            );
        }
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
                waiter.reject(new NativeLtdRuntimeError(
                    "NATIVE_RUNTIME_POOL_CLOSED",
                    "The native LTD runtime pool is closed.",
                    { workerUnavailable: true }
                ));
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
        try {
            const result = await worker.execute(request, timeoutMs);
            this.#release(worker, true);
            return result;
        } catch (error) {
            this.#release(worker, error?.workerUnavailable !== true);
            throw error;
        }
    }

    close() {
        if (this.closed) return;
        this.closed = true;
        for (const waiter of this.waiters.splice(0)) {
            waiter.reject(new NativeLtdRuntimeError(
                "NATIVE_RUNTIME_POOL_CLOSED",
                "The native LTD runtime pool is closed.",
                { workerUnavailable: true }
            ));
        }
        for (const worker of this.workers) worker.close();
        this.workers.clear();
        this.idle.length = 0;
    }
}
