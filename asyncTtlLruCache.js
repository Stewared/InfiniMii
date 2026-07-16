export class AsyncTtlLruCache {
    #entries = new Map();
    #maximumEntries;
    #now;
    #ttlMs;

    constructor({ ttlMs, maximumEntries, now = Date.now } = {}) {
        if (!Number.isFinite(ttlMs) || ttlMs <= 0) throw new TypeError("ttlMs must be positive");
        if (!Number.isInteger(maximumEntries) || maximumEntries <= 0) {
            throw new TypeError("maximumEntries must be a positive integer");
        }
        this.#ttlMs = ttlMs;
        this.#maximumEntries = maximumEntries;
        this.#now = now;
    }

    delete(key) {
        return this.#entries.delete(key);
    }

    clear() {
        this.#entries.clear();
    }

    get size() {
        return this.#entries.size;
    }

    getIfPresent(key) {
        const entry = this.#entries.get(key);
        if (!entry || entry.promise || entry.expiresAt <= this.#now()) {
            if (entry && !entry.promise) this.#entries.delete(key);
            return { hit: false, value: undefined };
        }
        this.#touch(key, entry);
        return { hit: true, value: entry.value };
    }

    set(key, value) {
        const entry = { value, expiresAt: this.#now() + this.#ttlMs };
        this.#entries.set(key, entry);
        this.#touch(key, entry);
        this.#prune();
        return value;
    }

    async get(key, loader) {
        if (typeof loader !== "function") throw new TypeError("loader must be a function");

        const now = this.#now();
        const cached = this.#entries.get(key);
        if (cached && (cached.promise || cached.expiresAt > now)) {
            this.#touch(key, cached);
            return cached.promise ? cached.promise : cached.value;
        }
        if (cached) this.#entries.delete(key);

        const promise = Promise.resolve().then(loader);
        const pending = { promise, expiresAt: Number.POSITIVE_INFINITY };
        this.#entries.set(key, pending);
        this.#prune();

        try {
            const value = await promise;
            if (this.#entries.get(key) === pending) {
                const resolved = { value, expiresAt: this.#now() + this.#ttlMs };
                this.#entries.set(key, resolved);
                this.#touch(key, resolved);
                this.#prune();
            }
            return value;
        } catch (error) {
            if (this.#entries.get(key) === pending) this.#entries.delete(key);
            throw error;
        }
    }

    #touch(key, entry) {
        this.#entries.delete(key);
        this.#entries.set(key, entry);
    }

    #prune() {
        const now = this.#now();
        for (const [key, entry] of this.#entries) {
            if (!entry.promise && entry.expiresAt <= now) this.#entries.delete(key);
        }
        while (this.#entries.size > this.#maximumEntries) {
            const oldestKey = this.#entries.keys().next().value;
            this.#entries.delete(oldestKey);
        }
    }
}
