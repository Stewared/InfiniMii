import mongoose from "mongoose";
import { MongoMemoryServer } from "mongodb-memory-server";
import { MII_DESCRIPTION_MAX_LENGTH } from "./miiDescriptionValidation.js";

mongoose.set("strictQuery", true);

const DEFAULT_MONGODB_URI = "mongodb://127.0.0.1:27017/infinimii";
const configuredMongoUri = String(process.env.MONGODB_URI || process.env.mongoUri || "").trim();
const LOCAL_DEV_MONGODB_URIS = new Set([
    "mongodb://127.0.0.1:27017/infinimii",
    "mongodb://localhost:27017/infinimii"
]);

let memoryMongoServer = null;

// --- Schemas --- //
const miiSchema = new mongoose.Schema({
    id: { type: String, required: true, unique: true, index: true },
    uploader: { type: String, required: true, index: true },
    contributor: { type: String, index: true },
    desc: { type: String, default: "No Description Provided", maxlength: MII_DESCRIPTION_MAX_LENGTH },
    miiHash: { type: String, index: true },
    votes: { type: Number, default: 1 },
    official: { type: Boolean, default: false, index: true },
    officialSource: { type: String, index: true },
    uploadedOn: { type: Number, default: () => Date.now(), index: true },
    console: { type: String, default: "3DS" },
    general: {
        height: Number,
        weight: Number,
        favoriteColor: Number,
        birthday: Number,
        birthMonth: Number,
        gender: Number
    },
    meta: {
        creatorName: { type: String, default: "" },
        name: { type: String, default: "" },
        console: { type: String, default: "3DS", },
        type: mongoose.Schema.Types.Mixed,
    },
    perms: mongoose.Schema.Types.Mixed,
    hair: mongoose.Schema.Types.Mixed,
    face: mongoose.Schema.Types.Mixed,
    eyes: mongoose.Schema.Types.Mixed,
    eyebrows: mongoose.Schema.Types.Mixed,
    nose: mongoose.Schema.Types.Mixed,
    mouth: mongoose.Schema.Types.Mixed,
    beard: mongoose.Schema.Types.Mixed,
    glasses: mongoose.Schema.Types.Mixed,
    mole: mongoose.Schema.Types.Mixed,
    tl: mongoose.Schema.Types.Mixed,
    mt: mongoose.Schema.Types.Mixed,
    officialCategories: { type: [String], default: [] },
    tags: { type: [String], default: [], index: true },
    published: { type: Boolean, default: false, index: true },
    private: { type: Boolean, default: true, index: true }, //TODO_DB: verify published vs private
    lockedFromUserEdits: { type: Boolean, default: false },
    blockedFromPublishing: { type: Boolean, default: false },
    blockReason: { type: String }
}, { timestamps: true, minimize: false });

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true, index: true },
    salt: String,
    pass: String,
    verificationToken: String,
    creationDate: { type: Number, default: () => Date.now() },
    email: String,
    votedFor: { type: [String], default: [] },
    miiPfp: { type: String, default: "00000" },
    pfpSet: { type: Boolean, default: false },
    roles: { type: [String], default: ["basic"] },
    verified: { type: Boolean, default: false },
    isBanned: { type: Boolean, default: false },
    banExpires: Number,
    banReason: String,
    tokenVersion: { type: Number, default: 0 }, // Don't accept JWTs older than this
    lastUsernameChange: { type: Number, default: 0 }, // Track when username was last changed
    resetPasswordToken: String, // Token for password reset
    resetPasswordExpires: Number, // Expiration time for reset token
    pendingEmail: String, // New email waiting to be verified
    pendingEmailToken: String, // Token for pending email verification
    pendingEmailExpires: Number, // Expiration time for pending email token
}, { timestamps: true, minimize: false });

const settingsSchema = new mongoose.Schema({
    _id: { type: String, required: true },
    highlightedMii: { type: String, default: "00000" },
    defaultUserPfpMii: { type: String, default: "QfK19" },
    highlightedMiiChangeDay: { type: Number, default: ()=>Date.now() },
    highlightedMiiReminderSentOn: { type: String, default: null },
    bannedIPs: { type: [String], default: [] },
    officialCategories: { type: mongoose.Schema.Types.Mixed, default: { categories: [] } },
    officialCompanySources: { type: [String], default: ["Nintendo"] },
    miiTags: { type: [String], default: [] }
}, { _id: false, minimize: false });

// Reserved usernames schema to prevent impersonating a user right after they change their username
// Also prevents a unlikely vulnerability where JWTs exist for an email+username and the user changes both, and somehow another user signs up with the same email and username
const reservedUsernameSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true, index: true },
    expiresAt: { type: Date, required: true, index: { expires: 0 } } // auto-deletes when expired
});

// --- Models --- //
const Miis = mongoose.model("Mii", miiSchema);
const Users = mongoose.model("User", userSchema);
const Settings = mongoose.model("Settings", settingsSchema);
const ReservedUsername = mongoose.model("ReservedUsername", reservedUsernameSchema);

// --- Connection --- //
function isMemoryMongoAllowed() {
    return process.env.NODE_ENV !== "production" && process.env.MONGODB_DISABLE_MEMORY_SERVER !== "true";
}

function normalizeMongoUriForComparison(uri) {
    return String(uri || "").trim().replace(/\/+$/, "");
}

function isLocalDevMongoUri(uri) {
    return LOCAL_DEV_MONGODB_URIS.has(normalizeMongoUriForComparison(uri));
}

async function startMemoryMongo(reason) {
    memoryMongoServer = await MongoMemoryServer.create({
        instance: {
            dbName: "infinimii"
        }
    });

    console.log(reason);
    return memoryMongoServer.getUri();
}

async function resolveMongoUri() {
    if (configuredMongoUri) {
        return configuredMongoUri;
    }

    if (!isMemoryMongoAllowed()) {
        return DEFAULT_MONGODB_URI;
    }

    return startMemoryMongo("[mongo] No MongoDB URI configured. Using an in-memory MongoDB instance for local development.");
}

function getMongoConnectOptions(mongoUri) {
    const options = {
        autoIndex: true
    };

    if (isMemoryMongoAllowed() && isLocalDevMongoUri(mongoUri)) {
        options.serverSelectionTimeoutMS = 1500;
    }

    return options;
}

function shouldFallbackToMemoryMongo(mongoUri) {
    return isMemoryMongoAllowed() && isLocalDevMongoUri(mongoUri);
}

async function cleanupMongoResources() {
    try {
        if (mongoose.connection.readyState !== 0) {
            await mongoose.disconnect();
        }
    } catch (error) {
        console.warn("[mongo] Failed to close mongoose cleanly:", error.message);
    }

    if (!memoryMongoServer) return;

    try {
        await memoryMongoServer.stop();
    } catch (error) {
        console.warn("[mongo] Failed to stop in-memory MongoDB cleanly:", error.message);
    } finally {
        memoryMongoServer = null;
    }
}

for (const signal of ["SIGINT", "SIGTERM"]) {
    process.once(signal, () => {
        cleanupMongoResources()
            .finally(() => process.exit(0));
    });
}

const connectionPromise = (async () => {
    const mongoUri = await resolveMongoUri();

    try {
        return await mongoose.connect(mongoUri, getMongoConnectOptions(mongoUri));
    } catch (error) {
        if (!shouldFallbackToMemoryMongo(mongoUri)) {
            throw error;
        }

        console.warn(`[mongo] Could not connect to local MongoDB at ${mongoUri}: ${error.message}`);
        await cleanupMongoResources();

        const fallbackUri = await startMemoryMongo("[mongo] Local MongoDB is unavailable. Using an in-memory MongoDB instance for local development.");
        return mongoose.connect(fallbackUri, {
            autoIndex: true
        });
    }
})();



// Clear indexes
async function clearIndexes() {
    try {
        await connectionPromise; // Wait for connection
        console.log('Connected to MongoDB. Dropping indexes...');

        // Drop indexes on each collection (keeps _id index)
        await Miis.collection.dropIndexes();
        console.log('Dropped indexes on Miis collection.');

        await Users.collection.dropIndexes();
        console.log('Dropped indexes on Users collection.');

        await Settings.collection.dropIndexes();
        console.log('Dropped indexes on Settings collection.');
        
        await ReservedUsername.collection.dropIndexes();
        console.log('Dropped indexes on ReservedUsernames collection.');

        console.log('All indexes cleared. Exiting...');
        // process.exit(0);
    } catch (error) {
        console.error('Error clearing indexes:', error);
        // process.exit(1);
    }
}
// clearIndexes();

export {
    cleanupMongoResources,
    connectionPromise,
    Miis,
    Users,
    Settings,
    ReservedUsername
};
