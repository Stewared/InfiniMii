const mongoose = require("mongoose");

mongoose.set("strictQuery", true);

// --- Schemas --- //
const miiSchema = new mongoose.Schema({
    id: { type: String, required: true, unique: true, index: true },
    uploader: { type: String, required: true, index: true },
    desc: { type: String, default: "No Description Provided" },
    votes: { type: Number, default: 1 },
    official: { type: Boolean, default: false, index: true },
    uploadedOn: { type: Number, default: () => Date.now(), index: true },
    console: { type: String, default: "3DS" },
    general: mongoose.Schema.Types.Mixed,
    meta: mongoose.Schema.Types.Mixed,
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
    officialCategories: { type: [String], default: [] },
    published: { type: Boolean, default: false, index: true },
    private: { type: Boolean, default: true, index: true }, //TODO_DB: verify published vs private
    blockedFromPublishing: { type: Boolean, default: false },
    blockReason: { type: String, default: "No Reason Provided" }
}, { timestamps: true, minimize: false });

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true, index: true },
    salt: String,
    pass: String,
    verificationToken: String,
    creationDate: { type: Number, default: () => Date.now() },
    email: String,
    votedFor: { type: [String], default: [] },
    submissions: { type: [String], default: [] },
    miiPfp: { type: String, default: "00000" },
    roles: { type: [String], default: ["basic"] },
    token: String,
    verified: { type: Boolean, default: false },
    privateMiis: { type: [String], default: [] },
    isBanned: { type: Boolean, default: false },
    banExpires: Number,
    banReason: String
}, { timestamps: true, minimize: false });

const settingsSchema = new mongoose.Schema({
    _id: { type: String, required: true },
    highlightedMii: { type: String, default: "00000" },
    highlightedMiiChangeDay: { type: Number, default: ()=>Date.now() },
    bannedIPs: { type: [String], default: [] },
    officialCategories: { type: mongoose.Schema.Types.Mixed, default: { categories: [] } }
}, { _id: false, minimize: false });

// --- Models --- //
const Mii = mongoose.model("Mii", miiSchema);
const User = mongoose.model("User", userSchema);
const Settings = mongoose.model("Settings", settingsSchema);

// --- Connection --- //
const connectionPromise = mongoose.connect("mongodb://localhost:27017/infinimii", {
    autoIndex: true
});

module.exports = {
    connectionPromise,
    Mii,
    User,
    Settings
};