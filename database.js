import mongoose from "mongoose";

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
    submissions: { type: [String], default: [] }, // TODO_DB: remove this
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



// Clear indexes
async function clearIndexes() {
    try {
        await connectionPromise; // Wait for connection
        console.log('Connected to MongoDB. Dropping indexes...');

        // Drop indexes on each collection (keeps _id index)
        await Mii.collection.dropIndexes();
        console.log('Dropped indexes on Miis collection.');

        await User.collection.dropIndexes();
        console.log('Dropped indexes on Users collection.');

        await Settings.collection.dropIndexes();
        console.log('Dropped indexes on Settings collection.');

        console.log('All indexes cleared. Exiting...');
        // process.exit(0);
    } catch (error) {
        console.error('Error clearing indexes:', error);
        // process.exit(1);
    }
}
clearIndexes();

export {
    connectionPromise,
    Mii,
    User,
    Settings
};