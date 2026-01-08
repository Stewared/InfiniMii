import { fileURLToPath } from 'url';
import { dirname } from 'path';
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
import helmet from 'helmet';
import miijs from "miijs";
import crypto from 'crypto';
import fs from "fs";
import ejs from 'ejs';
import express from "express";
import path from "path";
import nodemailer from "nodemailer";
import cookieParser from 'cookie-parser';
import compression from 'compression';
import multer from 'multer';
import FormData from 'form-data';
import https from 'https';
import { RegExpMatcher, englishDataset, englishRecommendedTransformers } from 'obscenity';
import { doubleMetaphone } from 'double-metaphone';
import validator from 'validator';
import jwt from 'jsonwebtoken';
import { STATUS_CODES } from 'http';

process.env = JSON.parse(fs.readFileSync("./env.json", "utf-8"));
import { connectionPromise, Mii as Miis, User as Users, Settings } from "./database.js";

const defaultMiisPerPage = 15;
const PRIVATE_MII_LIMIT = process.env.privateMiiLimit;
const baseUrl = process.env.baseUrl;
const swearList = englishDataset.containers.map(c => c.metadata.originalWord).filter(Boolean);
const upload = multer({
    dest: './uploads/',
    filename: (req, file, cb) => {
        const ext = file.originalname.split('.').pop(); // keep extension
        const hash = crypto.randomBytes(16).toString('hex');
        cb(null, `${hash}.${ext}`);
    }
});
var globalSalt = process.env.salt;

function bitStringToBuffer(bitString) {
  const byteLength = Math.ceil(bitString.length / 8);
  const buffer = Buffer.alloc(byteLength);

  for (let i = 0; i < bitString.length; i++) {
    if (bitString[i] === '1') {
      buffer[i >> 3] |= 1 << (7 - (i & 7));
    }
  }

  return buffer;
}

//#region Database
async function getSettings() {
    let settings = await Settings.findById("global");
    if (!settings) {
        settings = await Settings.create({
            _id: "global",
            highlightedMii: null,
            highlightedMiiChangeDay: null,
            bannedIPs: [],
            officialCategories: { categories: [] }
        });
    }
    return settings;
}

async function updateSettings(updates) {
    return await Settings.findByIdAndUpdate("global", updates, { new: true, upsert: true });
}

async function getAllMiis(includePrivate = false) {
    const query = includePrivate ? {} : { private: false };
    return await Miis.find(query).lean();
}

async function getMiiById(id, includePrivate = false) {
    const query = { id };
    if (!includePrivate) query.private = false;
    return await Miis.findOne(query).lean();
}
async function getUserByUsername(username, lean=true) {
    let userPromise = Users.findOne({ username });
    if (lean) userPromise = userPromise.lean();
    return await userPromise;
}
async function getAllUsers() {
    return await Users.find({}).lean();
}
//#endregion

const ejsFunctions = {
    "decodeColor": (colorIndex) => (["Red", "#dd5e17", "#e2cd5e", "Lime", "Green", "Blue", "Cyan", "#e65ba1", "Purple", "Brown", "White", "Black"][colorIndex] || colorIndex)
}

/** Build EJS variables for the page. `user` is assumed to be the logged in user */
async function getSendables(req, title, user) { 
    const currentPath = req.path;
    const queryString = Object.keys(req.query).length > 0 
        ? '?' + new URLSearchParams(req.query).toString() 
        : '';
    const settings = await getSettings();
    const allUsers = await getAllUsers();

    // Build information related to the current user
    let userPfpMiiColor = null;
    if (req.user) {
        const userPfpMii = await getMiiById(req.user.miiPfp, true);
        userPfpMiiColor = userPfpMii.general.favoriteColor;
    }
    
    const currentUser = req.user?.username || "Default";
    const pfp = req.user?.miiPfp || "00000";
    
    var send = {
        ...ejsFunctions,
        highlightedMii: settings.highlightedMii,
        bannedIPs: settings.bannedIPs,
        officialCategories: settings.officialCategories,
        howToTitle: "How To",
        currentPath: currentPath + queryString,
        thisUser: currentUser, // *username
        user: req.user,
        isModerator: canModerate(req.user),
        isOfficial: isOfficial(req.user),
        isResearcher: isResearcher(req.user),
        isAdmin: isAdmin(req.user),
        pfp: pfp,
        query: req.query,
        discordInvite: process.env.discordInvite,
        githubLink: process.env.githubLink,
        baseUrl: baseUrl,
        title: title,
        userPfpMiiColor: userPfpMiiColor ?? "#111111",
        highlightedMiiData: await getMiiById(settings.highlightedMii, false),
        averageMiiData: await getMiiById("average", false),
    };

    send.currentFilter=send.currentFilter||"";
    return send;
}

//#region Roles
// Role System - Array-based for multiple roles
const ROLES = {
    TEMP_BANNED: 'tempBanned',
    PERM_BANNED: 'permBanned', 
    BASIC: 'basic',
    SUPPORTER: 'supporter',
    RESEARCHER: 'researcher',
    MODERATOR: 'moderator',
    ADMINISTRATOR: 'administrator'
};
const OFFICIAL_ROLES = [ ROLES.RESEARCHER, ROLES.MODERATOR, ROLES.ADMINISTRATOR ];

const ROLE_DISPLAY = {
    [ROLES.TEMP_BANNED]: '🚫 Temporarily Banned',
    [ROLES.PERM_BANNED]: '⛔ Permanently Banned',
    [ROLES.BASIC]: 'User',
    [ROLES.SUPPORTER]: '💖 Supporter',
    [ROLES.RESEARCHER]: '🔬 Researcher',
    [ROLES.MODERATOR]: '🛡️ Moderator',
    [ROLES.ADMINISTRATOR]: '👑 Administrator'
};

// Helper functions for role system
function getUserRoles(user) {
    if (Array.isArray(user?.roles)) {
        return user.roles;
    }
    return [ROLES.BASIC];
}

function hasRole(user, role) {
    const roles = getUserRoles(user);
    return roles.includes(role);
}

function canUploadOfficial(user) {
    return hasRole(user, ROLES.RESEARCHER) || 
           hasRole(user, ROLES.ADMINISTRATOR);
}

function canModerate(user) {
    return hasRole(user, ROLES.MODERATOR) || 
           hasRole(user, ROLES.ADMINISTRATOR);
}

function isOfficial(user) {
    return hasRole(user, ROLES.MODERATOR) || 
        hasRole(user, ROLES.RESEARCHER) ||
        hasRole(user, ROLES.ADMINISTRATOR);

}

// Permission to edit official Miis
function isResearcher(user) {
    return hasRole(user, ROLES.RESEARCHER) || 
           hasRole(user, ROLES.MODERATOR) ||
           hasRole(user, ROLES.ADMINISTRATOR);
}

function isAdmin(user) {
    return hasRole(user, ROLES.ADMINISTRATOR);
}

async function isBanned(user) {
    const roles = getUserRoles(user);
    if (roles.includes(ROLES.PERM_BANNED)) return true;
    if (roles.includes(ROLES.TEMP_BANNED)) {
        if (user.banExpires && Date.now() < user.banExpires) {
            return true;
        }
        else if (user.banExpires) {
            // Unban user - remove temp ban role
            user.roles = user.roles.filter(r => r !== ROLES.TEMP_BANNED);
            delete user.banExpires;
            await Users.findOneAndUpdate({ username: user.username }, { 
                roles: user.roles,
                $unset: { banExpires: 1 }
            });
            return false;
        }
        return true;
    }
    return false;
}

function ensureBasicRole(user) {
    if (!user.roles || user.roles.length === 0) {
        user.roles = [ROLES.BASIC];
    }
    // NOTE: this does not save
}

function addRole(user, role) {
    ensureBasicRole(user);
    if (!user.roles.includes(role)) {
        user.roles.push(role);
    }
}

function removeRole(user, role) {
    ensureBasicRole(user);
    user.roles = user.roles.filter(r => r !== role);
    ensureBasicRole(user);
}
//#endregion

function createToken(user) {
    const payload = {
        username: user.username,
        email: user.email,
        tokenVersion: user.tokenVersion || 0
    };
    return jwt.sign(payload, process.env.JWT_SECRET || "beta_testing_only_secret", { 
        expiresIn: '30d',
        algorithm: 'HS256'
    });
}

// Find a category node by path
function findCategoryByPath(path, tree) {
    if (!path || !tree) return null;
    
    const parts = path.split('/');
    let current = tree;
    
    for (const part of parts) {
        const found = current.find(node => node.name === part);
        if (!found) return null;
        if (parts.indexOf(part) === parts.length - 1) return found;
        current = found.children;
    }
    
    return null;
}

// TODO_DB: verify
// Get all leaf categories (categories with no children) as flat array
function getAllLeafCategories(tree, result = []) {
    if (!tree) return result;
    tree.forEach(node => {
        if (node.children && node.children.length > 0) {
            getAllLeafCategories(node.children, result);
        } else {
            result.push(node);
        }
    });
    return result;
}

// Get all categories (including parents) as flat array with paths
function getAllCategoriesFlat(tree, result = []) {
    if (!tree) return result;
    tree.forEach(node => {
        result.push(node);
        if (node.children && node.children.length > 0) {
            getAllCategoriesFlat(node.children, result);
        }
    });
    return result;
}

// Recursively update paths after a rename
function updateCategoryPaths(node, parentPath = '') {
    node.path = parentPath ? `${parentPath}/${node.name}` : node.name;
    if (node.children && node.children.length > 0) {
        node.children.forEach(child => {
            updateCategoryPaths(child, node.path);
        });
    }
}

// Find parent of a category by path
function findParentByChildPath(path, tree, parent = null) {
    if (!path || !tree) return null;
    
    for (const node of tree) {
        if (node.path === path) {
            return parent;
        }
        if (node.children && node.children.length > 0) {
            const found = findParentByChildPath(path, node.children, node);
            if (found) return found;
        }
    }
    
    return null;
}

// Rename category in all Miis that use it
async function renameCategoryInAllMiis(oldPath, newPath) {
    let count = 0;
    
    // Update all Miis (published and private)
    const miis = await Miis.find({
        official: true,
        officialCategories: oldPath
    });
    
    for (const mii of miis) {
        const index = mii.officialCategories.indexOf(oldPath);
        if (index > -1) {
            mii.officialCategories[index] = newPath;
            await Miis.findOneAndUpdate(
                { id: mii.id },
                { $set: { officialCategories: mii.officialCategories } }
            );
            count++;
        }
    }
    
    return count;
}

// Remove category from all Miis
async function removeCategoryFromAllMiis(path) {
    let count = 0;
    
    // Update all Miis
    const miis = await Miis.find({
        official: true,
        officialCategories: path
    });
    
    for (const mii of miis) {
        mii.officialCategories = mii.officialCategories.filter(c => c !== path);
        await Miis.findOneAndUpdate(
            { id: mii.id },
            { $set: { officialCategories: mii.officialCategories } }
        );
        count++;
    }
    
    return count;
}

// Get all descendant paths (for deletion)
function getAllDescendantPaths(node, result = []) {
    result.push(node.path);
    if (node.children && node.children.length > 0) {
        node.children.forEach(child => {
            getAllDescendantPaths(child, result);
        });
    }
    return result;
}

function sha256(str) {
    return crypto.createHash('sha256').update(`${str}${globalSalt}`).digest('hex');
}

function isVPN(ip) {
    // Basic check - you might want to use a VPN detection API
    // For now, just check if it's a common VPN pattern
    // This is a placeholder - implement proper VPN detection if needed
    return false; // TODO: Implement VPN detection
}

function shuffleArray(array) {
  for (let i = array.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [array[i], array[j]] = [array[j], array[i]];
  }
  return array;
}

// Seeded random number generator (Mulberry32)
function seededRandom(seed) {
    return function() {
        seed |= 0;
        seed = seed + 0x6D2B79F5 | 0;
        var t = Math.imul(seed ^ seed >>> 15, 1 | seed);
        t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t;
        return ((t ^ t >>> 14) >>> 0) / 4294967296;
    };
}

// Seeded shuffle using Fisher-Yates
function seededShuffle(array, seed) {
    const rng = seededRandom(seed);
    const shuffled = [...array];
    for (let i = shuffled.length - 1; i > 0; i--) {
        const j = Math.floor(rng() * (i + 1));
        [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
    }
    return shuffled;
}

function validate(what) {
    return /^(\d|\D){1,15}$/.test(what);
}

const swearMatcher = new RegExpMatcher({
    ...englishDataset.build(),
    ...englishRecommendedTransformers, // Full leet-speak detection
});
const badPhonetics = new Set(
    swearList.flatMap(w => doubleMetaphone(w).filter(Boolean))
);

/** Loose filter check that filters if it sounds phonetically similar to any bad word */
function soundsBad(str) {
    // Strict profanity check with full leet-speak
    if (swearMatcher.hasMatch(str)) return true;

    // Remove non-alphabetic for phonetic analysis
    const cleanStr = str.replace(/[^a-zA-Z]/g, '');
    if (cleanStr.length === 0) return false;
    
    const phonetics = doubleMetaphone(cleanStr);
    return phonetics.some(p => p && badPhonetics.has(p));
}

/** Check input against the filter explicitly including leetspeek */
function isBad(str) {
    return swearMatcher.hasMatch(str);
}

async function genId() {
    let chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let attempt = 0;
    let length = 5;
    let newId;
    while (true) {
        newId = "";
        for (var i = 0; i < length; i++) {
            newId += chars[Math.floor(Math.random() * chars.length)];
        }
        let exists = await Miis.exists({ id: newId });
        let isProfane = soundsBad(newId) && attempt < 30; // prevent broken filter from hanging app

        if (!exists && !isProfane) break; // Stop once we find a suitable ID

        // If no ID is found several times in a row, increase the length.
        attempt++;
        if (attempt % 5 === 0) {
            length += 1;
        }
    }
    return newId;
}

function wilsonMethod(upvotes, uploadedOn) {
    // Constants for the Wilson Score Interval
    const z = 1.96; // 95% confidence interval
    
    // Calculate the fraction of upvotes
    const p = upvotes / (upvotes + 1); // Adding 1 to avoid division by zero
    
    // Calculate the "score"
    const score =
    (p + (z * z) / (2 * (upvotes + 1)) - z * Math.sqrt((p * (1 - p) + (z * z) / (4 * (upvotes + 1))) / (upvotes + 1))) /
    (1 + (z * z) / (upvotes + 1));
    
    // Calculate the hotness by considering the time elapsed
    const elapsedTime = (Date.now() - uploadedOn) / (1000 * 60 * 60); // Convert milliseconds to hours
    const hotness = score / elapsedTime;
    
    return hotness;
}

// Paginated API that queries database directly with skip/limit
async function paginatedApi(what, page = 1, perPage = defaultMiisPerPage, filter = null) {
    const skip = (page - 1) * perPage;
    const settings = await getSettings();
    
    let query = { private: false, id: { $ne: "average" } };
    let sort = {};
    
    switch(what) {
        case "random": { // TODO: this is random, but based on sort order. True random is possible but not deterministically

            const seed = parseInt(filter); // filter contains the seed from the route
            const totalCount = await Miis.countDocuments(query);
            
            const pipeline = [
                { $match: query },
                {
                    $addFields: {
                        randomSort: {
                            $mod: [
                                { $add: [
                                    { $toLong: "$uploadedOn" },
                                    seed
                                ]},
                                999999
                            ]
                        }
                    }
                },
                { $sort: { randomSort: 1 } },
                { $skip: skip },
                { $limit: perPage }
            ];
            
            const items = await Miis.aggregate(pipeline);
            
            return {
                items,
                total: totalCount,
                page,
                perPage,
                totalPages: Math.ceil(totalCount / perPage),
                seed
            };
        }
        
        case "trending": {// TODO: rebrand to "trending"
            const now = Date.now();

            const pipeline = [
                { $match: query },
                {
                    $addFields: {
                        ageHours: {
                            $divide: [
                                { $subtract: [now, "$uploadedOn"] },
                                1000 * 60 * 60
                            ]
                        }
                    }
                },
                {
                    $addFields: {
                        hotness: {
                            $divide: [
                                "$votes",
                                {
                                    $pow: [
                                        { $add: ["$ageHours", 2] },
                                        1.5
                                    ]
                                }
                            ]
                        }
                    }
                },
                { $sort: { hotness: -1 } },
                { $skip: skip },
                { $limit: perPage }
            ];

            const [items, total] = await Promise.all([
                Miis.aggregate(pipeline),
                Miis.countDocuments(query)
            ]);

            return {
                items,
                total,
                page,
                perPage,
                totalPages: Math.ceil(total / perPage)
            };
        }

        case "top":
            sort = { votes: -1 };
            break;
        
        case "recent":
            sort = { uploadedOn: -1 };
            break;
        
        case "official":
            query.official = true;
            if (filter) {
                query.officialCategories = filter;
            }
            sort = { votes: -1 };
            break;
        
        case "search":
            if (filter) {
                // Use MongoDB regex for database-level filtering
                const searchRegex = new RegExp(filter, 'i'); // Case-insensitive regex
                const searchQuery = {
                    ...query,
                    $or: [
                        { 'meta.name': searchRegex },
                        { 'desc': searchRegex },
                        { 'uploader': searchRegex }
                    ]
                };
                
                const searchTotal = await Miis.countDocuments(searchQuery);
                const searchItems = await Miis.find(searchQuery)
                    .sort({ votes: -1 })
                    .skip(skip)
                    .limit(perPage)
                    .lean();
                
                return {
                    items: searchItems,
                    total: searchTotal,
                    page,
                    perPage,
                    totalPages: Math.ceil(searchTotal / perPage)
                };
            }
            sort = { votes: -1 };
            break;
        
        default:
            return { items: [], total: 0, page: 1, perPage, totalPages: 0 };
    }
    
    // For simple sorted queries (best, recent, official without category)
    const totalCount = await Miis.countDocuments(query);
    const items = await Miis.find(query)
        .sort(sort)
        .skip(skip)
        .limit(perPage)
        .lean();
    
    return {
        items,
        total: totalCount,
        page,
        perPage,
        totalPages: Math.ceil(totalCount / perPage)
    };
}

// API for things that do not pagination (homepage categories and /api endpoint)
async function api(what,limit=50,begin=0,fltr){
    const allMiis = await Miis.find({ private: false, id: { $ne: "average" } }).lean();
    const settings = await getSettings();
    
    var newArr;
    switch(what){
        case "all":
            return allMiis;
        case "highlightedMii":
            return await getMiiById(settings.highlightedMii);
        case "getMii":
            return await getMiiById(fltr);
        case "random":
            newArr = shuffleArray([...allMiis]);
            break;
        case "trending":
            newArr = [...allMiis];
            newArr.sort((a, b) => {
                return wilsonMethod(b.votes, b.uploadedOn) - wilsonMethod(a.votes, a.uploadedOn);
            });
            break;
        case "top":
            newArr = [...allMiis];
            newArr.sort((a, b) => {
                return b.votes - a.votes;
            });
            break;
        case "recent":
            newArr=[...allMiis];
            newArr.sort((a, b) => {
                return b.uploadedOn - a.uploadedOn;
            });
            break;
        case "official":
            newArr = allMiis.filter(mii => mii.official);
            newArr.sort((a, b) => {
                return b.votes - a.votes;
            });
            break;
        case "search":
            fltr = fltr.toLowerCase();
            newArr = allMiis.filter(mii=>{
                return mii.meta.name.toLowerCase().includes(fltr)||mii.desc.toLowerCase().includes(fltr)||mii.uploader.toLowerCase().includes(fltr);
            });
            newArr.sort((a, b) => {
                return b.votes - a.votes;
            });
            break;
        default:
            throw new Error("No valid type specified");
    }
    return newArr.slice(begin,limit);
}

function hashPassword(password, s) {
    let salt;
    if (s) {
        salt = s;
    }
    else {
        salt = crypto.randomBytes(16).toString('hex');
    }
    const hash = crypto.pbkdf2Sync(password, salt + globalSalt, 1000, 64, 'sha256').toString('hex');
    return { salt, hash };
}
function validatePassword(password, salt, hash) {
    return hashPassword(password, salt).hash === hash;
}

/** Generate cryptographically secure token used to verify email is accessible */
function genToken(length = 15) {
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    const bytes = crypto.randomBytes(length);
    let token = "";

    for (let i = 0; i < length; i++) {
        token += chars[bytes[i] % chars.length];
    }
    return token;
}

function sendEmail(to, subj, cont) {
    nodemailer.createTransport({
        host: 'smtp.zoho.com',
        port: 465,
        secure: true,
        auth: {
            user: process.env.email,
            pass: process.env.emailPass
        }
    }).sendMail({
        from: process.env.email,
        to: to,
        subject: subj,
        html: cont
    });
}
function makeReport(content, attachments = []) {
    const formData = new FormData();
    
    // Add the JSON payload
    formData.append('payload_json', content);
    
    // Add any file attachments
    attachments.forEach((attachment, index) => {
        formData.append(`files[${index}]`, attachment.data, {
            filename: attachment.filename,
            contentType: attachment.contentType || 'image/png'
        });
    });
    
    // Send using form-data instead of JSON
    const url = new URL(process.env.hookUrl);
    
    const options = {
        hostname: url.hostname,
        path: url.pathname + url.search,
        method: 'POST',
        headers: formData.getHeaders()
    };
    
    const req = https.request(options, (res) => {
        if (res.statusCode !== 200 && res.statusCode !== 204) {
            console.error(`Discord webhook returned status ${res.statusCode}`);
        }
    });
    
    req.on('error', (error) => {
        console.error('Error sending to Discord:', error);
    });
    
    formData.pipe(req);
}


//Averaging Helpers
const isPlainObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
function mean(nums) {
    if (!nums.length) return undefined;
    return nums.reduce((a, b) => a + b, 0) / nums.length;
}
function mode(arr) {
    const counts = new Map();
    const firstIndex = new Map();
    let best, bestCount = -1;
    arr.forEach((v, i) => {
        const c = (counts.get(v) ?? 0) + 1;
        counts.set(v, c);
        if (!firstIndex.has(v)) firstIndex.set(v, i);
        if (c > bestCount || (c === bestCount && firstIndex.get(v) < firstIndex.get(best))) {
            best = v; bestCount = c;
        }
    });
    return best;
}
function getNestedAsArrays(obj) {
    const ret = {};
    for (const [key, val] of Object.entries(obj)) {
        if (isPlainObject(val)) {
            ret[key] = getNestedAsArrays(val);
        }
        else {
            ret[key] = [val];
        }
    }
    return ret;
}
function populateNestedArrays(arrayObj, obj) {
    const ret = structuredClone(arrayObj);
    for (const [key, val] of Object.entries(obj)) {
        if (isPlainObject(val)) {
            if (!ret[key] || !isPlainObject(ret[key])) ret[key] = {};
            ret[key] = populateNestedArrays(ret[key], val);
        }
        else {
            if (!Array.isArray(ret[key])) ret[key] = [];
            ret[key].push(val);
        }
    }
    return ret;
}
async function getCollectedLeavesAcrossMiis(allMiis) {
    let acc;
    for (const mii of allMiis) {
        acc = acc ? populateNestedArrays(acc, mii) : getNestedAsArrays(mii);
    }
    return acc;
}
function mostCommonPageTypePair(pageArr, typeArr) {
    if (!Array.isArray(pageArr) || !Array.isArray(typeArr)) return null;
    const n = Math.min(pageArr.length, typeArr.length);
    const key = (p, t) => JSON.stringify([p, t]);
    const counts = new Map();
    const order = new Map();
    let bestKey, bestCount = -1;
    
    for (let i = 0; i < n; i++) {
        const p = pageArr[i], t = typeArr[i];
        if (p === undefined || p === null || t === undefined || t === null) continue;
        const k = key(p, t);
        const c = (counts.get(k) ?? 0) + 1;
        counts.set(k, c);
        if (!order.has(k)) order.set(k, i);
        if (c > bestCount || (c === bestCount && order.get(k) < order.get(bestKey))) {
            bestKey = k; bestCount = c;
        }
    }
    return bestKey ? JSON.parse(bestKey) : null; // [page, type]
}
function averageValuesForKey(key, values) {
    const vals = values.filter(v => v !== undefined && v !== null);
    if (!vals.length) return undefined;

    if (key==="type" || key==="color") {
        return mode(vals);
    }
    
    const allNumbers   = vals.every(v => typeof v === "number" && Number.isFinite(v));
    const allBooleans  = vals.every(v => typeof v === "boolean");
    const allStrings   = vals.every(v => typeof v === "string");
    const onlyNumOrBool = vals.every(v => typeof v === "number" || typeof v === "boolean");
    
    if (allNumbers) return Math.round(mean(vals));
    if (allBooleans) {
        const trues = vals.filter(Boolean).length;
        return trues >= (vals.length - trues); // modal boolean
    }
    if (onlyNumOrBool) {
        // booleans as 1/0, rounded mean
        const asNums = vals.map(v => (typeof v === "boolean" ? (v ? 1 : 0) : v));
        return Math.round(mean(asNums));
    }
    if (allStrings) return mode(vals);
    
    // Heterogeneous fallback → mode
    return mode(vals);
}
function averageObjectWithPairs(node, parentKey = "") {
    // Leaf arrays
    if (Array.isArray(node)) {
        return averageValuesForKey(parentKey, node);
    }
    
    // Non-object leaves
    if (!isPlainObject(node)) return node;
    
    // Special handling: resolve modal (page,type) pair if both are present as leaves/arrays
    const hasPage = Object.prototype.hasOwnProperty.call(node, "page");
    const hasType = Object.prototype.hasOwnProperty.call(node, "type");
    const pageIsLeaf = hasPage && !isPlainObject(node.page);
    const typeIsLeaf = hasType && !isPlainObject(node.type);
    
    const out = {};
    
    if (hasPage && hasType && pageIsLeaf && typeIsLeaf) {
        const pageArr = Array.isArray(node.page) ? node.page : [node.page];
        const typeArr = Array.isArray(node.type) ? node.type : [node.type];
        
        const pair = mostCommonPageTypePair(pageArr, typeArr);
        if (pair) {
            const [bestPage, bestType] = pair;
            out.page = bestPage;
            out.type = bestType;
        }
        else {
            // Fallbacks if no pair resolved
            out.page = averageValuesForKey("page", pageArr);
            out.type = averageValuesForKey("type", typeArr);
        }
        
        // Process any siblings at this level
        for (const [k, v] of Object.entries(node)) {
            if (k === "page" || k === "type") continue;
            out[k] = averageObjectWithPairs(v, k);
        }
        return out;
    }
    
    // General case: recurse
    for (const [k, v] of Object.entries(node)) {
        out[k] = averageObjectWithPairs(v, k);
    }
    return out;
}
async function setAverageMii(){
    const pipeline = [
        {
            $match: {
                published: true,
                private: false,
                id: { $ne: "average" }
            }
        },
        {
            $project: {
                _id: 0,
                general: 1,
                hair: 1,
                face: 1,
                eyes: 1,
                eyebrows: 1,
                nose: 1,
                mouth: 1,
                beard: 1,
                glasses: 1,
                mole: 1
            }
        }
    ];
    const allMiis = await Miis.aggregate(pipeline);


    const leaves = await getCollectedLeavesAcrossMiis(allMiis);
    var avg=averageObjectWithPairs(leaves);
    delete avg._id;
    avg.id = "average";
    avg.meta = { 
        name: `J${avg.general.gender===0?"ohn":"ane"} Doe`, 
        creatorName: "InfiniMii", 
        type: "3DS"
    };
    avg.desc="The most common or average features and placements of those features across all Miis on the website";
    avg.uploader = "Everyone";
    avg.votes = 0;
    avg.uploadedOn = Date.now();
    avg.private = false;
    avg.published = true;
    
    // Upsert average Mii
    await Miis.findOneAndUpdate(
        { id: "average" },
        { $set: avg },
        { upsert: true, new: true }
    );
    
    return avg;
}

// Sitemap generation functions
function generateSitemapXML(urls) {
    let xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
    xml += '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"\n';
    xml += '        xmlns:image="http://www.google.com/schemas/sitemap-image/1.1">\n';
    
    urls.forEach(url => {
        xml += '  <url>\n';
        xml += `    <loc>${url.loc}</loc>\n`;
        if (url.lastmod) xml += `    <lastmod>${url.lastmod}</lastmod>\n`;
        if (url.changefreq) xml += `    <changefreq>${url.changefreq}</changefreq>\n`;
        if (url.priority) xml += `    <priority>${url.priority}</priority>\n`;
        
        // Add image sitemap data if present
        if (url.images && url.images.length > 0) {
            url.images.forEach(img => {
                xml += '    <image:image>\n';
                xml += `      <image:loc>${img.loc}</image:loc>\n`;
                if (img.title) xml += `      <image:title>${escapeXml(img.title)}</image:title>\n`;
                if (img.caption) xml += `      <image:caption>${escapeXml(img.caption)}</image:caption>\n`;
                xml += '    </image:image>\n';
            });
        }
        
        xml += '  </url>\n';
    });
    
    xml += '</urlset>';
    return xml;
}

function escapeXml(unsafe) {
    return unsafe.replace(/[<>&'"]/g, (c) => {
        switch (c) {
            case '<': return '&lt;';
            case '>': return '&gt;';
            case '&': return '&amp;';
            case '\'': return '&apos;';
            case '"': return '&quot;';
        }
    });
}

import 'express-async-errors'; // Make router async errors handle the same as sync errors (dropping down to next() handler)
const site = express();
site.use(express.json());
site.use(express.urlencoded({ extended: true }));
site.use(express.static(path.join(__dirname + '/static')));
site.use(express.static(path.join(__dirname + '/static/css')));
site.use(express.static(path.join(__dirname + '/static/js')));
site.use(express.static(path.join(__dirname + '/static/assets')));
site.use(cookieParser());
site.use('/favicon.ico', express.static('static/favicon.png'));


//#region Middleware

// Security middleware
site.use(helmet({ contentSecurityPolicy: false }));
site.use((req, res, next) => {
    // Security headers
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    
    // Content Security Policy (adjust as needed)
    res.setHeader('Content-Security-Policy', 
        "default-src 'self'; " +
        "script-src 'self' 'unsafe-inline' https://www.googletagmanager.com https://www.google-analytics.com; " +
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
        "font-src 'self' https://fonts.gstatic.com; " +
        "img-src 'self' data: https:; " +
        "connect-src 'self' https://www.google-analytics.com;"
    );
    
    next();
});

// Auth middleware (using JWTs)
site.use(async (req, res, next) => {
    const token = req.cookies.token;
    if (!token) {
        return next(); // Not logged in, keep req.user undefined
    }

    try {
        const payload = jwt.verify(token, process.env.JWT_SECRET || "beta_testing_only_secret", { // TODO REMOVE
            algorithms: ['HS256']
        });
        const user = await Users.findOne({ 
            username: payload.username,
            email: payload.email,
            tokenVersion: payload.tokenVersion
        });
        // TODO: exploit where you change your username/email, and old token can still access it....
        // SOLUTION: on email/username change, increase token version

        // Optional: check token version to allow invalidation
        if (!user) {
            res.clearCookie('token');
            res.clearCookie('username');
            return next();
        }

        req.user = user; // attach full DB user
        next();
    } catch (err) {
        // jwt.verify failed, clear.
        res.clearCookie('token');
        res.clearCookie('username');
        next();
    }
})

// Ban middleware
site.use(async (req, res, next) => {
    // Check if user is banned
    if (req.user) {
        if (req.user) {
            // Check IP ban
            const clientIPs = [req.headers['x-forwarded-for'], req.socket.remoteAddress]
                .filter(Boolean)
                .map(ip => sha256(ip));
            const settings = await getSettings();
            if (settings.bannedIPs.some(ip => clientIPs.includes(ip))) {
                res.clearCookie('username');
                res.clearCookie('token');
                return res.json({error: 'Your IP address has been permanently banned.'});
            }
            
            // Check user ban
            if (await isBanned(req.user)) {
                // Allow access to logout only
                if (req.path === '/logout') {
                    return next();
                }
                
                if (req.user.role === ROLES.TEMP_BANNED && req.user.banExpires) {
                    const timeLeft = Math.ceil((req.user.banExpires - Date.now()) / (1000 * 60 * 60));
                    return res.json({error: `You are temporarily banned. Time remaining: ${timeLeft} hours. Reason: ${req.user.banReason || 'No reason provided'}`});
                }
                else {
                    return res.send(`You are permanently banned. Reason: ${req.user.banReason || 'No reason provided'}`);
                }
            }
        }
    }
    next();
});

// Compression middleware
site.use(compression({
    level: 6,
    threshold: 100 * 1024, // Only compress if response > 100kb
    filter: (req, res) => {
        if (req.headers['x-no-compression']) {
            return false;
        }
        return compression.filter(req, res);
    }
}));

//#endregion

// Patch ejs renderFile to resolve the ejsPartials at root, making includes shorter
ejs.renderFile = ((orig) => {
    return function (file, data, opts = {}, cb) {
        return orig.call(
            this,
            file,
            data,
            {
                views: [
                    path.join(__dirname, 'ejsFiles'),
                    path.join(__dirname, 'ejsPartials')
                ],
                ...opts
            },
            cb
        );
    };
})(ejs.renderFile)

function renderEjs(file, inp) {
    return new Promise((resolve, reject) => {
        ejs.renderFile(file, inp, {}, function(err, str) {
            if (err) {
                reject(err);
            } else {
                resolve(str);
            }
        });
    });
}

async function sendError(res, req, message, status) {
    return res.status(status).send(await renderEjs("./ejsFiles/error.ejs", {
        message: message,
        status: `${status} ${STATUS_CODES[status]}`,
        ...(await getSendables(req))
    }));
}

//#region Static handling

  
// Serve private Mii images with authentication
site.use('/privateMiiImgs', async (req, res, next) => {
    const miiId = req.path.split('/').pop().split('.')[0];
    
    const privateMii = await Miis.findOne({ id: miiId, private: true }).lean();
    if (privateMii) {
        const isOwner = privateMii.uploader === req.user.username;
        const isModerator = req.user && canModerate(req.user);
        
        if (isModerator || isOwner) {
            next();
        } else {
            if (req.accepts('html')) {
                res.status(403).json({ error: 'Access denied' });
            } else {
                await sendError(res, req, "Access denied. This is a private Mii.", 403);
            }
        }
    } else {
        next();
    }
});

site.use('/privateMiiQRs', async (req, res, next) => {
    const miiId = req.path.split('/').pop().split('.')[0];
    
    const privateMii = await Miis.findOne({ id: miiId, private: true }).lean();
    if (privateMii) {
        const isOwner = privateMii.uploader === req.user.username;
        const isModerator = req.user && canModerate(req.user);
        
        if (isOwner || isModerator) {
            next();
        } else {
            return sendError(res, req, "Access denied. This is a private Mii.", 403);
        }
    } else {
        next();
    }
});

// Static assets caching
site.use('/static', express.static(path.join(__dirname, 'static'), {
    maxAge: '7d',
    etag: true
}));

//#endregion

async function requireAuth(req, res, next) {
    if (!req.user) {
        // TODO_AUTH: redirect to /login with a ?next
        return sendError(res, req, "Authentication required.", 401);
    }
    next();
}
function requireRole(roles) {
    // Returns middleware when called
    if (!Array.isArray(roles)) {
        roles = [ roles  ];
    }
    return async (req, res, next) => {
        if (!req.user) {
            // TODO_AUTH: redirect to /login with a ?next
            await sendError(res, req, "Authentication required.", 401);
        }
        const userRoles = getUserRoles(req.user);
        const hasRequiredRole = roles.some(role => userRoles.includes(role));
        if (!hasRequiredRole && !userRoles.includes(ROLES.ADMINISTRATOR)) {
            return sendError(res, req, "Insufficient permissions.", 403);
        }
        next();
    }
}

connectionPromise.then(() => { // TODO: server error page if DB fails
    site.listen(process.env.PORT || 8080, async () => {
        console.log("Starting, do not stop...");

        // Ensure directories exist
        if (!fs.existsSync('./static/privateMiiImgs')) {
            fs.mkdirSync('./static/privateMiiImgs', { recursive: true });
        }
        if (!fs.existsSync('./static/privateMiiQRs')) {
            fs.mkdirSync('./static/privateMiiQRs', { recursive: true });
        }
        if (!fs.existsSync('./static/temp')) {
            fs.mkdirSync('./static/temp', { recursive: true });
        }

        // Initialize settings if not exists
        const settings = await getSettings();
        console.log("Settings initialized");

        // For Quickly Uploading Batches of Miis
        if (fs.existsSync('./quickUploads')) {
            await Promise.all(
                fs.readdirSync("./quickUploads").map(async (file) => {
                    let mii;
                    switch (file.split(".").pop().toLowerCase()) {
                        case "mii":
                            mii = await miijs.convertMii(await miijs.readWiiBin(`./quickUploads/${file}`));
                            break;
                        case "png"://Do the same as JPG
                        case "jpg":
                            mii = await miijs.read3DSQR(`./quickUploads/${file}`);
                            break;
                        case "txt"://Don't go to default handler, but don't do anything
                            return;
                        default:
                            fs.unlinkSync(`./quickUploads/${file}`);
                            return;
                    }

                    if (!mii) {
                        console.warn(`Couldn't read ${file}`);
                        fs.unlinkSync(`./quickUploads/${file}`);
                        return;
                    }

                    mii.uploadedOn = Date.now();
                    mii.uploader = fs.readFileSync("./quickUploads/uploader.txt", "utf-8");
                    mii.official = mii.uploader === "Nintendo";
                    mii.votes = 1;
                    mii.id = await genId();
                    mii.desc = "Uploaded in Bulk";
                    mii.private = false;
                    mii.published = true;

                    await Miis.create(mii);

                    fs.unlinkSync(`./quickUploads/${file}`);
                    console.log(`Added ${mii.meta.name} from quick uploads`);
                })
            );
            console.log("Finished Checking Quick Uploads Folder");
        }

        // For ensuring QRs are readable
        const qrFiles = fs.readdirSync("./static/miiQRs");
        await Promise.all(
            qrFiles.map(async (file) => {
                try {
                    if (!fs.existsSync(`./static/miiQRs/${file}`)) return;
                    const mii = await miijs.read3DSQR(`./static/miiQRs/${file}`);
                    if (!mii?.meta?.name) {
                        fs.unlinkSync(`./static/miiQRs/${file}`);
                    }
                }
                catch (e) {
                    fs.unlinkSync(`./static/miiQRs/${file}`);
                }
            })
        );
        console.log("Ensured QRs Are Readable For All Miis");

        // Make sure QRs and Thumbnails exist
        const allMiis = await Miis.find({}).lean();
        await Promise.all(
            allMiis.map(async (mii) => {
                const imgPath = mii.private ? `./static/privateMiiImgs/${mii.id}.png` : `./static/miiImgs/${mii.id}.png`;
                const qrPath = mii.private ? `./static/privateMiiQRs/${mii.id}.png` : `./static/miiQRs/${mii.id}.png`;

                if (!fs.existsSync(imgPath)) {
                    fs.writeFileSync(imgPath, await miijs.renderMii(mii));
                    console.log(`Making image for ${mii.id}`);
                }

                if (!fs.existsSync(qrPath)) {
                    miijs.write3DSQR(mii, qrPath);
                    console.log(`Making QR for ${mii.id}`);
                }
            })
        );
        console.log(`Ensured All Miis Have QRs And Face Renders\nGenerating new average Mii...`);
        await setAverageMii();
        setInterval(async () => await setAverageMii(), 1800000);//30 Mins

        // TODO: it's passing it without all the fields
        const avgMii = await getMiiById("average");

        if (avgMii) {
            fs.promises.writeFile(`./static/miiImgs/average.png`, await miijs.renderMii(avgMii)).catch(() => console.log);
            await miijs.write3DSQR(avgMii, `./static/miiQRs/average.png`).catch(() => console.log);
        }
        console.log(`All setup finished.\nOnline`);
    });
});

site.get('/', async (req, res) => {
    let toSend = await getSendables(req, "InfiniMii");
    toSend.title = "InfiniMii";
    toSend.miiCategories={
        "Random": { miis: (await paginatedApi("random", 1, 5)).items, link: "./random" },
        "Trending": { miis: (await paginatedApi("trending", 1, 5)).items, link: "./trending" },
        "Top": { miis: (await paginatedApi("top", 1, 5)).items, link: "./top" },
        "Recent": { miis: (await paginatedApi("recent", 1, 5)).items, link: "./recent" },
        "Official": { miis: (await paginatedApi("official", 1, 5)).items, link: "./official" }
    };
    
    ejs.renderFile(toSend.thisUser.toLowerCase() === "default" ? './ejsFiles/about.ejs' : './ejsFiles/index.ejs', toSend, {}, function (err, str) {
        if (err) {
            res.send(err);
            console.log(err);
            return;
        }
        res.send(str);
    });
});
//The following up to and including /recent are all sorted before being renders in miis.ejs, meaning the file is recycled. / is currently just a clone of /trending. /official and /search is more of the same but with a slight change to make Highlighted Mii still work without the full Mii array
site.get('/random', async (req, res) => {
    let toSend = await getSendables(req);
    const page = parseInt(req.query.page) || 1;
    const perPage = 30;
    
    // Get or generate seed: use query param if provided, otherwise generate random seed
    // On page 1 without seed, generate new random seed. On subsequent pages, seed must be passed.
    const seed = req.query.seed || Math.floor(Math.random() * 1000000).toString();
    
    const paginatedData = await paginatedApi("random", page, perPage, seed);
    toSend.displayedMiis = paginatedData.items;
    toSend.pagination = {
        currentPage: paginatedData.page,
        totalPages: paginatedData.totalPages,
        total: paginatedData.total,
        perPage: paginatedData.perPage,
        seed: paginatedData.seed // Pass seed to template for pagination links
    };
    
    toSend.title = "Random Miis - InfiniMii";
    ejs.renderFile('./ejsFiles/miis.ejs', toSend, {}, function(err, str) {
        if (err) {
            res.send(err);
            console.log(err);
            return;
        }
        res.send(str)
    });
});
site.get('/trending', async (req, res) => {
    let toSend = await getSendables(req);
    const page = parseInt(req.query.page) || 1;
    
    const paginatedData = await paginatedApi("trending", page, defaultMiisPerPage);
    toSend.displayedMiis = paginatedData.items;
    toSend.pagination = {
        currentPage: paginatedData.page,
        totalPages: paginatedData.totalPages,
        total: paginatedData.total,
        perPage: paginatedData.perPage
    };
    
    toSend.title = "Trending Miis - InfiniMii";
    ejs.renderFile('./ejsFiles/miis.ejs', toSend, {}, function(err, str) {
        if (err) {
            res.send(err);
            console.log(err);
            return;
        }
        res.send(str)
    });
});
site.get('/top', async (req, res) => {
    let toSend = await getSendables(req);
    const page = parseInt(req.query.page) || 1;
    
    const paginatedData = await paginatedApi("top", page, defaultMiisPerPage);
    toSend.displayedMiis = paginatedData.items;
    toSend.pagination = {
        currentPage: paginatedData.page,
        totalPages: paginatedData.totalPages,
        total: paginatedData.total,
        perPage: paginatedData.perPage
    };
    
    toSend.title = "Top Miis - InfiniMii";
    ejs.renderFile('./ejsFiles/miis.ejs', toSend, {}, function(err, str) {
        if (err) {
            res.send(err);
            console.log(err);
            return;
        }
        res.send(str)
    });
});
site.get('/recent', async (req, res) => {
    let toSend = await getSendables(req);
    const page = parseInt(req.query.page) || 1;    const perRow = 5;
    
    const paginatedData = await paginatedApi("recent", page, defaultMiisPerPage);
    toSend.displayedMiis = paginatedData.items;
    toSend.pagination = {
        currentPage: paginatedData.page,
        totalPages: paginatedData.totalPages,
        total: paginatedData.total,
        perPage: paginatedData.perPage
    };
    
    toSend.title = "Recent Miis - InfiniMii";
    ejs.renderFile('./ejsFiles/miis.ejs', toSend, {}, function(err, str) {
        if (err) {
            res.send(err);
            console.log(err);
            return;
        }
        res.send(str)
    });
});
site.get('/official', async (req, res) => {
    let toSend = await getSendables(req);
    
    const page = parseInt(req.query.page) || 1;
    const filterCategory = req.query.category;
    
    // Get settings for categories
    const settings = await getSettings();
    const categories = settings.officialCategories?.categories || [];
    
    // Get all unique leaf categories (only categories that can be assigned to Miis)
    const leafCategories = getAllLeafCategories(categories);
    
    // Create category info with paths for display
    toSend.availableCategories = leafCategories.map(cat => ({
        name: cat.name,
        path: cat.path,
        color: cat.color,
        fullPath: cat.path // Show full path for clarity
    }));
    
    // Sort categories by path
    toSend.availableCategories.sort((a, b) => a.path.localeCompare(b.path));
    
    // Get paginated official Miis
    const paginatedData = await paginatedApi("official", page, defaultMiisPerPage, filterCategory);
    toSend.displayedMiis = paginatedData.items;
    toSend.pagination = {
        currentPage: paginatedData.page,
        totalPages: paginatedData.totalPages,
        total: paginatedData.total,
        perPage: paginatedData.perPage
    };
    
    if (filterCategory) {
        toSend.currentFilter = filterCategory;
    }
    
    toSend.title = filterCategory 
        ? `Official Miis - ${filterCategory} - InfiniMii`
        : "Official Miis - InfiniMii";
    
    ejs.renderFile('./ejsFiles/official.ejs', toSend, {}, function(err, str) {
        if (err) {
            res.send(err);
            console.log(err);
            return;
        }
        res.send(str);
    });
});
site.get('/searchResults', async (req, res) => {
    let toSend = await getSendables(req);
    const page = parseInt(req.query.page) || 1;
    const searchQuery = req.query.q;
    
    const paginatedData = await paginatedApi("search", page, defaultMiisPerPage, searchQuery);
    toSend.displayedMiis = paginatedData.items;
    toSend.pagination = {
        currentPage: paginatedData.page,
        totalPages: paginatedData.totalPages,
        total: paginatedData.total,
        perPage: paginatedData.perPage
    };
    
    toSend.title = "Search '" + searchQuery + "' - InfiniMii";
    ejs.renderFile('./ejsFiles/miis.ejs', toSend, {}, function(err, str) {
        if (err) {
            res.send(err);
            console.log(err);
            return;
        }
        res.send(str)
    });
});
site.get('/search', async (req, res) => {
    ejs.renderFile('./ejsFiles/search.ejs', await getSendables(req), {}, function(err, str) {
        if (err) {
            res.send(err);
            console.log(err);
            return;
        }
        res.send(str)
    });
});
site.get('/transferInstructions', async (req, res) => {
    ejs.renderFile('./ejsFiles/transferInstructions.ejs', await getSendables(req), {}, function(err, str) {
        if (err) {
            res.send(err);
            console.log(err);
            return;
        }
        res.send(str)
    });
});
site.get('/upload', async (req, res) => {
    let toSend = await getSendables(req);
    toSend.fromAmiibo=req.query?.fromAmiibo;
    // Check if coming from Amiibo extraction
    if (req.query.fromAmiibo) {
        const tempMiiId = req.query.fromAmiibo;
        const tempImgPath = `./static/miiImgs/${tempMiiId}.png`;
        const tempBinPath = `./static/temp/${tempMiiId}.bin`;
        
        if (fs.existsSync(tempImgPath) && fs.existsSync(tempBinPath)) {
            // Read the Mii data
            try {
                const binData = fs.readFileSync(tempBinPath);
                const mii = await miijs.read3DSQR(binData, false);
                
                toSend.fromAmiibo = {
                    id: tempMiiId,
                    name: mii.meta.name || "Unknown",
                    creator: mii.meta.creatorName || "Unknown"
                };
            } catch (e) {
                console.error('Error reading temp Amiibo Mii:', e);
            }
        }
    }
    
    ejs.renderFile('./ejsFiles/upload.ejs', toSend, {}, function(err, str) {
        if (err) {
            res.send(err);
            console.log(err);
            return;
        }
        res.send(str)
    });
});
site.get('/api', async (req, res) => {
    try{
        res.json(await api(req.query.type,req.query.arg));
    }
    catch(e){
        res.json({error: "Invalid arguments"});
    }
});
site.get('/verify', async (req, res) => {
    try {
        const user = await getUserByUsername(req.query.user);
        if (!user) {
            res.json({error: "User not found"});
            return;
        }
        
        if (validatePassword(req.query.token, user.salt, user.verificationToken)) {
            await Users.findOneAndUpdate(
                { username: req.query.user },
                { 
                    $unset: { verificationToken: "" },
                    $set: { 
                        verified: true 
                    }
                }
            );
            
            // Get updated user and create JWT
            const updatedUser = await getUserByUsername(req.query.user);
            const jwtToken = createToken(updatedUser);
            
            res.cookie("username", req.query.user, { 
                maxAge: 30 * 24 * 60 * 60 * 1000 // 1 Month
            });
            res.cookie("token", jwtToken, { 
                maxAge: 30 * 24 * 60 * 60 * 1000, // 1 Month
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'lax'
            });
            // res.redirect("/");
            res.json({ redirect: "/" }); 
        }
        else {
            res.json({error: "Bad request"});
            return;
        }
    }
    catch (e) {
        res.send("Error");
        console.log(e);
    }
});
site.get('/deleteMii', async (req, res) => { // TODO: csrf here, make post
    try {
        if (!req.user) {
            res.json({error: "Not logged in"});
            return;
        }
        
        const isModerator = canModerate(req.user);
        const miiId = req.query.id;
        
        // Try to find the Mii (could be public or private)
        const mii = await getMiiById(miiId, true);
        const uploader = await getUserByUsername(mii.uploader);
        
        if (!mii) {
            res.json({error: "Mii not found"});
            return;
        }
        
        // Check permissions
        const canDelete = mii.uploader === req.user.username || isModerator;
        
        if (!canDelete) {
            res.json({error: "Permission denied"});
            return;
        }
        
        var d = new Date();
        const imgPath = mii.private ? `./static/privateMiiImgs/${mii.id}.png` : `./static/miiImgs/${mii.id}.png`;
        const qrPath = mii.private ? `./static/privateMiiQRs/${mii.id}.png` : `./static/miiQRs/${mii.id}.png`;
        
        let miiImageData;
        try {
            miiImageData = fs.readFileSync(imgPath);
        } catch(e) {
            miiImageData = null;
        }

        const attachments = miiImageData ? [{
            data: miiImageData,
            filename: `${mii.id}.png`,
            contentType: 'image/png'
        }] : [];

        makeReport(JSON.stringify({
            embeds: [{
                "type": "rich",
                "title": (mii.official ? "Official " : "") + (mii.private ? "Private " : "Published ") + `Mii Deleted by ` + req.cookies.username,
                "description": mii.desc,
                "color": mii.private ? 0xff6600 : 0xff0000,
                "fields": [
                    {
                        "name": `Mii Name`,
                        "value": mii.meta?.name,
                        "inline": true
                    },
                    {
                        "name": `${mii.official ? "Uploaded" : "Made"} by`,
                        "value": `[${mii.uploader}](https://infinimii.com/user/${encodeURIComponent(mii.uploader)})`,
                        "inline": true
                    },
                    {
                        "name": `Mii Creator Name (embedded in Mii file)`,
                        "value": mii.meta.creatorName,
                        "inline": true
                    }
                ],
                ...(miiImageData ? {
                    "image": {
                        "url": `attachment://${mii.id}.png`
                    }
                } : {}),
                "footer": {
                    "text": `Deleted at ${d.getHours()}:${d.getMinutes()}, ${d.toDateString()} UTC`
                }
            }]
        }), attachments);
        
        // Delete from database
        await Miis.findOneAndDelete({ id: miiId });
        
        // Delete files
        try { fs.unlinkSync(imgPath); } catch(e) {}
        try { fs.unlinkSync(qrPath); } catch(e) {}
        
        res.json({ okay: true });
        
        if(mii.uploader!==uploader.username) sendEmail(uploader.email,`Mii Deleted - InfiniMii`,`Hi ${mii.uploader}, one of your Miis "${mii.meta.name}" has been deleted by a Moderator. You can reply to this email to receive support.`);
    }
    catch (e) {
        console.error('Delete Mii error:', e);
        res.json({error: "Server error"});
    }
});
// Update Mii Field (Moderator only)
site.post('/updateMiiField', requireAuth, requireRole(ROLES.MODERATOR), async (req, res) => {
    try {
        const { id, field, value } = req.body;

        if (!id || !field || value === undefined) {
            return res.json({ error: 'Missing parameters' });
        }

        const mii = await getMiiById(id);
        if (!mii) {
            return res.json({ error: 'Mii not found' });
        }

        // Store old value for logging
        let oldValue;
        let updates = {};

        // Update the appropriate field
        switch (field) {
            case 'name':
                oldValue = mii.meta.name;
                updates['meta.name'] = value;
                break;
            case 'desc':
                oldValue = mii.desc;
                updates.desc = value;
                break;
            case 'creatorName':
                oldValue = mii.meta.creatorName;
                updates['meta.creatorName'] = value;
                break;
            case 'uploader':
                // Validate new uploader exists
                const newUploader = await getUserByUsername(value);
                if (!newUploader) {
                    return res.json({ error: 'User does not exist' });
                }
                
                oldValue = mii.uploader;
                
                updates.uploader = value;
                break;
            default:
                return res.json({ error: 'Invalid field' });
        }

        await Miis.findOneAndUpdate({ id }, { $set: updates });

        // Log to Discord
        makeReport(JSON.stringify({
            embeds: [{
                type: 'rich',
                title: `🛠️ Mii ${field} Updated`,
                description: `Moderator ${req.cookies.username} updated ${field}`,
                color: 0xFFA500,
                fields: [
                    {
                        name: 'Mii',
                        value: `[${mii.meta.name}](https://infinimii.com/mii/${id})`,
                        inline: true
                    },
                    {
                        name: 'Field',
                        value: field,
                        inline: true
                    },
                    {
                        name: 'Old Value',
                        value: oldValue || 'N/A',
                        inline: false
                    },
                    {
                        name: 'New Value',
                        value: value,
                        inline: false
                    }
                ],
                thumbnail: {
                    url: `https://infinimii.com/miiImgs/${id}.png`
                }
            }]
        }));

        res.json({ okay: true });
    } catch (e) {
        console.error('Error updating Mii field:', e);
        res.json({ error: 'Server error' });
    }
});
// Regenerate QR Code (Moderator only)
site.get('/regenerateQR', requireAuth, requireRole(ROLES.MODERATOR), async (req, res) => {
    try {
        const { id } = req.query;
        const mii = await getMiiById(id);

        if (!mii) {
            return res.json({ error: 'Mii not found' });
        }

        // Regenerate the QR code
        await miijs.write3DSQR(mii, `./static/miiQRs/${id}.png`);

        // Log to Discord
        makeReport(JSON.stringify({
            embeds: [{
                type: 'rich',
                title: '🔄 QR Code Regenerated',
                description: `Moderator ${req.cookies.username} regenerated QR code`,
                color: 0x00AFF0,
                fields: [
                    {
                        name: 'Mii',
                        value: `[${mii.meta.name}](https://infinimii.com/mii/${id})`,
                        inline: true
                    }
                ],
                thumbnail: {
                    url: `https://infinimii.com/miiImgs/${id}.png`
                }
            }]
        }));

        res.json({ okay: true });
    } catch (e) {
        console.error('Error regenerating QR:', e);
        res.json({ error: 'Server error' });
    }
});
// Add Role to User (Admin only)
site.post('/addUserRole', requireAuth, requireRole(ROLES.ADMINISTRATOR), async (req, res) => {
    try {
        const { username, role } = req.body;
        const targetUser = await getUserByUsername(username);

        if (!targetUser) {
            return res.json({ error: 'User not found' });
        }

        if (!Object.values(ROLES).includes(role)) {
            return res.json({ error: 'Invalid role' });
        }

        addRole(targetUser, role);
        await Users.findOneAndUpdate({ username }, { roles: targetUser.roles });

        makeReport(JSON.stringify({
            embeds: [{
                type: 'rich',
                title: '➕ Role Added to User',
                description: `Administrator ${req.cookies.username} added a role`,
                color: 0x00FF00,
                fields: [
                    {
                        name: 'User',
                        value: username,
                        inline: true
                    },
                    {
                        name: 'Role Added',
                        value: ROLE_DISPLAY[role],
                        inline: true
                    },
                    {
                        name: 'Current Roles',
                        value: getUserRoles(targetUser).map(r => ROLE_DISPLAY[r]).join(', '),
                        inline: false
                    }
                ]
            }]
        }));
        if(['researcher','moderator','administrator'].includes(role.toLowerCase())){
            sendEmail(targetUser.email,`New Role Added - InfiniMii`,`Congratulations ${username}, you were made a ${role[0].toUpperCase()}${role.slice(1,role.length)} on InfiniMii!`);
        }

        res.json({ roles: targetUser.roles });
    } catch (e) {
        console.error('Error adding user role:', e);
        res.json({ error: 'Server error' });
    }
});

// Remove Role from User (Admin only)
site.post('/removeUserRole', requireAuth, requireRole(ROLES.ADMINISTRATOR), async (req, res) => {
    try {
        const { username, role } = req.body;
        const targetUser = await getUserByUsername(username);

        if (!targetUser) {
            return res.json({ error: 'User not found' });
        }

        removeRole(targetUser, role);
        await Users.findOneAndUpdate({ username }, { roles: targetUser.roles });

        makeReport(JSON.stringify({
            embeds: [{
                type: 'rich',
                title: '➖ Role Removed from User',
                description: `Administrator ${req.cookies.username} removed a role`,
                color: 0xFF9900,
                fields: [
                    {
                        name: 'User',
                        value: username,
                        inline: true
                    },
                    {
                        name: 'Role Removed',
                        value: ROLE_DISPLAY[role],
                        inline: true
                    },
                    {
                        name: 'Current Roles',
                        value: getUserRoles(targetUser).map(r => ROLE_DISPLAY[r]).join(', '),
                        inline: false
                    }
                ]
            }]
        }));

        res.json({ roles: targetUser.roles });
    } catch (e) {
        console.error('Error removing user role:', e);
        res.json({ error: 'Server error' });
    }
});

// Temporary Ban User (Moderator+)
site.post('/tempBanUser', requireAuth, requireRole(ROLES.MODERATOR), async (req, res) => {
    try {
        const { username, hours, reason } = req.body;
        const targetUser = await getUserByUsername(username);

        if (!targetUser) {
            return res.json({ error: 'User not found' });
        }

        // Moderators can't ban admins or other moderators
        if (!isAdmin(req.user) && canModerate(targetUser)) {
            return res.json({ error: 'Cannot ban moderators or administrators' });
        }

        addRole(targetUser, ROLES.TEMP_BANNED);
        const banExpires = Date.now() + (hours * 60 * 60 * 1000);
        
        await Users.findOneAndUpdate(
            { username },
            {
                $set: {
                    roles: targetUser.roles,
                    banExpires,
                    banReason: reason
                }
            }
        );

        makeReport(JSON.stringify({
            embeds: [{
                type: 'rich',
                title: '⏰ User Temporarily Banned',
                description: `${req.cookies.username} temporarily banned a user`,
                color: 0xFF9900,
                fields: [
                    {
                        name: 'User',
                        value: username,
                        inline: true
                    },
                    {
                        name: 'Duration',
                        value: `${hours} hours`,
                        inline: true
                    },
                    {
                        name: 'Reason',
                        value: reason || 'No reason provided',
                        inline: false
                    }
                ]
            }]
        }));
        sendEmail(targetUser.email,`Ban - InfiniMii`,`Hi ${username}, you were banned on InfiniMii for the next ${hours}. ${reason?`Reason: ${reason}`:`No reason was specified at this time.`} Understand that repeated violations may result in a permanent ban and account deletion. You may reply to this email for support.`);

        res.json({ okay: true });
    } catch (e) {
        console.error('Error temp banning user:', e);
        res.json({ error: 'Server error' });
    }
});

// Permanent Ban User (Admin only)
site.post('/permBanUser', requireAuth, requireRole(ROLES.ADMINISTRATOR), async (req, res) => {
    try {
        const { username, reason } = req.body;
        const targetUser = await getUserByUsername(username);

        if (!targetUser) {
            return res.json({ error: 'User not found' });
        }

        // TODO: uuuh. This is banning the IP of the admin. Not the user. Check the other endpoint too.
        const clientIP = [req.headers['x-forwarded-for'], req.socket.remoteAddress];
        
        // Ban IP if not VPN - TODO: this should definitely still ban VPN IPs...
        if (!isVPN(clientIP[0]) && !isVPN(clientIP[1])) {
            const ipHash = sha256(clientIP);
            const settings = await getSettings();
            if (!settings.bannedIPs.includes(ipHash)) {
                await updateSettings({ $addToSet: { bannedIPs: ipHash } });
            }
        }

        // Delete all user's Miis
        const userMiis = await Miis.find({ uploader: targetUser.username }).select('id').lean();
        const miiIds = userMiis.map(m => m.id);
        for (const miiId of miiIds) {
            try {
                const mii = await getMiiById(miiId);
                if (mii) {
                    // Delete files
                    try { fs.unlinkSync(`./static/miiImgs/${miiId}.png`); } catch(e) {}
                    try { fs.unlinkSync(`./static/miiQRs/${miiId}.png`); } catch(e) {}
                    
                    // Delete Mii from DB
                    await Miis.findOneAndDelete({ id: miiId });
                }
            } catch(e) {
                console.error(`Error deleting Mii ${miiId}:`, e);
            }
        }

        // Delete user account
        await Users.findOneAndDelete({ username });

        makeReport(JSON.stringify({
            embeds: [{
                type: 'rich',
                title: '⛔ User Permanently Banned',
                description: `${req.cookies.username} permanently banned a user`,
                color: 0xFF0000,
                fields: [
                    {
                        name: 'User',
                        value: username,
                        inline: true
                    },
                    {
                        name: 'Miis Deleted',
                        value: miiIds.length.toString(),
                        inline: true
                    },
                    {
                        name: 'IP Banned',
                        value: !isVPN(clientIP) ? 'Yes' : 'No (VPN detected)',
                        inline: true
                    },
                    {
                        name: 'Reason',
                        value: reason || 'No reason provided',
                        inline: false
                    }
                ]
            }]
        }));
        sendEmail(targetUser.email,`Permanent Ban - InfiniMii`,`Hi ${username}, due to repeated and/or serious violations of rules on InfiniMii, you have been permanently banned from the website. ${reason?`Reason: ${reason}`:`No reason was provided at this time.`} This will prevent you from making any new accounts in the future, and all uploaded Miis have been deleted. If you feel this is in error, you may reply to this email to receive support.`)

        res.json({ okay: true });
    } catch (e) {
        console.error('Error perm banning user:', e);
        res.json({ error: 'Server error' });
    }
});

// Delete All User Miis (Moderator+)
site.post('/deleteAllUserMiis', requireAuth, requireRole(ROLES.MODERATOR), async (req, res) => {
    try {
        const { username } = req.body;
        const targetUser = await getUserByUsername(username);

        if (!targetUser) {
            return res.json({ error: 'User not found' });
        }

        const userMiis = await Miis.find({ uploader: targetUser.username }).select('id').lean();
        const miiIds = userMiis.map(m => m.id);
        let deletedCount = 0;

        for (const miiId of miiIds) {
            try {
                const mii = await getMiiById(miiId);
                if (mii) {
                    // Delete files
                    try { fs.unlinkSync(`./static/miiImgs/${miiId}.png`); } catch(e) {}
                    try { fs.unlinkSync(`./static/miiQRs/${miiId}.png`); } catch(e) {}
                    
                    // Delete Mii from DB
                    await Miis.findOneAndDelete({ id: miiId });
                    deletedCount++;
                }
            } catch(e) {
                console.error(`Error deleting Mii ${miiId}:`, e);
            }
        }

        makeReport(JSON.stringify({
            embeds: [{
                type: 'rich',
                title: '🗑️ All User Miis Deleted',
                description: `${req.cookies.username} deleted all Miis from user ${username}`,
                color: 0xFF6600,
                fields: [
                    {
                        name: 'User',
                        value: username,
                        inline: true
                    },
                    {
                        name: 'Miis Deleted',
                        value: deletedCount.toString(),
                        inline: true
                    }
                ]
            }]
        }));
        //There is very very little reason this will not precede a ban, so we're not going to bother emailing the user for this one.

        res.json({ deletedCount });
    } catch (e) {
        console.error('Error deleting all user Miis:', e);
        res.json({ error: 'Server error' });
    }
});

// Change Username (Moderator+)
site.post('/changeUsername', requireAuth, requireRole(ROLES.MODERATOR), async (req, res) => {
    try {
        const { oldUsername, newUsername } = req.body;

        if (!validate(newUsername)) {
            return res.json({ error: 'Invalid username format' });
        }

        const existing = await getUserByUsername(newUsername);
        if (existing) {
            return res.json({ error: 'Username already taken' });
        }

        const user = await getUserByUsername(oldUsername);
        if (!user) {
            return res.json({ error: 'User not found' });
        }

        // Update username in User document
        await Users.findOneAndUpdate(
            { username: oldUsername },
            { $set: { username: newUsername } }
        );

        // Update uploader field in all user's Miis
        await Miis.updateMany(
            { uploader: oldUsername },
            { $set: { uploader: newUsername } }
        );

        makeReport(JSON.stringify({
            embeds: [{
                type: 'rich',
                title: '✏️ Username Changed',
                description: `${req.cookies.username} changed a username`,
                color: 0x00FF00,
                fields: [
                    {
                        name: 'Old Username',
                        value: oldUsername,
                        inline: true
                    },
                    {
                        name: 'New Username',
                        value: newUsername,
                        inline: true
                    }
                ]
            }]
        }));
        sendEmail(user.email,`Username Changed - InfiniMii`,`Hi ${oldUsername}, a moderator has changed your username to ${newUsername}. This will be what you login with moving forward. You can reply to this email to receive support.`);

        res.json({ okay: true });
    } catch (e) {
        console.error('Error changing username:', e);
        res.json({ error: 'Server error' });
    }
});

// Toggle Mii Official Status (Moderator+)
site.post('/toggleMiiOfficial', requireAuth, requireRole(ROLES.MODERATOR), async (req, res) => {
    try {
        const { id, official } = req.body;

        if (!id || official === undefined) {
            return res.json({ error: 'Missing parameters' });
        }

        const mii = await getMiiById(id, false);
        if (!mii) {
            return res.json({ error: 'Mii not found' });
        }

        const oldStatus = mii.official;
        
        await Miis.findOneAndUpdate(
            { id },
            { official }
        );

        // Log to Discord
        makeReport(JSON.stringify({
            embeds: [{
                type: 'rich',
                title: official ? '⭐ Mii Marked as Official' : '❌ Mii Unmarked as Official',
                description: `Moderator ${req.cookies.username} changed official status`,
                color: official ? 0xFFD700 : 0x808080,
                fields: [
                    {
                        name: 'Mii',
                        value: `[${mii.meta.name}](https://infinimii.com/mii/${id})`,
                        inline: true
                    },
                    {
                        name: 'Old Status',
                        value: oldStatus ? 'Official' : 'Not Official',
                        inline: true
                    },
                    {
                        name: 'New Status',
                        value: official ? 'Official' : 'Not Official',
                        inline: true
                    }
                ],
                thumbnail: {
                    url: `https://infinimii.com/miiImgs/${id}.png`
                }
            }]
        }));

        res.json({ okay: true });
    } catch (e) {
        console.error('Error toggling official status:', e);
        res.json({ error: 'Server error' });
    }
});

// Main sitemap endpoint
site.get('/sitemap.xml', async (req, res) => {
    const urls = [
        {
            loc: baseUrl + '/',
            lastmod: new Date().toISOString().split('T')[0],
            changefreq: 'daily',
            priority: '1.0'
        },
        {
            loc: baseUrl + '/random',
            changefreq: 'always',
            priority: '0.8'
        },
        {
            loc: baseUrl + '/trending',
            changefreq: 'hourly',
            priority: '0.9'
        },
        {
            loc: baseUrl + '/top',
            changefreq: 'daily',
            priority: '0.9'
        },
        {
            loc: baseUrl + '/recent',
            changefreq: 'hourly',
            priority: '0.8'
        },
        {
            loc: baseUrl + '/official',
            changefreq: 'weekly',
            priority: '0.9'
        },
        {
            loc: baseUrl + '/search',
            changefreq: 'monthly',
            priority: '0.7'
        },
        {
            loc: baseUrl + '/upload',
            changefreq: 'monthly',
            priority: '0.6'
        },
        {
            loc: baseUrl + '/convert',
            changefreq: 'monthly',
            priority: '0.7'
        },
        {
            loc: baseUrl + '/qr',
            changefreq: 'monthly',
            priority: '0.7'
        }
    ];
    
    res.header('Content-Type', 'application/xml');
    res.send(generateSitemapXML(urls));
});

// Mii-specific sitemap (separate for better organization)
site.get('/sitemap-miis.xml', async (req, res) => {
    const urls = [];
    
    // Add all published Miis
    const allMiis = await getAllMiis(false);
    allMiis.forEach(mii => {
        const lastmod = mii.uploadedOn ? new Date(mii.uploadedOn).toISOString().split('T')[0] : new Date().toISOString().split('T')[0];
        
        urls.push({
            loc: `${baseUrl}/mii/${miiId}`,
            lastmod: lastmod,
            changefreq: 'weekly',
            priority: mii.official ? '0.9' : '0.7',
            images: [
                {
                    loc: `${baseUrl}/miiImgs/${miiId}.png`,
                    title: `${mii.meta.name} - Mii Character`,
                    caption: mii.desc || `${mii.meta.name} Mii character for Nintendo systems`
                },
                {
                    loc: `${baseUrl}/miiQRs/${miiId}.png`,
                    title: `${mii.meta.name} - QR Code`,
                    caption: `QR Code for ${mii.meta.name} - Scan with 3DS, Wii U, Tomodachi Life, or Miitomo`
                }
            ]
        });
    });
    
    res.header('Content-Type', 'application/xml');
    res.send(generateSitemapXML(urls));
});

// User profiles sitemap
site.get('/sitemap-users.xml', async (req, res) => {
    const urls = [];
    
    const allUsers = await getAllUsers();
    allUsers.forEach(user => {
        if (user.username !== 'default' && user.username !== 'Nintendo') {
            urls.push({
                loc: `${baseUrl}/user/${encodeURIComponent(user.username)}`,
                changefreq: 'weekly',
                priority: '0.6'
            });
        }
    });
    
    res.header('Content-Type', 'application/xml');
    res.send(generateSitemapXML(urls));
});

// Sitemap index
site.get('/sitemap-index.xml', async (req, res) => {
    let xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
    xml += '<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n';
    
    const sitemaps = [
        { loc: `${baseUrl}/sitemap.xml`, lastmod: new Date().toISOString().split('T')[0] },
        { loc: `${baseUrl}/sitemap-miis.xml`, lastmod: new Date().toISOString().split('T')[0] },
        { loc: `${baseUrl}/sitemap-users.xml`, lastmod: new Date().toISOString().split('T')[0] }
    ];
    
    sitemaps.forEach(sitemap => {
        xml += '  <sitemap>\n';
        xml += `    <loc>${sitemap.loc}</loc>\n`;
        xml += `    <lastmod>${sitemap.lastmod}</lastmod>\n`;
        xml += '  </sitemap>\n';
    });
    
    xml += '</sitemapindex>';
    
    res.header('Content-Type', 'application/xml');
    res.send(xml);
});

// ========== AMIIBO ENDPOINTS ==========

// Amiibo tools page
site.get('/amiibo', async (req, res) => {
    ejs.renderFile('./ejsFiles/amiibo.ejs', await getSendables(req), {}, function(err, str) {
        if (err) {
            res.send(err);
            console.log(err);
            return;
        }
        res.send(str)
    });
});

// Extract Mii from Amiibo
// Extract Mii from Amiibo
site.post('/extractMiiFromAmiibo', upload.single('amiibo'), async (req, res) => {
    try {
        if (!req.file) {
            res.json({ error: 'No Amiibo file uploaded' });
            return;
        }
        
        // Read the Amiibo dump
        const amiiboDump = fs.readFileSync("./uploads/" + req.file.filename);
        
        // Extract Mii data (92 bytes, decrypted 3DS format)
        const miiData = miijs.extractMiiFromAmiibo(amiiboDump);
        
        // Convert to JSON - miiData is already decrypted 3DS format
        const mii = await miijs.read3DSQR(miiData);
        
        // Generate ID and save temporarily
        const tempId = await genId();
        mii.id = tempId;
        mii.uploadedOn = Date.now();
        mii.uploader = "temp_" + tempId;
        mii.desc = "Extracted from Amiibo";
        mii.votes = 0;
        mii.official = false;
        
        // Render images with FFL - save to temp location
        const miiImage = await miijs.renderMii(mii);
        fs.writeFileSync("./static/miiImgs/" + tempId + ".png", miiImage);
        await miijs.write3DSQR(mii, "./static/miiQRs/" + tempId + ".png");
        
        // Also save the decrypted bin data for upload
        fs.writeFileSync("./static/temp/" + tempId + ".bin", miiData);
        
        // Clean up upload
        try { fs.unlinkSync("./uploads/" + req.file.filename); } catch (e) { }
        
        res.json({ mii: mii });
    } catch (e) {
        console.error('Error extracting Mii from Amiibo:', e);
        try { fs.unlinkSync("./uploads/" + req.file.filename); } catch (e) { }
        res.json({ error: 'Failed to extract Mii from Amiibo: ' + e.message }); // TODO: don't send message
    }
});

// Insert Mii into Amiibo
// Insert Mii into Amiibo
site.post('/insertMiiIntoAmiibo', upload.fields([
    { name: 'amiibo', maxCount: 1 },
    { name: 'mii', maxCount: 1 }
]), async (req, res) => {
    try {
        if (!req.files.amiibo || !req.files.amiibo[0]) {
            res.json({ error: 'No Amiibo file uploaded' });
            return;
        }
        
        // Read the Amiibo dump
        const amiiboDump = fs.readFileSync(req.files.amiibo[0].path);
        
        let miiData;
        const source = req.body.miiSource;
        
        // Get Mii data based on source
        if (source === 'file') {
            if (!req.files.mii || !req.files.mii[0]) {
                res.json({ error: 'No Mii file uploaded' });
                try { fs.unlinkSync(req.files.amiibo[0].path); } catch (e) { }
                return;
            }
            
            let mii;
            const miiType = req.body.miiType;
            
            if (miiType === 'wii') {
                mii = await miijs.readWiiBin(req.files.mii[0].path);
                mii = miijs.convertMii(mii, '3ds');
            }
            else if (miiType === '3ds') {
                mii = await miijs.read3DSQR(req.files.mii[0].path);
            }
            else if (miiType === '3dsbin') {
                // Handle both encrypted and decrypted bins
                const binData = fs.readFileSync(req.files.mii[0].path);
                mii = await miijs.read3DSQR(binData, false);
            }
            
            // Get decrypted binary data (92 bytes)
            // We need to convert the Mii back to binary format
            const tempQrPath = "./static/temp/" + await genId() + ".png";
            await miijs.write3DSQR(mii, tempQrPath);
            miiData = await miijs.read3DSQR(tempQrPath, true);
            try { fs.unlinkSync(tempQrPath); } catch (e) { }
            
            try { fs.unlinkSync(req.files.mii[0].path); } catch (e) { }
            
        }
        else if (source === 'miiId') {
            const miiId = req.body.miiId;
            
            if (!miiId || !miiId.trim()) {
                res.json({ error: 'No Mii ID provided' });
                try { fs.unlinkSync(req.files.amiibo[0].path); } catch (e) { }
                return;
            }
            
            let mii = null;
            
            // Check published Miis first
            mii = await getMiiById(miiId, false);
            
            // Check private Miis
            if (!mii) {
                const privateMii = await Miis.findOne({ id: miiId, private: true });
                if (privateMii) {
                    const user = await getUserByUsername(req.cookies.username);
                    const isModerator = user && canModerate(user);
                    const isOwner = privateMii.uploader === req.cookies.username;
                
                    if (!isOwner && !isModerator) {
                        res.json({ error: 'You do not have permission to use this private Mii' });
                        try { fs.unlinkSync(req.files.amiibo[0].path); } catch (e) { }
                        return;
                    }
                    
                    mii = privateMii;
                }
            }
            
            if (!mii) {
                res.json({ error: 'Invalid Mii ID - Mii not found' });
                try { fs.unlinkSync(req.files.amiibo[0].path); } catch (e) { }
                return;
            }
            
            // Convert Mii to 3DS format if needed
            if (mii.console?.toLowerCase() !== "3ds" && mii.console?.toLowerCase() !== "wii u") {
                mii = miijs.convertMii(mii, "3ds");
            }
            
            // Generate temporary QR and extract binary
            const tempPath = `./static/temp/${await genId()}.png`;
            try {
                await miijs.write3DSQR(mii, tempPath);
                miiData = await miijs.read3DSQR(tempPath, true);
                fs.unlinkSync(tempPath);
            } catch (e) {
                console.error('Error converting Mii to binary:', e);
                res.json({ error: 'Failed to convert Mii data: ' + e.message });  // TODO: remove e.message
                try { fs.unlinkSync(req.files.amiibo[0].path); } catch (e2) { }
                try { fs.unlinkSync(tempPath); } catch (e2) { }
                return;
            }
        }
        else if (source === 'studio') {
            let studioCode = req.body.studioCode.trim();
            
            // Extract code from URL if provided
            if (studioCode.includes('studio.mii.nintendo.com')) {
                const match = studioCode.match(/data=([0-9a-fA-F]+)/);
                if (match) studioCode = match[1];
            }
            
            // Convert Studio to 3DS format
            const mii = miijs.convertStudioToMii(studioCode);
            
            // Write temporary QR and extract binary
            const tempPath = "./static/temp/" + await genId() + ".png";
            await miijs.write3DSQR(mii, tempPath);
            miiData = await miijs.read3DSQR(tempPath, true);
            try { fs.unlinkSync(tempPath); } catch (e) { }
        }
        else {
            res.json({ error: 'Invalid Mii source' });
            try { fs.unlinkSync(req.files.amiibo[0].path); } catch (e) { }
            return;
        }
        
        // Ensure miiData is a Buffer
        if (!(miiData instanceof Buffer)) {
            if (miiData instanceof Uint8Array) {
                miiData = Buffer.from(miiData);
            } else {
                throw new Error('Mii data is not in the correct format');
            }
        }
        
        // Validate miiData length (should be 92 bytes for decrypted 3DS Mii)
        if (miiData.length !== 92) {
            throw new Error(`Invalid Mii data length: ${miiData.length} bytes (expected 92)`);
        }
        
        console.log('Inserting Mii data:', miiData.length, 'bytes');
        
        // Insert Mii into Amiibo
        const modifiedAmiibo = miijs.insertMiiIntoAmiibo(amiiboDump, miiData);
        
        // Clean up
        try { fs.unlinkSync(req.files.amiibo[0].path); } catch (e) { }
        
        // Send modified Amiibo
        res.setHeader('Content-Disposition', 'attachment; filename="amiibo_modified.bin"');
        res.setHeader('Content-Type', 'application/octet-stream');
        res.send(modifiedAmiibo);
        
    } catch (e) {
        console.error('Error inserting Mii into Amiibo:', e);
        try { 
            if (req.files.amiibo) fs.unlinkSync(req.files.amiibo[0].path);
            if (req.files.mii) fs.unlinkSync(req.files.mii[0].path);
        } catch (cleanupErr) { }
        res.json({ error: 'Failed to insert Mii into Amiibo: ' + e.message });
    }
});
// Upload extracted Amiibo Mii
site.post('/uploadExtractedAmiibo', async (req, res) => {
    try {
        // Check authentication
        if (!req.user) {
            res.json({error: "Please log in to upload Miis"});
            return;
        }
        const tempMiiId = req.body.miiId;
        
        // Check private Mii limit
        const privateMiisCount = await Miis.countDocuments({ uploader: req.user.username, private: true });
        if (privateMiisCount >= PRIVATE_MII_LIMIT) {
            res.json({error: `You have reached the limit of ${PRIVATE_MII_LIMIT} private Miis. Please publish or delete some before uploading more.`});
            return;
        }
        
        // Check if temporary files exist
        const tempImgPath = `./static/miiImgs/${tempMiiId}.png`;
        const tempQrPath = `./static/miiQRs/${tempMiiId}.png`;
        
        if (!fs.existsSync(tempImgPath) || !fs.existsSync(tempQrPath)) {
            res.json({error: "Extracted Mii data not found. Please extract again."});
            return;
        }
        
        // Generate new ID for the actual upload
        const newMiiId = await genId();
        
        // Move files from temp location to private folders
        fs.renameSync(tempImgPath, `./static/privateMiiImgs/${newMiiId}.png`);
        fs.renameSync(tempQrPath, `./static/privateMiiQRs/${newMiiId}.png`);
        
        // Create the Mii object (we need to reconstruct it from the QR)
        const mii = await miijs.read3DSQR(`./static/privateMiiQRs/${newMiiId}.png`);
        mii.id = newMiiId;
        mii.uploadedOn = Date.now();
        mii.uploader = req.user.username;
        mii.desc = "Extracted from Amiibo";
        mii.votes = 1;
        mii.official = false;
        mii.published = false;
        mii.blockedFromPublishing = false;
        
        // Store in database as private Mii
        await Miis.create({
            ...mii,
            id: newMiiId,
            private: true
        });
        
        // Send to Discord for moderator review
        var d = new Date();
        const miiImagePath = `./static/privateMiiImgs/${newMiiId}.png`;
        const miiImageData = fs.readFileSync(miiImagePath);

        makeReport(JSON.stringify({
            embeds: [{
                "type": "rich",
                "title": `Private Mii Uploaded (Extracted from Amiibo)`,
                "description": mii.desc,
                "color": 0x00aaff,
                "fields": [
                    {
                        "name": `Mii Name`,
                        "value": mii.meta?.name || "Unknown",
                        "inline": true
                    },
                    {
                        "name": `Uploaded by`,
                        "value": `[${username}](https://miis.kestron.com/user/${encodeURIComponent(username)})`,
                        "inline": true
                    },
                    {
                        "name": `Mii Creator Name`,
                        "value": mii.meta?.creatorName || "Unknown",
                        "inline": true
                    }
                ],
                "image": {
                    "url": `attachment://${newMiiId}.png`
                },
                "footer": {
                    "text": `View: https://miis.kestron.com/mii/${newMiiId} | Uploaded at ${d.getHours()}:${d.getMinutes()}, ${d.toDateString()} UTC`
                }
            }]
        }), [
            {
                data: miiImageData,
                filename: `${newMiiId}.png`,
                contentType: 'image/png'
            }
        ]);
        
        // Redirect to private Miis page
        // res.redirect("/myPrivateMiis");
        res.json({ redirect: "/myPrivateMiis" }); 
        
    } catch (e) {
        console.error('Error uploading extracted Amiibo Mii:', e);
        res.json({error: "Server error: " + e.message});
    }
});
// ========== STUDIO ENDPOINTS ==========

// Upload Mii from Studio code
site.post('/uploadStudioMii', requireAuth, async (req, res) => {
    try {
        let uploader = req.user.username;
        
        // Check private Mii limit
        const privateMiisCount = await Miis.countDocuments({ uploader: req.user.username, private: true });
        if (privateMiisCount >= Number(PRIVATE_MII_LIMIT)) {
            res.json({error: `You have reached the limit of ${PRIVATE_MII_LIMIT} private Miis. Please publish or delete some before uploading more.`});
            return;
        }
        
        // Check if trying to upload official Mii without permission
        if (req.body.official && !canUploadOfficial(req.user)) {
            res.json({error: 'Only Researchers and Administrators can upload official Miis'});
            return;
        }
        
        let studioCode = req.body.studioCode.trim();
        
        // Extract code from URL if provided
        if (studioCode.includes('studio.mii.nintendo.com')) {
            const match = studioCode.match(/data=([0-9a-fA-F]+)/);
            if (match) {
                studioCode = match[1];
            }
        }
        
        // Validate hex format
        if (!/^[0-9a-fA-F]+$/.test(studioCode)) {
            res.json({error: "Invalid Studio code format"});
            return;
        }
        
        // Convert Studio to 3DS Mii
        const mii = miijs.convertStudioToMii(studioCode);
        
        mii.id = await genId();
        mii.uploadedOn = Date.now();
        mii.uploader = req.body.official ? "Nintendo" : uploader;
        mii.desc = req.body.desc || "";
        mii.votes = 1;
        mii.official = req.body.official || false;
        mii.published = false;
        mii.blockedFromPublishing = false;
        
        // Add official Mii categorization
        if (req.body.official) {
            mii.officialCategories = [];
            
            // Parse categories (now stores paths instead of names)
            if (req.body.categories) {
                const categories = Array.isArray(req.body.categories) ? req.body.categories : [req.body.categories];
                mii.officialCategories = [...new Set(categories.filter(c => c && c.trim()))];
            }
        }
        
        // Render images using LOCAL FFL, not Studio
        const miiImageData = await miijs.renderMii(mii);
        fs.writeFileSync("./static/privateMiiImgs/" + mii.id + ".png", miiImageData);
        await miijs.write3DSQR(mii, "./static/privateMiiQRs/" + mii.id + ".png");
        
        // Store in database as private Mii
        await Miis.create({
            ...mii,
            id: mii.id,
            private: true
        });
        
        // Send to Discord for moderator review
        var d = new Date();
        makeReport(JSON.stringify({
            embeds: [{
                "type": "rich",
                "title": (req.body.official ? "Official " : "") + `Private Mii Uploaded from Studio`,
                "description": mii.desc,
                "color": 0x00aaff,
                "fields": [
                    {
                        "name": `Mii Name`,
                        "value": mii.meta?.name || "Unknown",
                        "inline": true
                    },
                    {
                        "name": `Uploaded by`,
                        "value": `[${uploader}](https://infinimii.com/user/${encodeURIComponent(uploader)})`,
                        "inline": true
                    },
                    {
                        "name": `Mii Creator Name`,
                        "value": mii.meta?.creatorName || "Unknown",
                        "inline": true
                    }
                ],
                "image": {
                    "url": `attachment://${mii.id}.png`
                },
                "footer": {
                    "text": `View: https://infinimii.com/mii/${mii.id} | Uploaded at ${d.getHours()}:${d.getMinutes()}, ${d.toDateString()} UTC`
                }
            }]
        }), [
            {
                data: miiImageData,
                filename: `${mii.id}.png`,
                contentType: 'image/png'
            }
        ]);
        
        setTimeout(() => { res.json({ redirect: "/myPrivateMiis" });  }, 2000); // TODO: jank
        
    } catch (e) {
        console.error('Error uploading Studio Mii:', e);
        res.json({error: "Failed to upload Mii from Studio: " + e.message}); // TODO: remove e.message
    }
});

// ========== DOWNLOAD ENDPOINTS ==========

// Download Mii in various formats
site.get('/downloadMii', async (req, res) => {
    try {
        const miiId = req.query.id;
        const format = req.query.format;
        
        const mii = await getMiiById(miiId, false);
        if (!mii) {
            res.json({error: "Invalid Mii ID"});
            return;
        }
        const miiName = mii.meta.name.replace(/[^a-z0-9]/gi, '_');
        
        if (format === 'qr' || format === '3dsqr') {
            // Download QR code
            const qrPath = "./static/miiQRs/" + miiId + ".png";
            res.setHeader('Content-Disposition', `attachment; filename="${miiName}_QR.png"`);
            res.sendFile(qrPath, { root: path.join(__dirname, "./") });
            
        }
        else if (format === '3dsbin' || format === '3dsbin_decrypted') {
            // Download decrypted 3DS bin
            const qrPath = "./static/miiQRs/" + miiId + ".png";
            const binData = await miijs.read3DSQR(qrPath, true);
            
            res.setHeader('Content-Disposition', `attachment; filename="${miiName}_decrypted.bin"`);
            res.setHeader('Content-Type', 'application/octet-stream');
            res.send(binData);
            
        }
        else if (format === '3dsbin_encrypted') {
            // Download encrypted 3DS bin (from QR)
            const qrPath = "./static/miiQRs/" + miiId + ".png";
            // Read QR and extract the encrypted portion
            // This requires reading the QR image and extracting the data payload
            // For now, we'll create a new encrypted QR and extract from it
            const tempQR = "./static/temp/" + await genId() + ".png";
            await miijs.write3DSQR(mii, tempQR);
            
            // Read the encrypted data from the QR
            // This is a placeholder - you may need to implement QR reading
            const encryptedData = await miijs.read3DSQR(tempQR, true);
            
            try { fs.unlinkSync(tempQR); } catch (e) { }
            
            res.setHeader('Content-Disposition', `attachment; filename="${miiName}_encrypted.bin"`);
            res.setHeader('Content-Type', 'application/octet-stream');
            res.send(encryptedData);
            
        }
        else if (format === 'wii' || format === 'wiibin') {
            // Convert to Wii and download
            const wiiMii = miijs.convertMii(mii, 'wii');
            const binData = await miijs.writeWiiBin(wiiMii);
            
            res.setHeader('Content-Disposition', `attachment; filename="${miiName}.mii"`);
            res.setHeader('Content-Type', 'application/octet-stream');
            res.send(binData);
            
        }
        else if (format === 'studio') {
            // Convert to Studio format and return as text
            const studioCode = miijs.convertMiiToStudio(mii);
            
            res.setHeader('Content-Disposition', `attachment; filename="${miiName}_studio.txt"`);
            res.setHeader('Content-Type', 'text/plain');
            res.send(studioCode);
            
        }
        else {
            res.json({error: "Invalid format specified"});
        }
        
    } catch (e) {
        console.error('Error downloading Mii:', e);
        res.json({error: "Failed to download Mii: " + e.message});
    }
});

// Get Studio code for a Mii (for copying)
site.get('/getStudioCode', async (req, res) => {
    try {
        const miiId = req.query.id;
        
        const mii = await getMiiById(miiId, false);
        if (!mii) {
            res.json({ error: 'Invalid Mii ID' });
            return;
        }
        const studioCode = miijs.convertMiiToStudio(mii);
        
        res.json({ 
            code: studioCode,
            url: `https://studio.mii.nintendo.com/miis/image.png?data=${studioCode}`
        });
        
    } catch (e) {
        console.error('Error getting Studio code:', e);
        res.json({ error: 'Failed to get Studio code: ' + e.message }); // TODO: remove sending error from here
    }
});

// Change User PFP (Moderator+)
site.post('/changeUserPfp', requireAuth, requireRole(ROLES.MODERATOR), async (req, res) => {
    try {
        const { username, miiId } = req.body;
        const targetUser = await getUserByUsername(username);

        if (!targetUser) {
            return res.json({ error: 'User not found' });
        }

        const mii = await getMiiById(miiId, false);
        if (!mii) {
            return res.json({ error: 'Mii not found' });
        }

        await Users.findOneAndUpdate(
            { username },
            { miiPfp: miiId }
        );

        makeReport(JSON.stringify({
            embeds: [{
                type: 'rich',
                title: '🖼️ User PFP Changed',
                description: `${req.cookies.username} changed profile picture for ${username}`,
                color: 0x00CCFF,
                fields: [
                    {
                        name: 'User',
                        value: username,
                        inline: true
                    },
                    {
                        name: 'New PFP Mii ID',
                        value: miiId,
                        inline: true
                    }
                ],
                thumbnail: {
                    url: `https://infinimii.com/miiImgs/${miiId}.png`
                }
            }]
        }));

        res.json({ okay: true });
    } catch (e) {
        console.error('Error changing user PFP:', e);
        res.json({ error: 'Server error' });
    }
});
site.post('/voteMii', requireAuth, async (req, res) => {
    if (!req.query.id) {
        res.json({error: "No ID specified"});
        return;
    }
    try {
        const mii = await getMiiById(req.query.id, false);
        if (!mii) {
            res.json({error: "Mii not found"});
            return;
        }
        if (mii.uploader === req.user.username) {
            res.json({error: "You submitted this Mii"});
            return;
        }
        if (req.user.votedFor.includes(req.query.id)) {
            // Unlike
            await Users.findOneAndUpdate(
                { username: req.cookies.username },
                { $pull: { votedFor: req.query.id } }
            );
            await Miis.findOneAndUpdate(
                { id: req.query.id },
                { $inc: { votes: -1 } }
            );
            res.send("Unliked");
            return;
        }
        // Like
        await Users.findOneAndUpdate(
            { username: req.cookies.username },
            { $addToSet: { votedFor: req.query.id } }
        );
        await Miis.findOneAndUpdate(
            { id: req.query.id },
            { $inc: { votes: 1 } }
        );
        res.send("Liked");
    }
    catch (e) {
        res.json({error: e}); // TOOD: don't send error
        return;
    }
});
site.get('/mii/:id', async (req, res) => {
    let inp = await getSendables(req);
    const miiId = req.params.id;
    
    // Try to get Mii (public or private)
    const mii = await getMiiById(miiId, true);
    
    if (!mii) {
        return sendError(res, req, "404 Mii not found", 404);
    }
    
    // Check access for private Miis
    if (mii.private) {
        const user = await getUserByUsername(req.cookies.username);
        const isModerator = user && canModerate(user);
        const isOwner = mii.uploader === req.cookies.username;
        
        if (!isOwner && !isModerator) {
            return sendError(res, req, "Access denied. This is a private Mii.", 403);
        }
        inp.isPrivate = true;
    } else {
        inp.isPrivate = false;
    }
    
    inp.mii = mii;
    inp.height=miijs.miiHeightToMeasurements(inp.mii.general.height);
    inp.weight=miijs.miiWeightToRealWeight(inp.mii.general.height,inp.mii.general.weight);

    // Override mii color for this page
    inp.userPfpMiiColor = mii.general.favoriteColor;

    // debugger

    ejs.renderFile('./ejsFiles/miiPage.ejs', inp, {}, function(err, str) {
        if (err) {
            res.send(err);
            console.log(err);
            return;
        }
        res.send(str);
    });
});
site.get('/user/:username', async (req, res) => {
    const targetUsername = decodeURIComponent(req.params.username);
    const targetUser = await getUserByUsername(targetUsername);
    
    if (!targetUser) {
       return sendError(res, req, "User not found", 404);
    }
    if (targetUsername === "Nintendo") { // a s'ti mret hcraes a ton si odnetniN ,tnavelerrI :nortseK
        res.redirect('/official');
        return;
    }
    let inp = await getSendables(req);
    inp.targetUser = targetUser;
    // inp.targetUser.name = targetUsername;
    inp.displayedMiis = [];
    
    // Get all user's public submissions
    const miis = await Miis.find({ 
        uploader: targetUsername, 
        private: false, 
        published: true
    }).lean();
    inp.displayedMiis = miis;
    
    ejs.renderFile('./ejsFiles/userPage.ejs', inp, {}, function(err, str) {
        if (err) {
            res.send(err);
            console.log(err);
            return;
        }
        res.send(str)
    });
});
site.get('/about', async (req, res) => {
    ejs.renderFile('./ejsFiles/about.ejs', await getSendables(req), {}, function(err, str) {
        if (err) {
            res.send(err);
            console.log(err);
            return;
        }
        res.send(str);
    });
});
site.get('/privacy', async (req, res) => {
    ejs.renderFile('./ejsFiles/privacy.ejs', await getSendables(req), {}, function(err, str) {
        if (err) {
            res.send(err);
            console.log(err);
            return;
        }
        res.send(str);
    });
});
site.get('/tos', async (req, res) => {
    ejs.renderFile('./ejsFiles/tos.ejs', await getSendables(req), {}, function(err, str) {
        if (err) {
            res.send(err);
            console.log(err);
            return;
        }
        res.send(str);
    });
});
site.get('/guidelines', async (req, res) => {
    ejs.renderFile('./ejsFiles/guidelines.ejs', await getSendables(req), {}, function(err, str) {
        if (err) {
            res.send(err);
            console.log(err);
            return;
        }
        res.send(str);
    });
});
site.get('/signup', async (req, res) => {
    ejs.renderFile('./ejsFiles/signup.ejs', await getSendables(req), {}, function(err, str) {
        if (err) {
            res.send(err);
            console.log(err);
            return;
        }
        res.send(str);
    });
});
site.get('/login', async (req, res) => {
    ejs.renderFile('./ejsFiles/login.ejs', await getSendables(req), {}, function(err, str) {
        if (err) {
            res.send(err);
            console.log(err);
            return;
        }
        res.send(str);
    });
});
site.get('/logout', async (req, res) => { // TODO: make this a POST request to prevent CSRF
    try {
        await res.clearCookie('username');
        await res.clearCookie('token');
        res.redirect("/");
    }
    catch (e) {
        console.log(e);
    }
});
site.get('/convert', async (req, res) => {
    ejs.renderFile('./ejsFiles/convert.ejs', await getSendables(req), {}, function(err, str) {
        if (err) {
            res.send(err);
            console.log(err);
            return;
        }
        res.send(str)
    });
});
site.get('/calculator', async (req, res) => {
    ejs.renderFile('./ejsFiles/calc.ejs', await getSendables(req), {}, function(err, str) {
        if (err) {
            res.send(err);
            console.log(err);
            return;
        }
        res.send(str);
    });
});
site.get('/qr', async (req, res) => {
    ejs.renderFile('./ejsFiles/qr.ejs', await getSendables(req), {}, function(err, str) {
        if (err) {
            res.send(err);
            console.log(err);
            return;
        }
        res.send(str)
    });
});
site.get('/settings', async (req, res) => {
    if (!req.user) {
        res.redirect("/");
        return;
    }
    var toSend= await getSendables(req);
    ejs.renderFile('./ejsFiles/settings.ejs', toSend, {}, function(err, str) {
        if (err) {
            res.send(err);
            console.log(err);
            return;
        }
        res.send(str)
    });
});
site.get('/myPrivateMiis', requireAuth, async (req, res) => {
    var toSend = await getSendables(req, undefined, req.user);
    
    const privateMiis = await Miis.find({ uploader: req.user.username, private: true }).lean();

    toSend.privateMiis = privateMiis;
    toSend.privateLimit = PRIVATE_MII_LIMIT;
    
    ejs.renderFile('./ejsFiles/myPrivateMiis.ejs', toSend, {}, function(err, str) {
        if (err) {
            res.send(err);
            console.log(err);
            return;
        }
        res.send(str);
    });
});
site.get('/manageCategories', requireAuth, requireRole(ROLES.RESEARCHER), async (req, res) => {
    var toSend = await getSendables(req, undefined, req.user);
    const settings = await getSettings();
    toSend.officialCategories = settings.officialCategories || {};
    
    ejs.renderFile('./ejsFiles/manageCategories.ejs', toSend, {}, function(err, str) {
        if (err) {
            res.send(err);
            console.log(err);
            return;
        }
        res.send(str);
    });
});
site.get('/changePfp', requireAuth, async (req, res) => {
    if (req.query.id?.length > 0) {
        const mii = await getMiiById(req.query.id);
        if (mii) {
            await Users.findOneAndUpdate(
                { username: req.cookies.username },
                { $set: { miiPfp: req.query.id } }
            );
            res.json({ okay: true });
        } else {
            res.json({error: "Invalid Mii ID"});
        }
    }
    else {
        res.json({error: "Invalid Mii ID"});
    }
});
site.get('/changeUser', requireAuth, async (req, res) => {    
    const newUsername = req.query.newUser;
    const oldUsername = req.cookies.username;
    const existingUser = await getUserByUsername(newUsername);
    
    if (validate(newUsername) && !existingUser) {
        // Update all Miis uploaded by this user
        await Miis.updateMany(
            { uploader: oldUsername },
            { uploader: newUsername }
        );
        
        // Update username
        await Users.findOneAndUpdate(
            { username: oldUsername },
            { username: newUsername }
        );
        
        var d = new Date();
        const updatedUser = await getUserByUsername(newUsername);
        makeReport(JSON.stringify({
            embeds: [{
                "type": "rich",
                "title": `Username Changed`,
                "description": `${oldUsername} is now ${newUsername}`,
                "color": 0xff0000,
                "thumbnail": {
                    "url": `https://infinimii.com/miiImgs/${updatedUser?.miiPfp || '00000'}.png`,
                    "height": 0,
                    "width": 0
                },
                "footer": {
                    "text": `Changed at ${d.getHours()}:${d.getMinutes()}, ${d.toDateString()} UTC`
                },
                "url": `https://infinimii.com/user/${encodeURIComponent(newUsername)}`
            }]
        }));
        res.cookie('username', newUsername, { maxAge: 30 * 24 * 60 * 60 * 1000/*1 Month*/ });
        res.json({ okay: true });
    }
    else {
        res.json({error: "Username invalid"});
    }
});
site.get('/changeHighlightedMii', requireAuth, requireRole(ROLES.MODERATOR), async (req, res) => {    
    const miiId = req.query.id;
    if (miiId?.length > 0) {
        const mii = await getMiiById(miiId, false);
        if (!mii) {
            res.json({error: "Invalid Mii ID"});
            return;
        }
        
        const currentDate = new Date();
        await updateSettings({
            highlightedMii: miiId,
            highlightedMiiChangeDay: currentDate.getDate()
        });
        
        res.json({ okay: true });
        let miiImageData;
        try {
            miiImageData = fs.readFileSync(`./static/miiImgs/${mii.id}.png`);
        } catch(e) {
            try {
                miiImageData = fs.readFileSync(`./static/miiImgs/${mii.id}.png`);
            } catch(e2) {
                miiImageData = null;
            }
        }

        const attachments = miiImageData ? [{
            data: miiImageData,
            filename: `${mii.id}.png`,
            contentType: 'image/png'
        }] : [];

        makeReport(JSON.stringify({
            embeds: [{
                "type": "rich",
                "title": (mii.official ? "Official " : "") + `Mii set as Highlighted Mii`,
                "description": mii.desc,
                "color": 0xff0000,
                "fields": [
                    {
                        "name": `Mii Name`,
                        "value": mii.meta.name,
                        "inline": true
                    },
                    {
                        "name": `Uploaded by`,
                        "value": `[${mii.uploader}](https://infinimii.com/user/${encodeURIComponent(mii.uploader)})`,
                        "inline": true
                    },
                    {
                        "name": `Mii Creator Name (embedded in Mii file)`,
                        "value": mii.meta.creatorName,
                        "inline": true
                    }
                ],
                ...(miiImageData ? {
                    "image": {
                        "url": `attachment://${mii.id}.png`
                    }
                } : {}),
                "footer": {
                    "text": `New Highlighted Mii set by ${req.cookies.username}`
                },
                "url": `https://infinimii.com/mii/` + mii.id
            }]
        }), attachments);
    }
    else {
        res.json({error: "Invalid Mii ID"});
    }
});
site.get('/reportMii', async (req,res)=>{ // TODO: add endpoints that cause stuff should be POST, not GET to prevent CSRF
    const mii = await getMiiById(req.query.id, false);
    makeReport(JSON.stringify({
        embeds: [{
            "type": "rich",
            "title": (mii.official ? "Official " : "") + `Mii has been reported`,
            "description": req.query.what,
            "color": 0xff0000,
            "fields": [
                {
                    "name": `Mii Name`,
                    "value": mii.meta.name,
                    "inline": true
                },
                {
                    "name":"Description",
                    "value":mii.desc,
                    "inline":true
                },
                {
                    "name": `Uploaded by`,
                    "value": `[${mii.uploader}](https://infinimii.com/user/${encodeURIComponent(mii.uploader)})`,
                    "inline": true
                },
                {
                    "name": `Mii Creator Name (embedded in Mii file)`,
                    "value": mii.meta.creatorName,
                    "inline": true
                }
            ],
            "thumbnail": {
                "url": `https://infinimii.com/miiImgs/${mii.id}.png`,
                "height": 0,
                "width": 0
            },
            "footer": {
                "text": `Mii has been reported by ${req.cookies.username?req.cookies.username:"Anonymous"}`
            },
            "url": `https://infinimii.com/mii/` + mii.id
        }]
    }));
    res.json({ okay: true });
});
site.get('/miiWii',async (req,res)=>{
    const fetchedMii = await getMiiById(req.query.id, false);
    const mii=await miijs.convertMii(fetchedMii);
    console.log(mii.meta.name);
    var miiBuffer=await miijs.writeWiiBin(mii);
    console.log(miiBuffer);
    console.log(await miijs.readWiiBin(miiBuffer)?.meta?.name);
    res.setHeader('Content-Disposition', `attachment; filename="${req.query.id}.mii"`);
    res.setHeader('Content-Type', 'application/octet-stream');
    res.send(miiBuffer);
});
site.get('/faq', async (req, res) => {
    ejs.renderFile('./ejsFiles/faq.ejs', await getSendables(req), {}, function(err, str) {
        if (err) {
            res.send(err);
            console.log(err);
            return;
        }
        res.send(str);
    });
});
site.get('/cite', async (req, res) => {
    ejs.renderFile('./ejsFiles/cite.ejs', await getSendables(req), {}, function(err, str) {
        if (err) {
            res.send(err);
            console.log(err);
            return;
        }
        res.send(str);
    });
});
// Change Email (User)
site.post('/changeEmail', requireAuth, async (req, res) => {
    try {
        const { oldEmail, newEmail } = req.body;

        // Verify old email matches
        if (req.user.email !== oldEmail) {
            return res.json({ error: 'Old email does not match' });
        }

        // Basic email validation
        if (!newEmail || !newEmail.includes('@') || !newEmail.includes('.')) {
            return res.json({ error: 'Invalid email format' });
        }

        var token = genToken();
        let link = "https://infinimii.com/verify?user=" + encodeURIComponent(req.cookies.username) + "&token=" + encodeURIComponent(token);
        
        // Increment token version to invalidate old JWTs (security - email is in JWT payload)
        const newTokenVersion = (req.user.tokenVersion || 0) + 1;
        
        await Users.findOneAndUpdate(
            { username: req.cookies.username },
            { 
                $set: { 
                    email: newEmail,
                    verified: false,
                    verificationToken: hashPassword(token, req.user.salt).hash,
                    tokenVersion: newTokenVersion
                }
            }
        ); // TODO_DB: this would brick your account if you send to a false email...

        makeReport(JSON.stringify({
            embeds: [{
                type: 'rich',
                title: '📧 Email Changed',
                description: `User ${req.cookies.username} changed their email`,
                color: 0x00CCFF,
                fields: [
                    {
                        name: 'User',
                        value: req.cookies.username,
                        inline: true
                    }
                ]
            }]
        }));

        sendEmail(oldEmail, "InfiniMii Verification", `Hi ${req.cookies.username}, we received a request to change your email on InfiniMii. If this was not you, please reply to this email to receive support.`);
        sendEmail(newEmail, "InfiniMii Verification", `Hi ${req.cookies.username}, we received a request to change your email on InfiniMii. Please verify your email by clicking this link: ${link}. If this was not you, please reply to this email to receive support.`);


        res.json({ okay: true });
    } catch (e) {
        console.error('Error changing email:', e);
        res.json({ error: 'Server error' });
    }
});

// Change Password (User)
site.post('/changePassword', requireAuth, async (req, res) => {
    try {
        const { oldPassword, newPassword } = req.body;

        // Verify old password
        if (!validatePassword(oldPassword, req.user.salt, req.user.pass)) {
            return res.json({ error: 'Old password is incorrect' });
        }

        // Hash new password with existing salt
        const newHashed = hashPassword(newPassword, req.user.salt);

        // Increment token version to invalidate old tokens
        const newTokenVersion = (req.user.tokenVersion || 0) + 1;

        await Users.findOneAndUpdate(
            { username: req.cookies.username },
            { 
                pass: newHashed.hash,
                tokenVersion: newTokenVersion
            }
        );

        // Get updated user and create new JWT
        const updatedUser = await getUserByUsername(req.cookies.username);
        const newToken = createToken(updatedUser);

        // Set new JWT token cookie
        res.cookie("token", newToken, { 
            maxAge: 30 * 24 * 60 * 60 * 1000,
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax'
        });

        makeReport(JSON.stringify({
            embeds: [{
                type: 'rich',
                title: '🔒 Password Changed',
                description: `User ${req.cookies.username} changed their password`,
                color: 0x00FF00,
                fields: [
                    {
                        name: 'User',
                        value: req.cookies.username,
                        inline: true
                    }
                ]
            }]
        }));
        sendEmail(req.user.email,`Password Changed - InfiniMii`,`Hi ${req.cookies.username}, your password was recently changed on InfiniMii. If this was not you, you can reply to this email to receive support.`);

        res.json({ okay: true });
    } catch (e) {
        console.error('Error changing password:', e);
        res.json({ error: 'Server error' });
    }
});

// Delete All User's Miis (User - own miis only)
site.post('/deleteAllMyMiis', requireAuth, async (req, res) => {
    try {
        const miis = await Miis.find({ uploader: req.user.username, private: false, published: true }).lean();
        const miiIds = miis.map(m => m.id);
        let deletedCount = 0;

        for (const miiId of miiIds) {
            try {
                const mii = await getMiiById(miiId, false);
                if (mii) {
                    // Delete files
                    try { fs.unlinkSync(`./static/miiImgs/${miiId}.png`); } catch(e) {}
                    try { fs.unlinkSync(`./static/miiQRs/${miiId}.png`); } catch(e) {}
                    
                    // Delete Mii from database
                    await Miis.deleteOne({ id: miiId });
                    deletedCount++;
                }
            } catch(e) {
                console.error(`Error deleting Mii ${miiId}:`, e);
            }
        }

        makeReport(JSON.stringify({
            embeds: [{
                type: 'rich',
                title: '🗑️ User Deleted All Their Miis',
                description: `${req.cookies.username} deleted all their own Miis`,
                color: 0xFF6600,
                fields: [
                    {
                        name: 'User',
                        value: req.cookies.username,
                        inline: true
                    },
                    {
                        name: 'Miis Deleted',
                        value: deletedCount.toString(),
                        inline: true
                    }
                ]
            }]
        }));
        sendEmail(req.user.email,`All Miis Deleted - InfiniMii`,`Hi ${req.cookies.username}, we received a request to delete all of your Miis. If this wasn't you, reply to this email to receive support.`);
        res.json({ deletedCount });
    } catch (e) {
        console.error('Error deleting all user Miis:', e);
        res.json({ error: 'Server error' });
    }
});

// Delete Account (User)
site.post('/deleteAccount', requireAuth, async (req, res) => {
    try {
        const username = req.user.username;
        const { password } = req.body;

        // Verify password
        if (!validatePassword(password, req.user.salt, req.user.pass)) {
            return res.json({ error: 'Password is incorrect' });
        }

        // Transfer Miis to a special "Deleted User" account
        let deletedUser = await getUserByUsername("[Deleted User]");
        if (!deletedUser) {
            await Users.create({
                username: "[Deleted User]",
                salt: "",
                pass: "",
                creationDate: Date.now(),
                email: "",
                votedFor: [],
                miiPfp: "00000",
                roles: [ROLES.BASIC],
            });
        }

        // Transfer all Miis to deleted user account
        await Miis.updateMany(
            { uploader: username },
            { uploader: "[Deleted User]" }
        );

        // Delete user account
        await Users.deleteOne({ username });

        // Clear cookies
        res.clearCookie('username');
        res.clearCookie('token');

        makeReport(JSON.stringify({
            embeds: [{
                type: 'rich',
                title: '👋 Account Deleted',
                description: `User ${username} deleted their account`,
                color: 0xFF0000,
                fields: [
                    {
                        name: 'Username',
                        value: username,
                        inline: true
                    },
                    {
                        name: 'Miis Transferred',
                        value: (await Miis.countDocuments({ uploader: username })).toString(),
                        inline: true
                    }
                ]
            }]
        }));
        sendEmail(req.user.email,`Account Deleted - InfiniMii`,`Hi ${req.cookies.username}, we received a request to delete your account. We're sorry to see you go! If this wasn't you, please reply to this email to receive support.`)
        res.json({ okay: true });
    } catch (e) {
        console.error('Error deleting account:', e);
        res.json({ error: 'Server error' });
    }
});

site.get('/getInstructions', async (req, res) => {
    try {
        const miiId = req.query.id;
        const format = req.query.format || '3ds'; // '3ds' or 'wii'
        const full = req.query.full === 'true';
        
        let mii = await getMiiById(miiId, false);
        if (!mii) {
            res.json({ error: 'Invalid Mii ID' });
            return;
        }
        
        // Convert to Wii format if requested
        if (format === 'wii') {
            mii = miijs.convertMii(mii, 'wii');
        }
        
        // Generate instructions
        const instructions = miijs.generateInstructions(mii, full);
        
        res.json({ 
            instructions: instructions,
            miiName: mii.meta.name,
            format: format
        });
        
    } catch (e) {
        console.error('Error generating instructions:', e);
        res.json({ error: 'Failed to generate instructions: ' + e.message });
    }
});

site.post('/uploadMii', requireAuth, upload.single('mii'), async (req, res) => {
    try {
        let uploader = req.user.username;
        
        // Check private Mii limit
        const privateMiisCount = await Miis.countDocuments({ uploader: req.user.username, private: true });
        if (privateMiisCount >= Number(PRIVATE_MII_LIMIT)) {
            res.json({error: `You have reached the limit of ${PRIVATE_MII_LIMIT} private Miis. Please publish or delete some before uploading more.`});
            try { fs.unlinkSync("./uploads/" + req.file.filename); } catch (e) { }
            return;
        }
        
        // Check if trying to upload official Mii without permission
        if (req.body.official && !canUploadOfficial(req.user)) {
            res.json({'error': 'Only Researchers and Administrators can upload official Miis'});
            try { fs.unlinkSync("./uploads/" + req.file.filename); } catch (e) { }
            return;
        }
        
        // TODO: catch errors here and request that they make sure they selected the right upload type

        let mii;
        if (req.body.type === "wii") {
            // Read Wii Mii and convert TO 3DS format
            const wiiMii = await miijs.readWiiBin("./uploads/" + req.file.filename);
            mii = miijs.convertMii(wiiMii, "3ds"); // Convert TO 3DS
        }
        else if (req.body.type === "3ds") {
            mii = await miijs.read3DSQR("./uploads/" + req.file.filename);
        }
        else if (req.body.type === "3dsbin") {
            var binData;
            if (req.file) {
                try {
                    // Read the uploaded file as a buffer
                    binData = fs.readFileSync("./uploads/" + req.file.filename);
                } catch (e) {
                    console.error('Error reading 3DS bin file:', e);
                    res.json({error: `Invalid 3DS bin file: ${e.message}`});
                    try { fs.unlinkSync("./uploads/" + req.file.filename); } catch (e2) { }
                    return;
                }
            }
            else{
                res.json({error: 'No file uploaded for 3DS bin'});
                return;
            }
            mii = await miijs.read3DSQR(binData);
        }
        else if (req.body.type === "3dsbin_amiibo") {
            // Uploading from Amiibo extraction
            const tempMiiId = req.body.fromAmiibo;
            const tempBinPath = `./static/temp/${tempMiiId}.bin`;
            
            if (!fs.existsSync(tempBinPath)) {
                res.json({error: 'Amiibo Mii data not found. Please extract again.'});
                return;
            }
            
            try {
                const binData = fs.readFileSync(tempBinPath);
                mii = await miijs.read3DSQR(binData, false);
                
                // Clean up temp files
                try { fs.unlinkSync(tempBinPath); } catch (e) { }
                try { fs.unlinkSync(`./static/miiImgs/${tempMiiId}.png`); } catch (e) { }
                try { fs.unlinkSync(`./static/miiQRs/${tempMiiId}.png`); } catch (e) { }
            } catch (e) {
                console.error('Error reading Amiibo Mii:', e);
                res.json({error: `Invalid Amiibo Mii data: ${e.message}`});
                return;
            }
        }
        else {
            res.json({error: 'No valid type specified'});
            try { fs.unlinkSync("./uploads/" + req.file.filename); } catch (e) { }
            return;
        }

        // Add official Mii categorization
        if (req.body.official) {
            mii.officialCategories = [];
            
            // Parse categories (now stores paths instead of names)
            if (req.body.categories) {
                const categories = Array.isArray(req.body.categories) ? req.body.categories : [req.body.categories];
                mii.officialCategories = [...new Set(categories.filter(c => c && c.trim()))];
            }
        }
        
        mii.id = await genId();
        mii.uploadedOn = Date.now();
        mii.uploader = req.body.official ? "Nintendo" : uploader;
        mii.desc = req.body.desc;
        mii.votes = 1;
        mii.official = req.body.official;
        mii.published = false;
        mii.blockedFromPublishing = false;
        
        // Save to private folders
        const miiImageData=await miijs.renderMii(mii);
        fs.writeFileSync("./static/privateMiiImgs/" + mii.id + ".png", miiImageData);
        await miijs.write3DSQR(mii, "./static/privateMiiQRs/" + mii.id + ".png");
        
        // Store in database as private Mii
        await Miis.create({
            ...mii,
            id: mii.id,
            private: true
        });
        
        // Send to Discord for moderator review
        var d = new Date();
        makeReport(JSON.stringify({
            embeds: [{
                "type": "rich",
                "title": (req.body.official ? "Official " : "") + `Private Mii Uploaded`,
                "description": mii.desc,
                "color": 0x00aaff,
                "fields": [
                    {
                        "name": `Mii Name`,
                        "value": mii.meta?.name || "Unknown",
                        "inline": true
                    },
                    {
                        "name": `Uploaded by`,
                        "value": `[${uploader}](https://infinimii.com/user/${encodeURIComponent(uploader)})`,
                        "inline": true
                    },
                    {
                        "name": `Mii Creator Name`,
                        "value": mii.meta?.creatorName || "Unknown",
                        "inline": true
                    }
                ],
                "image": {
                    "url": `attachment://${mii.id}.png`
                },
                "footer": {
                    "text": `View: https://infinimii.com/mii/${mii.id} | Uploaded at ${d.getHours()}:${d.getMinutes()}, ${d.toDateString()} UTC`
                }
            }]
        }), [
            {
                data: miiImageData,
                filename: `${mii.id}.png`,
                contentType: 'image/png'
            }
        ]);
        
        setTimeout(() => { res.json({ redirect: "/myPrivateMiis" });  }, 2000); // TODO: jank

        // TODO: does rendering lag this? If so, 

    } catch (e) {
        console.error('Error uploading Mii:', e);
        res.json({error: 'Server error'});
        try { fs.unlinkSync("./uploads/" + req.file.filename); } catch (e2) { }
    }
});
// Update Official Mii Categories (Researcher+)
site.post('/updateOfficialCategories', requireAuth, requireRole(ROLES.RESEARCHER), async (req, res) => {
    try {
        const { miiId, categories } = req.body;

        if (!miiId || !Array.isArray(categories)) {
            return res.json({ error: 'Missing parameters' });
        }

        const mii = await getMiiById(miiId, false);
        if (!mii) {
            return res.json({ error: 'Mii not found' });
        }

        if (!mii.official) {
            return res.json({ error: 'This is not an official Mii' });
        }

        const oldCategories = mii.officialCategories || [];
        const newCategories = [...new Set(categories.filter(c => c && c.trim()))];
        
        await Miis.findOneAndUpdate(
            { id: miiId },
            { officialCategories: newCategories }
        );

        makeReport(JSON.stringify({
            embeds: [{
                type: 'rich',
                title: '📂 Official Mii Categories Updated',
                description: `${req.cookies.username} updated categories for an official Mii`,
                color: 0x00AAFF,
                fields: [
                    {
                        name: 'Mii',
                        value: `[${mii.meta?.name || mii.meta.name}](https://infinimii.com/mii/${miiId})`,
                        inline: true
                    },
                    {
                        name: 'Old Categories',
                        value: oldCategories.length ? oldCategories.join(', ') : 'None',
                        inline: false
                    },
                    {
                        name: 'New Categories',
                        value: newCategories.length ? newCategories.join(', ') : 'None',
                        inline: false
                    }
                ]
            }]
        }));

        res.json({ okay: true });
    } catch (e) {
        console.error('Error updating official categories:', e);
        res.json({ error: 'Server error' });
    }
});
// Get all official categories (nested structure)
site.get('/getOfficialCategories', async (req, res) => {
    try {
        const settings = await getSettings();
        res.json({ categories: settings.officialCategories.categories });
    } catch (e) {
        console.error('Error getting categories:', e);
        res.json({ error: 'Server error' });
    }
});

// Add new category (can be root or nested under a parent)
site.post('/addCategory', requireAuth, requireRole(ROLES.RESEARCHER), async (req, res) => {
    try {
        const { name, color, parentPath } = req.body;

        if (!name || !name.trim()) {
            return res.json({ rror: 'Category name required' });
        }

        const categoryName = name.trim();
        
        const settings = await getSettings();
        // Determine where to add the category
        let targetArray;
        let newPath;
        
        if (!parentPath) {
            // Add as root category
            targetArray = settings.officialCategories.categories;
            newPath = categoryName;
            
            // Check if already exists at root
            if (targetArray.find(c => c.name === categoryName)) {
                return res.json({ error: 'Category already exists at this level' });
            }
        } else {
            // Add as child of parent
            const parent = findCategoryByPath(parentPath);
            if (!parent) {
                return res.json({ error: 'Parent category not found' });
            }
            
            targetArray = parent.children;
            newPath = `${parentPath}/${categoryName}`;
            
            // Check if already exists under this parent
            if (targetArray.find(c => c.name === categoryName)) {
                return res.json({ error: 'Category already exists under this parent' });
            }
        }

        const newCategory = {
            name: categoryName,
            color: color || "#999999",
            path: newPath,
            children: []
        };
        
        targetArray.push(newCategory);

        await updateSettings({ officialCategories: settings.officialCategories });

        makeReport(JSON.stringify({
            embeds: [{
                type: 'rich',
                title: '📁 New Category Created',
                description: `${req.cookies.username} created a new category`,
                color: parseInt(color?.replace('#', '') || '999999', 16),
                fields: [
                    {
                        name: 'Category Name',
                        value: categoryName,
                        inline: true
                    },
                    {
                        name: 'Path',
                        value: newPath,
                        inline: true
                    },
                    {
                        name: 'Parent',
                        value: parentPath || 'Root',
                        inline: true
                    }
                ]
            }]
        }));

        res.json({ categories: settings.officialCategories.categories });
    } catch (e) {
        console.error('Error adding category:', e);
        res.json({ error: 'Server error' });
    }
});

// Rename category and update all Miis using it or its descendants
site.post('/renameCategory', requireAuth, requireRole(ROLES.RESEARCHER), async (req, res) => {
    try {
        const { path, newName } = req.body;

        if (!path || !newName || !newName.trim()) {
            return res.json({ error: 'Path and new name required' });
        }

        const category = findCategoryByPath(path);
        if (!category) {
            return res.json({ error: 'Category not found' });
        }

        const newNameTrimmed = newName.trim();
        const oldName = category.name;
        const oldPath = category.path;

        // Check if sibling with same name exists
        const settings = await getSettings();
        const parent = findParentByChildPath(path);
        const siblings = parent ? parent.children : settings.officialCategories.categories;
        if (siblings.find(c => c.name === newNameTrimmed && c.path !== path)) {
            return res.json({ error: 'A category with this name already exists at this level' });
        }

        // Get all paths that will change (this category and all descendants)
        const pathsToUpdate = getAllDescendantPaths(category);
        
        // Update the name
        category.name = newNameTrimmed;
        
        // Rebuild paths for this category and all descendants
        const parentPath = path.substring(0, path.lastIndexOf('/'));
        updateCategoryPaths(category, parentPath);
        
        // Get new paths after update
        const newPaths = getAllDescendantPaths(category);
        
        // Update all Miis that use any of these paths
        let totalUpdated = 0;
        for (let i = 0; i < pathsToUpdate.length; i++) {
            const updated = await renameCategoryInAllMiis(pathsToUpdate[i], newPaths[i]);
            totalUpdated += updated;
        }

        await updateSettings({ officialCategories: settings.officialCategories });

        makeReport(JSON.stringify({
            embeds: [{
                type: 'rich',
                title: '✏️ Category Renamed',
                description: `${req.cookies.username} renamed a category`,
                color: parseInt(category.color?.replace('#', '') || '999999', 16),
                fields: [
                    {
                        name: 'Old Name',
                        value: oldName,
                        inline: true
                    },
                    {
                        name: 'New Name',
                        value: newNameTrimmed,
                        inline: true
                    },
                    {
                        name: 'Old Path',
                        value: oldPath,
                        inline: false
                    },
                    {
                        name: 'New Path',
                        value: category.path,
                        inline: false
                    },
                    {
                        name: 'Miis Updated',
                        value: totalUpdated.toString(),
                        inline: true
                    }
                ]
            }]
        }));

        res.json({ categories: settings.officialCategories.categories, updatedMiis: totalUpdated });
    } catch (e) {
        console.error('Error renaming category:', e);
        res.json({ error: 'Server error' });
    }
});

// Delete category and all its descendants, remove from all Miis
site.post('/deleteCategory', requireAuth, requireRole(ROLES.RESEARCHER), async (req, res) => {
    try {
        const { path } = req.body;

        if (!path) {
            return res.json({ error: 'Category path required' });
        }

        const category = findCategoryByPath(path);
        if (!category) {
            return res.json({ error: 'Category not found' });
        }

        // Get all paths to remove (category and all descendants)
        const pathsToRemove = getAllDescendantPaths(category);
        
        // Remove from parent's children array
        const settings = await getSettings();
        const parent = findParentByChildPath(path);
        if (parent) {
            parent.children = parent.children.filter(c => c.path !== path);
        } else {
            // Remove from root
            settings.officialCategories.categories = settings.officialCategories.categories.filter(c => c.path !== path);
        }
        
        // Remove all paths from all Miis
        let totalUpdated = 0;
        for (const pathToRemove of pathsToRemove) {
            const updated = await removeCategoryFromAllMiis(pathToRemove);
            totalUpdated += updated;
        }

        await updateSettings({ officialCategories: settings.officialCategories });

        makeReport(JSON.stringify({
            embeds: [{
                type: 'rich',
                title: '🗑️ Category Deleted',
                description: `${req.cookies.username} deleted a category and all its descendants`,
                color: 0xFF0000,
                fields: [
                    {
                        name: 'Category',
                        value: category.name,
                        inline: true
                    },
                    {
                        name: 'Path',
                        value: path,
                        inline: true
                    },
                    {
                        name: 'Descendants Deleted',
                        value: (pathsToRemove.length - 1).toString(),
                        inline: true
                    },
                    {
                        name: 'Miis Updated',
                        value: totalUpdated.toString(),
                        inline: true
                    }
                ]
            }]
        }));

        res.json({ categories: settings.officialCategories.categories, updatedMiis: totalUpdated });
    } catch (e) {
        console.error('Error deleting category:', e);
        res.json({ error: 'Server error' });
    }
});

// Move category to a new parent
site.post('/moveCategory', requireAuth, requireRole(ROLES.RESEARCHER), async (req, res) => {
    try {
        const { categoryPath, newParentPath } = req.body;

        if (!categoryPath) {
            return res.json({ error: 'Category path required' });
        }

        const category = findCategoryByPath(categoryPath);
        if (!category) {
            return res.json({ error: 'Category not found' });
        }

        // Prevent moving to self or descendant
        if (newParentPath && newParentPath.startsWith(categoryPath + '/')) {
            return res.json({ error: 'Cannot move category to its own descendant' });
        }

        if (newParentPath === categoryPath) {
            return res.json({ error: 'Cannot move category to itself' });
        }

        // Get all paths before move
        const oldPaths = getAllDescendantPaths(category);

        // Remove from current parent
        const settings = await getSettings();
        const oldParent = findParentByChildPath(categoryPath);
        if (oldParent) {
            oldParent.children = oldParent.children.filter(c => c.path !== categoryPath);
        } else {
            settings.officialCategories.categories = settings.officialCategories.categories.filter(c => c.path !== categoryPath);
        }

        // Add to new parent
        let newParentNode;
        let newSiblings;
        if (!newParentPath) {
            // Move to root
            newSiblings = settings.officialCategories.categories;
            newParentNode = null;
        } else {
            newParentNode = findCategoryByPath(newParentPath);
            if (!newParentNode) {
                return res.json({ error: 'New parent category not found' });
            }
            newSiblings = newParentNode.children;
        }

        // Check for name conflict
        if (newSiblings.find(c => c.name === category.name)) {
            return res.json({ error: 'A category with this name already exists at the destination' });
        }

        newSiblings.push(category);

        // Update paths
        updateCategoryPaths(category, newParentPath || '');

        // Get new paths after move
        const newPaths = getAllDescendantPaths(category);

        // Update all Miis
        let totalUpdated = 0;
        for (let i = 0; i < oldPaths.length; i++) {
            const updated = await renameCategoryInAllMiis(oldPaths[i], newPaths[i]);
            totalUpdated += updated;
        }

        await updateSettings({ officialCategories: settings.officialCategories });

        makeReport(JSON.stringify({
            embeds: [{
                type: 'rich',
                title: '📦 Category Moved',
                description: `${req.cookies.username} moved a category`,
                color: 0x9C27B0,
                fields: [
                    {
                        name: 'Category',
                        value: category.name,
                        inline: true
                    },
                    {
                        name: 'Old Path',
                        value: oldPaths[0],
                        inline: false
                    },
                    {
                        name: 'New Path',
                        value: category.path,
                        inline: false
                    },
                    {
                        name: 'Miis Updated',
                        value: totalUpdated.toString(),
                        inline: true
                    }
                ]
            }]
        }));

        res.json({ categories: settings.officialCategories.categories, updatedMiis: totalUpdated });
    } catch (e) {
        console.error('Error moving category:', e);
        res.json({ error: 'Server error' });
    }
});
// Get all official categories (for building forms)
site.get('/getOfficialCategories', async (req, res) => {
    try {
        const settings = await getSettings();
        res.json({ categories: settings.officialCategories });
    } catch (e) {
        console.error('Error getting categories:', e);
        res.json({ error: 'Server error' });
    }
});
// Publish a private Mii
site.post('/publishMii', requireAuth,  async (req, res) => {
    try {
        const { miiId } = req.body;
        
        if (mii.uploader !== req.cookies.username) {
            return res.json({ error: 'Mii not found in your private collection' });
        }

        const mii = await Miis.findOne({ id: miiId, private: true }).lean();
        if (!mii) {
            return res.json({ error: 'Mii data not found' });
        }

        // Check if blocked from publishing
        if (mii.blockedFromPublishing) {
            return res.json({ error: 'This Mii has been blocked from publishing by a moderator. Please contact support if you believe this is an error.' });
        }

        // Move files from private to public folders
        try {
            if (fs.existsSync(`./static/privateMiiImgs/${miiId}.png`)) {
                fs.unlink(`./static/privateMiiImgs/${miiId}.png`,()=>{});
            }
            
            if (fs.existsSync(`./static/privateMiiQRs/${miiId}.png`)) {
                fs.unlink(`./static/privateMiiQRs/${miiId}.png`,()=>{});
            }
        } catch (e) {
            console.error('Error moving Mii files:', e);
            return res.json({ error: 'Error moving Mii files' });
        }

        //Because of security for private images, we can't just move the folders, we have to make new renders.
        var miiImageData;
        if (!fs.existsSync(`./static/miiImgs/${mii.id}.png`)) {
            miiImageData=await miijs.renderMii(mii);
            fs.writeFileSync(`./static/miiImgs/${mii.id}.png`, miiImageData);
        }
        if (!fs.existsSync(`./static/miiQRs/${mii.id}.png`)) {
            miijs.write3DSQR(mii, `./static/miiQRs/${mii.id}.png`);
        }

        // Update Mii status to published and public
        await Miis.findOneAndUpdate(
            { id: miiId },
            { $set: { private: false, published: true } }
        );

        // Notify Discord
        var d = new Date();
        makeReport(JSON.stringify({
            embeds: [{
                "type": "rich",
                "title": (mii.official ? "Official " : "") + `Mii Published`,
                "description": mii.desc,
                "color": 0x00ff00,
                "fields": [
                    {
                        "name": `Mii Name`,
                        "value": mii.meta.name,
                        "inline": true
                    },
                    {
                        "name": `Published by`,
                        "value": `[${req.cookies.username}](https://infinimii.com/user/${encodeURIComponent(req.cookies.username)})`,
                        "inline": true
                    }
                ],
                "image": {
                    "url": `attachment://${miiId}.png`
                },
                "footer": {
                    "text": `View: https://infinimii.com/mii/${miiId} | Published at ${d.getHours()}:${d.getMinutes()}, ${d.toDateString()} UTC`
                }
            }]
        }), [
            {
                data: miiImageData,
                filename: `${miiId}.png`,
                contentType: 'image/png'
            }
        ]);

        res.json({ okay: true });
    } catch (e) {
        console.error('Error publishing Mii:', e);
        res.json({ error: 'Server error' });
    }
});
// Block a private Mii from being published (Moderator only)
site.post('/blockMiiFromPublishing', requireAuth, requireRole(ROLES.MODERATOR), async (req, res) => {
    try {
        const { miiId, reason } = req.body;

        const mii = await Miis.findOne({ id: miiId, published: false }).lean();
        if (!mii) {
            return res.json({ error: 'Unpublished Mii not found' });
        }

        await Miis.findOneAndUpdate(
            { id: miiId },
            { 
                $set: { 
                    blockedFromPublishing: true,
                    blockReason: reason || 'No reason provided'
                }
            }
        );

        makeReport(JSON.stringify({
            embeds: [{
                type: 'rich',
                title: '🚫 Private Mii Blocked from Publishing',
                description: `${req.cookies.username} blocked a private Mii from being published`,
                color: 0xFF6600,
                fields: [
                    {
                        name: 'Mii Name',
                        value: mii.meta.name,
                        inline: true
                    },
                    {
                        name: 'Uploader',
                        value: mii.uploader,
                        inline: true
                    },
                    {
                        name: 'Reason',
                        value: reason || 'No reason provided'
                    }
                ]
            }]
        }));

        res.json({ okay: true });
    } catch (e) {
        console.error('Error blocking Mii:', e);
        res.json({ error: 'Server error' });
    }
});
site.post('/convertMii', upload.single('mii'), async (req, res) => {
    // TODO: Verify that mii.name is valid here
    try {
        let tempMiiPath = crypto.randomBytes(16).toString('hex'); // TODO: verify convertMii features work after path changes
        let mii;
        if (req.body.fromType === "3DS/Wii U") {
            mii = await miijs.read3DSQR("./uploads/" + req.file.filename);
        }
        if (req.body.fromType === "3DS Bin") {
            mii = await miijs.read3DSQR(req.body["3dsbin"]);
        }
        if (req.body.fromType === "Wii") {
            mii = miijs.readWiiBin("./uploads/" + req.file.filename);
        }
        if (req.body.fromType.includes("3DS") && req.body.toType.includes("Wii Mii")) {
            mii = miijs.convertMii(mii, "3ds");
        }
        if (req.body.fromType === "Wii" && req.body.toType.includes("3DS")) {
            mii = miijs.convertMii(mii, "wii");
        }
        if (req.body.toType.includes("Special")) {
            mii.info.type = "Special";
        }
        else {
            mii.info.type = "Normal";
        }
        try { fs.unlinkSync("./uploads/" + req.file.filename); } catch (e) { }
        if (req.body.toType.includes("Wii Mii")) {
            await miijs.writeWiiBin(mii, "./" + tempMiiPath + ".mii");
            res.setHeader('Content-Disposition', `attachment; filename="${mii.name}.mii"`);
            await res.sendFile("./" + tempMiiPath + ".mii", { root: path.join(__dirname, "./") });
            setTimeout(() => {
                fs.unlinkSync("./" + tempMiiPath + ".mii");
            }, 2000);
            return;
        }
        if (req.body.toType.includes("3DS")) {
            await miijs.write3DSQR(mii, "./static/converted/" + tempMiiPath + ".png");
            setTimeout(() => {
                res.json({ redirect: "/converted/" + tempMiiPath + ".png" }); 
                // res.redirect("/converted/" + tempMiiPath + ".png");
            }, 5000);
            setTimeout(() => {
                fs.unlinkSync("./static/converted/" + tempMiiPath + ".png");
            }, 10000);
            return;
        }
    }
    catch (e) {
        console.log(e);
        res.json({error: "Server error"});
    }
});
site.post('/signup', async (req, res) => {
    // TODO: JWT model

    // Field validation
    if (!validator.isEmail(req.body.email)) {
        res.json({ error: "Invalid email address" });
        return;
    }
    const cleanEmail = validator.normalizeEmail(req.body.email);

    // Validate username
    const existingUsername = await getUserByUsername(req.body.username);
    if (existingUsername) {
        res.json({ error: "Username already taken" });
        return;
    }
    if (isBad(req.body.username) || existingUsername || !validate(req.body.username)) {
        res.json({ error: "Username invalid" });
        return;
    }

    // Account does not already exist
    const existingUserEmail = await Users.exists({ email: cleanEmail })
    if (existingUserEmail) {
        res.json({ error: "Email already in use" });
        return;
    }
    
    // Check IP ban
    const clientIPs = [req.headers['x-forwarded-for'], req.socket.remoteAddress]
        .filter(Boolean)
        .map(ip => sha256(ip))
    const settings = await getSettings();
    if (settings.bannedIPs.some( ip => clientIPs.includes(ip))) {
        return res.json({ error: 'This IP address has been permanently banned from creating accounts.' });
    }
    
    var hashedPassword = hashPassword(req.body.pass);
    var token = genToken();
    
    await Users.create({
        username: req.body.username,
        salt: hashedPassword.salt,
        pass: hashedPassword.hash,
        verificationToken: hashPassword(token, hashedPassword.salt).hash,
        creationDate: Date.now(),
        email: cleanEmail,
        roles: [ ROLES.BASIC ],
    });
    
    let link = "https://infinimii.com/verify?user=" + encodeURIComponent(req.body.username) + "&token=" + encodeURIComponent(token);
    sendEmail(cleanEmail, "InfiniMii Verification", 
        "Welcome to InfiniMii! If you initiated this message, verify your email by clicking this link: " + link
    );
    res.json({ message: "Check your email to verify your account!" });
});
site.post('/login', async (req, res) => {
    const user = await getUserByUsername(req.body.username);
    if (!user) {
        res.json({ error: "Invalid username or password" });
        return;
    }
    
    if (validatePassword(req.body.pass, user.salt, user.pass)) {
        if (user.verified) {
            // Create JWT token
            const token = createToken(user);
            
            res.cookie('token', token, {
                maxAge: 30 * 24 * 60 * 60 * 1000, // 1 Month
                httpOnly: true, // Prevent XSS leaking - TODO: changing username should require password because it should return a JWT with a version increase
                secure: process.env.NODE_ENV === 'production', // HTTPS only in production
                sameSite: 'lax' // CSRF protection
            });
            res.cookie('username', req.body.username, { 
                maxAge: 30 * 24 * 60 * 60 * 1000 
            });
        }
        else {
            res.json({ error: "Email not verified yet" }); 
            // TODO: should this prevent login until email validated? Maybe add a resend code button. 
            // TODO: if email is never validated, the username is lost... give them maybe 24 hours to verify their email before deleting the account...
            return;
        }
    }
    res.json({ redirect: "/" }); 
});

site.get("/error", async(req, res) => {
    let crash = undefined.field;
});

// Error-handling middleware at the bottom of the stack
site.use(async (err, req, res, next) => {
    console.error(err);
    // TODO: remove try catch from all endpoints in favor of this handler

    // Check what the client accepts
    if (!req.accepts('html')) {
        // If it doesn't want HTML at all, serve it json.
        res.status(500).json({
            error: {
                message: err.message || 'Internal Server Error',
                // optional: stack trace in dev
                ...(process.env.NODE_ENV === 'development' && { stack: `DEV STACK: ` + err.stack }),
            }
        });
    } else {
        return await sendError(res, req, "Internal Server Error. Please try again later.", 500);
    }
});

setInterval(async () => {
    var curTime = new Date();
    const settings = await getSettings();
    if (curTime.getHours() === 22 && settings.highlightedMiiChangeDay !== curTime.getDay()) {
        makeReport("**Don't forget to set a new Highlighted Mii!**");
    }
}, 1000 * 60 * 60);

// TODO: reset password functionality which should increase token version

// TODO: "Check your email to verify your account!" should be feedback on the site, not a new page

// TODO: verify pass and salt are strings of len>1

// TOOD: /logout should not give no auth errors

// TODO: middlewhare should serve json responses...

// TODO: username changes need to change mii's uploader field. 

///// Utils:
// - Look for opening <% without closing one
// <%(?![\s\S]*%>)

///// Utils:
// - Look for opening <% without closing one
// <%(?![\s\S]*%>)
