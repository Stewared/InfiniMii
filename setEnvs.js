// Utility to set process environment variables from envs.json
//   If beta, it sets fields like process.env.field to process.env.betaField if it exists.

// The server should not early-exit
let skipValidateEnvs = process.argv.includes("--ignore-missing-envs");

import { readFileSync } from "fs";
import chalk from "chalk";

// Create require for more consistent env.json finding.
import { createRequire } from "module";
const require = createRequire(import.meta.url);

// Node 25+ defines a global navigator without `gpu`, which causes
// miijs to skip its Node WebGPU bootstrap path.
if (process.versions?.node && globalThis.navigator && !globalThis.navigator.gpu) {
    try {
        delete globalThis.navigator;
    }
    catch { }
}

// Utility to catch errors reading envs
function readEnvs(filename, warningOnMissing, warningOnInvalid, errorCallback) {
    let path;
    try {
        path = require.resolve(filename);
    }
    catch {
        // require.resolve throws an error if it cannot find it
        if (!skipValidateEnvs) console.log(warningOnMissing);
        skipValidateEnvs = true; // Can't validate envs if any failed to load
        errorCallback?.();
        console.log(chalk.red("env checking will be disabled due to invalid files."));
        return {};
    }
    try {
        return JSON.parse(readFileSync(path, "utf-8").toString());
    }
    catch {
        if (!skipValidateEnvs) console.log(warningOnInvalid);
        skipValidateEnvs = true; // Can't validate envs if any failed to load
        errorCallback?.();
        console.log(chalk.red("env checking will be disabled due to invalid files."));
        return {};
    }
}
const envs = readEnvs(
    "./env.json",
    chalk.red("Missing env.json file, please see the README.md for how to create it."),
    chalk.red("Invalid env.json file, please see the README.md for how to create it, " + chalk.bold("and make sure you removed the comments" + ".")),
    () => process.exit(1) // Envs are required to boot
);
const envTemplate = readEnvs(
    "./example.env.json",
    chalk.yellow("Missing example.env.json file, make sure you did not delete it when creating envs."),
    chalk.yellow("Invalid example.env.json, make sure you did not modify it.")
);


const isBeta = Boolean(envs.beta);
const optionalEnvs = new Set([
    "researchHook",
    "INDEXNOW_KEY",
    "OAUTH_AUTO_CREATE_ACCOUNTS",
    "OAUTH_AUTO_LINK_EMAIL",
    "GOOGLE_CLIENT_ID",
    "GOOGLE_CLIENT_SECRET",
    "GOOGLE_CALLBACK_URL",
    "DISCORD_CLIENT_ID",
    "DISCORD_CLIENT_SECRET",
    "DISCORD_CALLBACK_URL",
    "GITHUB_CLIENT_ID",
    "GITHUB_CLIENT_SECRET",
    "GITHUB_CALLBACK_URL",
    "MICROSOFT_CLIENT_ID",
    "MICROSOFT_CLIENT_SECRET",
    "MICROSOFT_TENANT_ID",
    "MICROSOFT_CALLBACK_URL",
    "APPLE_CLIENT_ID",
    "APPLE_CLIENT_SECRET",
    "APPLE_TEAM_ID",
    "APPLE_KEY_ID",
    "APPLE_PRIVATE_KEY",
    "APPLE_CALLBACK_URL",
    "FACEBOOK_CLIENT_ID",
    "FACEBOOK_CLIENT_SECRET",
    "FACEBOOK_APP_ID",
    "FACEBOOK_APP_SECRET",
    "FACEBOOK_CALLBACK_URL",
    "X_CLIENT_ID",
    "X_CLIENT_SECRET",
    "X_CALLBACK_URL",
    "TWITTER_CLIENT_ID",
    "TWITTER_CLIENT_SECRET",
    "TWITCH_CLIENT_ID",
    "TWITCH_CLIENT_SECRET",
    "TWITCH_CALLBACK_URL",
    "STEAM_CLIENT_ID",
    "STEAM_CALLBACK_URL"
]);
let compiledEnvs = structuredClone(envs); // Start with all defined so ones missing from example are still defined
const missingEnvs = [];
const optionalEnvPathsToDelete = [];

function trackMissingOptionalEnv(fullKey, envPath) {
    if (!missingEnvs.includes(fullKey)) missingEnvs.push(fullKey);
    if (envPath && !optionalEnvPathsToDelete.includes(envPath)) optionalEnvPathsToDelete.push(envPath);
}

function deleteCompiledEnvValue(target, path) {
    const keys = String(path || "").split(".").filter(Boolean);
    if (!keys.length) return;

    const lastKey = keys.pop();
    let current = target;

    for (const key of keys) {
        if (!current || typeof current !== "object") return;
        current = current[key];
    }

    if (current && typeof current === "object" && lastKey in current) {
        delete current[lastKey];
    }
}

function validateEnvTemplate(template, envs, parentKey = "", parentEnvPath = "") {
    const scopedEnvs = envs && typeof envs === "object" ? envs : {};
    let levelsCompiledEnvs = {};
    for (const [key, value] of Object.entries(template)) {
        const fullKey = parentKey ? `${parentKey}.${key}` : key;

        const betaReplacementKey = `beta${key[0].toUpperCase() + key.slice(1)}`;
        const isBetaReplacementSet = betaReplacementKey in scopedEnvs;
        const keyToUse = isBeta && isBetaReplacementSet ? betaReplacementKey : key;
        const envPath = parentEnvPath ? `${parentEnvPath}.${keyToUse}` : keyToUse;

        // Recurse if looking at object
        if (value && typeof value === "object" && !Array.isArray(value)) {
            levelsCompiledEnvs[key] = validateEnvTemplate(value, scopedEnvs[keyToUse], fullKey, envPath);
            continue;
        }

        const isSet = keyToUse in scopedEnvs;
        const envWasLeftAsDefault = isSet && scopedEnvs[keyToUse] === value;

        if (!skipValidateEnvs && (!isSet || envWasLeftAsDefault)) {
            if (optionalEnvs.has(fullKey)) {
                trackMissingOptionalEnv(fullKey, envPath);
                continue;
            }
            console.log(chalk.red(`${envWasLeftAsDefault ? "Unchanged" : "Missing required"} environment variable ${chalk.yellow.bold(fullKey)} in ${chalk.bold("env.json")}.`));
            console.log(chalk.red("Field description:"), chalk.yellow(value));
            console.log(chalk.red("Cannot start without this, please add it."));
            process.exit(1);
        }
        else {
            levelsCompiledEnvs[key] = scopedEnvs[keyToUse];
        }
    }
    return levelsCompiledEnvs;
}

// Validate envs against template
if (!skipValidateEnvs) {
    const validatedEnvs = validateEnvTemplate(envTemplate, envs);
    compiledEnvs = { ...compiledEnvs, ...validatedEnvs };

    for (const envPath of optionalEnvPathsToDelete) {
        deleteCompiledEnvValue(compiledEnvs, envPath);
    }
}

// Apply compiledEnvs to process.env
Object.keys(compiledEnvs).forEach(key => process.env[key] = compiledEnvs[key]);

// Envs are all strings, so make beta falsy if it's "false"
if (process.env.beta == "false") delete process.env.beta;

export default {
    missingEnvs,
    envs: compiledEnvs, // process.env only supports strings, objects need to be pulled from here.
    env: compiledEnvs   // Alias
};
