import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const indexSource = fs.readFileSync(path.join(root, "index.js"), "utf8");
const rendererSource = fs.readFileSync(path.join(root, "miiImageRenderer.js"), "utf8");
const rerendererSource = fs.readFileSync(path.join(root, "rerenderer.js"), "utf8");

test("shared image boundary routes instead of canonicalizing every source to LTD", () => {
    assert.match(rendererSource, /resolveMiiRendererRoute\(mii/);
    assert.match(rendererSource, /route\.backend\s*===\s*["']LTD["']/);
    assert.match(rendererSource, /renderTlMiiImageResult\(mii/);
    assert.match(rendererSource, /rendererProfile:\s*route\.profile/);
    assert.match(rendererSource, /rendererBackend:\s*route\.backend/);
});

test("stored standard images use distinct cache state and cannot hit stale LTD state", () => {
    assert.match(indexSource, /isCurrentReadyStandardMiiRender\(mii,\s*identity\)/);
    assert.match(indexSource, /mii\?\.imageRender\?\.portrait/);
    assert.match(indexSource, /publishCasGuardedStandardMiiImage/);
    assert.match(indexSource, /persistStandardMiiRenderPortraitStateCas/);
});

test("era changes during image generation use one generic single-flight without recursive deadlock", () => {
    const ensureSource = /async function ensureCurrentStoredMiiImageAsset\([\s\S]*?\n}\n\nasync function hasCurrentStoredMiiImageAsset/.exec(indexSource)?.[0] || '';
    assert.match(ensureSource, /runLtdImageGenerationSingleFlight\(assetPath/);
    assert.match(ensureSource, /const currentMii = await resolveCurrentMii\(\)/);
    assert.match(ensureSource, /writeRenderedMiiImage\(currentMii, assetPath\)/);
    assert.match(ensureSource, /hasCurrentStoredMiiImageAsset\(committedMii, rendererRevision, assetPath\)/);
    assert.doesNotMatch(
        ensureSource.slice(ensureSource.indexOf('runLtdImageGenerationSingleFlight')),
        /ensureCurrentStoredMiiImageAsset\(/
    );
    assert.doesNotMatch(ensureSource, /ensureCurrentLtdImageAsset/);
});

test("every era-aware renderer reread includes hidden native LTD bytes", () => {
    assert.match(indexSource, /resolveCurrentMii:\s*async\s*\(\)\s*=>\s*await Miis\.findOne\(\{ id: mii\.id \}\)\.select\(["']\+ltdData["']\)/);
    assert.match(rerendererSource, /Miis\.findOne\(\{ id: miiId \}\)\.select\(["']\+ltdData["']\)/);
    assert.match(indexSource, /async function getCurrentLtdRenderIdentityMii[\s\S]*?\.select\(["']\+ltdData["']\)/);
    assert.match(indexSource, /validateClaimedMii:\s*async\s*\(claimedMii\)\s*=>\s*resolveMiiRendererRoute\(claimedMii\)\.backend\s*===\s*["']LTD["']/);
});

test("legacy LTD rerender queue cannot publish a TL or RFL result through LTD CAS", () => {
    assert.match(rerendererSource, /resolveMiiRendererRoute\(miiData\)\.backend\s*!==\s*["']LTD["']/);
    assert.match(rerendererSource, /Skipped non-LTD render/);
});

test("dashboard passes a validated renderer request to both previews", () => {
    assert.match(indexSource, /requestedRendererProfile/);
    assert.match(indexSource, /resolveMiiRendererRoute\(renderSource/);
    assert.match(indexSource, /renderStoredMiiImage\(renderSource,\s*renderOptions\)/);
    assert.match(indexSource, /renderStoredMiiImage\(renderSource,\s*\{\s*\.\.\.renderOptions,\s*fullBody:\s*true\s*\}\)/);
    assert.match(indexSource, /dashboardRendererProfile\s*=\s*rendererRoute\.profile\s*===\s*["']RFL["']\s*\?\s*["']["']/);
    assert.match(indexSource, /rendererProfile:\s*dashboardRendererProfile/);
    assert.match(indexSource, /availableRendererProfiles:\s*rendererRoute\.locked\s*\?\s*\[["']LTD["']\]\s*:\s*\[["']TL["'],\s*["']LTD["']\]/);
});

test("ID-only dashboard rendering uses stored data only after the LTD access gate", () => {
    assert.match(indexSource, /const hasExplicitMiiPayload\s*=\s*Boolean\(req\.file\s*\|\|\s*rawInput\s*\|\|\s*objectInput\)/);
    assert.match(indexSource, /assertLtdWorkspaceAccessAvailable\(resolved\.record,\s*["']dashboard["'],\s*\{\s*storedRecord:\s*true\s*\}\)/);
    assert.match(indexSource, /renderSource:\s*!hasExplicitMiiPayload\s*&&\s*storedRecord\s*\?\s*storedRecord\s*:\s*decoded\.mii/);
});
