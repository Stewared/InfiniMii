import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const testDirectory = path.dirname(fileURLToPath(import.meta.url));
const indexSource = fs.readFileSync(
  path.join(testDirectory, "..", "index.js"),
  "utf8"
);
const dashboardSource = fs.readFileSync(
  path.join(testDirectory, "..", "static", "js", "miiDashboard.js"),
  "utf8"
);
const miiPageSource = fs.readFileSync(
  path.join(testDirectory, "..", "ejsFiles", "miiPage.ejs"),
  "utf8"
);

function routeSource(startMarker, endMarker) {
  const start = indexSource.indexOf(startMarker);
  assert.ok(start >= 0, `missing route marker: ${startMarker}`);
  const end = indexSource.indexOf(endMarker, start + startMarker.length);
  assert.ok(end > start, `missing route boundary: ${endMarker}`);
  return indexSource.slice(start, end);
}

test("Wiimote uploads are decoded as trusted bytes before the RCD policy assertion", () => {
  const route = routeSource(
    "site.post('/api/wiimote/importData'",
    "site.post('/extractMiiFromAmiibo'"
  );
  assert.match(route, /createMiiData\(trustedMiiFileInput\(req\.file\)\)/);
  assert.match(route, /downloadPolicySource\s*=\s*miiInput/);
  assert.match(
    route,
    /assertMiiDownloadFormat\(downloadPolicySource,\s*["']rcd["']/
  );
});

test("dashboard policy continuity is server-signed and sourceMiiEra is not trusted", () => {
  const analyzeRoute = routeSource(
    "site.post('/miiDashboard/analyze'",
    "site.post('/miiDashboard/saveJson'"
  );
  const convertRoute = routeSource(
    "site.post('/convertMii'",
    "site.post('/makeMiiChild'"
  );

  assert.match(analyzeRoute, /verifyMiiDownloadPolicyToken/);
  assert.match(analyzeRoute, /createMiiDownloadPolicyToken/);
  assert.doesNotMatch(
    analyzeRoute,
    /!storedRecord\s*&&\s*submittedPolicyToken/
  );
  assert.match(
    analyzeRoute,
    /decodedDownloadPolicy\s*=\s*getMiiDownloadPolicy\(decoded\.mii\)/
  );
  assert.match(
    analyzeRoute,
    /storedDownloadPolicy\?\.ltdOnly\s*\|\|\s*decodedDownloadPolicy\.ltdOnly\s*\|\|\s*verifiedTokenPolicy\?\.ltdOnly/
  );
  assert.match(convertRoute, /verifyMiiDownloadPolicyToken/);
  assert.doesNotMatch(
    convertRoute,
    /if\s*\(sourceMiiId\)[\s\S]*?}\s*else\s*{\s*const submittedPolicyToken/
  );
  assert.match(
    convertRoute,
    /decodedDownloadPolicy\s*=\s*getMiiDownloadPolicy\(miiData\)/
  );
  assert.match(
    convertRoute,
    /effectiveLtdOnly\s*=\s*decodedDownloadPolicy\.ltdOnly\s*\|\|\s*storedDownloadPolicy\?\.ltdOnly\s*\|\|\s*verifiedTokenPolicy\?\.ltdOnly/
  );
  assert.match(
    convertRoute,
    /\.\.\.\(effectiveLtdOnly\s*\?\s*\{\s*era:\s*["']LTD["']/
  );
  assert.doesNotMatch(convertRoute, /sourceMiiEra/);
  assert.match(
    dashboardSource,
    /downloadPolicyToken:\s*dashboardState\?\.downloadPolicyToken/
  );
  assert.match(
    dashboardSource,
    /downloadPolicyMiiData:\s*dashboardState\?\.downloadPolicyToken/
  );
});

test("private stored-Mii policy resolution includes hidden native LTD bytes", () => {
  const resolverStart = indexSource.indexOf(
    "async function resolveMiiIdForImport"
  );
  const resolverEnd = indexSource.indexOf(
    "async function resolveMiiInputForInstructions",
    resolverStart
  );
  assert.ok(resolverStart >= 0 && resolverEnd > resolverStart);
  const resolver = indexSource.slice(resolverStart, resolverEnd);

  assert.match(resolver, /resolveMiiIdForImportWithLookups/);
  assert.match(
    resolver,
    /findPrivateMii:[\s\S]*?Miis\.findOne\(\{\s*id:\s*trimmedId,\s*private:\s*true\s*\}\)[\s\S]*?\.select\(["']\+ltdData["']\)[\s\S]*?\.lean\(\)/
  );
});

test("every LTD attachment response is marked non-cacheable", () => {
  const helperStart = indexSource.indexOf("async function sendExportResponse");
  const helperEnd = indexSource.indexOf(
    "async function exportMiiById",
    helperStart
  );
  assert.ok(helperStart >= 0 && helperEnd > helperStart);
  const helper = indexSource.slice(helperStart, helperEnd);

  assert.match(
    helper,
    /if\s*\(normalized\s*===\s*["']ltd["']\)\s*{[\s\S]*?applyNoCacheHeaders\(res\)/
  );
  assert.match(helper, /LTD_SHAREMII_IMPORT_UNSAFE[\s\S]*?status\(422\)/);
  assert.match(helper, /res\.send\(buffer\)/);
});

test("LTD exports wrap authoritative bytes in the ShareMii 3.0 compatibility envelope", () => {
  const helperStart = indexSource.indexOf("async function exportMiiToBuffer");
  const helperEnd = indexSource.indexOf(
    "async function writeQrPng",
    helperStart
  );
  assert.ok(helperStart >= 0 && helperEnd > helperStart);
  const helper = indexSource.slice(helperStart, helperEnd);

  assert.match(
    helper,
    /if\s*\(format\s*===\s*["']ltd["']\)[\s\S]*?ensureCanonicalLtdForMii\([\s\S]*?buildShareMiiV3CompatibleLtdDownload\(canonical\.bytes\)/
  );
});

test("unsafe ShareMii files receive an explicit 422 at every public ingestion boundary", () => {
  const uploadRoute = routeSource(
    "site.post('/uploadMii'",
    "site.post('/updateOfficialCategories'"
  );
  const exportRoute = routeSource(
    "site.post('/exportMii'",
    "site.get('/downloadMii'"
  );
  const dashboardRoute = routeSource(
    "site.post('/miiDashboard/analyze'",
    "site.post('/miiDashboard/saveJson'"
  );
  const convertRoute = routeSource(
    "site.post('/convertMii'",
    "site.post('/makeMiiChild'"
  );

  for (const source of [uploadRoute, exportRoute, convertRoute]) {
    assert.match(source, /LTD_SHAREMII_IMPORT_UNSAFE/);
    assert.match(source, /status\(422\)/);
  }
  assert.match(dashboardRoute, /buildMiiDashboardErrorPayload/);
  assert.match(dashboardRoute, /LTD_SHAREMII_IMPORT_UNSAFE[\s\S]*?422/);
  assert.match(
    indexSource,
    /buildMiiDashboardErrorPayload[\s\S]*?LTD_SHAREMII_IMPORT_UNSAFE[\s\S]*?code:\s*error\.code/
  );
});

test("ID-only dashboard loads authorize private access before rejecting LTD workspaces", () => {
  const analyzeRoute = routeSource(
    "site.post('/miiDashboard/analyze'",
    "site.post('/miiDashboard/saveJson'"
  );
  const resolveIndex = analyzeRoute.indexOf(
    "resolveMiiIdForImport(miiId, req)"
  );
  const accessErrorIndex = analyzeRoute.indexOf(
    "if (resolved.error)",
    resolveIndex
  );
  const ltdPolicyIndex = analyzeRoute.indexOf(
    'assertLtdWorkspaceAccessAvailable(resolved.record, "dashboard", { storedRecord: true })',
    accessErrorIndex
  );

  assert.ok(resolveIndex >= 0);
  assert.ok(accessErrorIndex > resolveIndex);
  assert.ok(ltdPolicyIndex > accessErrorIndex);
  assert.match(analyzeRoute, /miiInput\s*=\s*resolved\.mii/);
  assert.doesNotMatch(analyzeRoute, /getStoredMiiDashboardDecodeInput/);
  assert.match(analyzeRoute, /storedRecord\s*=\s*resolved\.record/);
  assert.match(
    analyzeRoute,
    /renderSource:\s*!hasExplicitMiiPayload\s*&&\s*storedRecord\s*\?\s*storedRecord\s*:\s*decoded\.mii/
  );
});

test("LTD workspace restrictions cover Dashboard, admin save, and Kidomatic boundaries", () => {
  const analyzeRoute = routeSource(
    "site.post('/miiDashboard/analyze'",
    "site.post('/miiDashboard/saveJson'"
  );
  const saveRoute = routeSource(
    "site.post('/miiDashboard/saveJson'",
    "site.get('/miiChild'"
  );
  const kidomaticRoute = routeSource(
    "site.post('/makeMiiKidomatic'",
    "site.post('/signup'"
  );

  assert.match(
    analyzeRoute,
    /assertLtdWorkspaceAccessAvailable\(objectInput,\s*["']dashboard["']\)/
  );
  assert.match(
    analyzeRoute,
    /assertSerializedLtdWorkspaceAccessAvailable\(rawInput,\s*["']dashboard["']\)/
  );
  assert.match(
    analyzeRoute,
    /createMiiDataWithDebug\(miiInput\)[\s\S]*?assertLtdWorkspaceAccessAvailable\(decoded\.mii,\s*["']dashboard["']\)/
  );
  assert.match(
    analyzeRoute,
    /verifiedTokenPolicy\.ltdOnly[\s\S]*?LtdWorkspaceUnavailableError\(["']dashboard["']\)/
  );
  assert.match(
    analyzeRoute,
    /instanceof LtdWorkspaceUnavailableError[\s\S]*?sendLtdWorkspaceUnavailableError/
  );

  assert.match(
    saveRoute,
    /getMiiById\(miiId,\s*true\)[\s\S]*?assertLtdWorkspaceAccessAvailable\(existingMii,\s*["']dashboard["'],\s*\{\s*storedRecord:\s*true\s*\}\)/
  );
  assert.match(
    saveRoute,
    /instanceof LtdWorkspaceUnavailableError[\s\S]*?sendLtdWorkspaceUnavailableError/
  );

  assert.match(
    kidomaticRoute,
    /assertLtdWorkspaceAccessAvailable\(objectInput,\s*["']kidomatic["']\)/
  );
  assert.match(
    kidomaticRoute,
    /assertSerializedLtdWorkspaceAccessAvailable\(rawInput,\s*["']kidomatic["']\)/
  );
  assert.match(
    kidomaticRoute,
    /assertLtdWorkspaceAccessAvailable\(miiData,\s*["']kidomatic["']\)[\s\S]*?miijs\.kidomatic/
  );
  assert.match(
    kidomaticRoute,
    /instanceof LtdWorkspaceUnavailableError[\s\S]*?sendLtdWorkspaceUnavailableError/
  );
});

test("LTD Mii pages hide recreation tools, Dashboard, and Kidomatic without a page-wide LTD fork", () => {
  assert.match(
    indexSource,
    /miiWorkspaceToolsEnabled\s*=\s*!miiPageDownloadPolicy\.ltdOnly/
  );
  assert.match(
    miiPageSource,
    /if\s*\(showMiiWorkspaceTools\)\s*\{[\s\S]*?Recreation Instructions[\s\S]*?\/miiDashboard\?id=[\s\S]*?kidomatic=1[\s\S]*?\}/
  );
  assert.equal((miiPageSource.match(/\/miiPage\.css/g) || []).length, 1);
  assert.doesNotMatch(miiPageSource, /<(?:html|body)[^>]*class=["'][^"']*ltd/i);
});

test("LTD Mii pages disable format conversion while keeping the direct LTD download selected", () => {
  assert.match(
    miiPageSource,
    /miiPageLtdConversionPending\s*=\s*miiPageExportValues\.length\s*>\s*0[\s\S]*?\.every\(\(value\)\s*=>\s*value\s*===\s*["']ltd["']\)/
  );
  assert.match(
    miiPageSource,
    /data-export-picker-disabled="<%=\s*miiPageLtdConversionPending\s*\?\s*["']true["']\s*:\s*["']false["']\s*%>"/
  );
  assert.match(
    miiPageSource,
    /if\s*\(miiPageLtdConversionPending\)\s*\{\s*%>\s*disabled[\s\S]*?aria-disabled=["']true["']/
  );
  assert.match(
    miiPageSource,
    /role=["']tooltip["'][^>]*><%=\s*miiPageLtdConversionTooltip\s*%>/
  );
  assert.match(miiPageSource, /LTD Mii Conversion is coming soon!/);
  assert.match(
    miiPageSource,
    /name=["']format["']\s+value=["']<%=\s*miiPageLtdConversionPending\s*\?\s*["']ltd["']\s*:\s*["']["']\s*%>["']/
  );
  assert.match(
    miiPageSource,
    /miiPageLtdConversionPending\s*\?\s*["']Download LTD["']\s*:\s*["']Download["']/
  );
  assert.match(
    miiPageSource,
    /if\s*\(miiPageQrExportsEnabled\)[\s\S]*?else if\s*\(miiPageLtdConversionPending\)[\s\S]*?class=["']ltd-photo-download["']/
  );
  assert.match(
    miiPageSource,
    /href=["']\/exportMii\?id=<%=\s*encodeURIComponent\(mii\.id\)\s*%>&amp;format=ltd["'][\s\S]*?<span>Download LTD<\/span>/
  );
});

test("stored QR middleware and automatic QR synchronization use per-record policy", () => {
  assert.match(
    indexSource,
    /site\.use\('\/miiQRs',\s*requireStoredMiiQrExportAllowed\)/
  );
  assert.match(
    indexSource,
    /site\.use\('\/privateMiiQRs',\s*requireStoredMiiQrExportAllowed\)/
  );
  assert.match(
    indexSource,
    /syncStoredMiiQrAssets[\s\S]*getMiiDownloadPolicy\(policyMii/
  );
  assert.match(
    indexSource,
    /serveGeneratedMiiQrAsset[\s\S]*isCurrentMiiQrCacheAsset\(mii, qrPath, qrConsole, portraitPath\)/
  );
  assert.match(
    indexSource,
    /winnerMii[\s\S]*getMiiDownloadPolicyPayloadHash\(currentMii\)[\s\S]*publishMiiQrCacheIdentity/
  );
  assert.match(
    indexSource,
    /Miis\.findOne\(\{ id: miiId, private: false \}\)\.select\("\+ltdData"\)\.lean\(\)/
  );
  assert.match(indexSource, /canAccessPrivateMiiAsset\([\s\S]*?winnerMii/);
  assert.match(
    indexSource,
    /syncStoredMiiQrAssets[\s\S]*winnerMii[\s\S]*sourceIdentity/
  );
  assert.match(
    indexSource,
    /site\.use\('\/miiQRs'[\s\S]*?serveGeneratedMiiQrAsset/
  );
  assert.match(
    indexSource,
    /site\.use\('\/privateMiiQRs'[\s\S]*?serveGeneratedMiiQrAsset/
  );
});

test("dashboard upload carries authoritative lineage and rejects LTD projections server-side", () => {
  const uploadRoute = routeSource(
    "site.post('/uploadMii'",
    "site.post('/updateOfficialCategories'"
  );

  assert.doesNotMatch(
    dashboardSource,
    /dashboardUploadAllowed|dashboardUploadSubmit\.disabled/
  );
  assert.match(
    dashboardSource,
    /onlyLtdExportAvailable[\s\S]*?exportSpecialOption\.hidden/
  );
  assert.match(
    dashboardSource,
    /dashboardUploadSourceMiiId\.value\s*=\s*dashboardState\?\.sourceMiiId/
  );
  assert.match(
    dashboardSource,
    /dashboardUploadDownloadPolicyToken\.value\s*=\s*dashboardState\?\.downloadPolicyToken/
  );
  assert.match(dashboardSource, /dashboardUploadDownloadPolicyMiiData\.value/);

  assert.match(
    uploadRoute,
    /resolveMiiIdForImport\(dashboardSourceMiiId,\s*req\)/
  );
  assert.match(uploadRoute, /verifyMiiDownloadPolicyToken/);
  assert.match(uploadRoute, /INVALID_DOWNLOAD_POLICY_TOKEN/);
  assert.match(
    uploadRoute,
    /storedSourcePolicy\?\.ltdOnly\s*\|\|\s*verifiedTokenPolicy\?\.ltdOnly/
  );
  assert.match(uploadRoute, /LTD_DASHBOARD_UPLOAD_UNAVAILABLE/);
  assert.match(
    uploadRoute,
    /e\?\.code\s*===\s*["']LTD_SHAREMII_IMPORT_UNSAFE["']/
  );
  assert.match(
    uploadRoute,
    /res\.status\(422\)\.json\(\{\s*error:\s*e\.message,\s*code:\s*e\.code\s*\}\)/
  );
});

test("saving dashboard JSON cannot downgrade an explicit stored LTD era", () => {
  const saveHelper = indexSource.slice(
    indexSource.indexOf("async function saveDashboardMiiFields"),
    indexSource.indexOf("async function saveDashboardMiiFields") + 12000
  );
  assert.match(
    saveHelper,
    /getMiiDownloadPolicy\(existingMii,\s*\{\s*storedRecord:\s*true\s*\}\)\.ltdOnly\s*&&\s*!replacementCarriesLtd/
  );
  assert.doesNotMatch(
    saveHelper,
    /existingMii\?\.ltdProvenance\?\.kind\s*===\s*["']native-upload["']/
  );
});
