import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import ejs from 'ejs';
import { fileURLToPath } from 'node:url';

const testDirectory = path.dirname(fileURLToPath(import.meta.url));
const templatePath = path.join(testDirectory, '..', 'ejsFiles', 'miiDashboard.ejs');
const template = ejs.compile(fs.readFileSync(templatePath, 'utf8'), {
    client: true,
    filename: templatePath
});

function renderDashboard() {
    return template({
        baseUrl: 'https://example.test',
        exportFormats: [
            { value: 'qr', label: 'QR' },
            { value: 'rcd', label: 'RCD' },
            { value: 'cfcd', label: 'CFCD' },
            { value: 'charinfo', label: 'CHARINFO' },
            { value: 'ltd', label: 'LTD' }
        ],
        toScriptJson: JSON.stringify,
        user: { username: 'admin' },
        miiDescriptionMaxLength: 300,
        isAdmin: true,
        assetVersion: 'test'
    }, undefined, () => '');
}

test('dashboard restores stored-ID loading and every workspace panel', () => {
    const html = renderDashboard();

    for (const elementId of [
        'dashboardMiiId',
        'dashboardRender',
        'dashboardFullBodyRender',
        'dashboardQrPreview',
        'dashboardInfoGrid',
        'dashboardTomodachiCard',
        'dashboardUploadForm',
        'dashboardRenderAsBtn',
        'dashboardRenderAsMenu',
        'dashboardRendererStatus',
        'dashboardUploadSourceMiiId',
        'dashboardUploadDownloadPolicyToken',
        'dashboardUploadDownloadPolicyMiiData',
        'dashboardUploadSubmit',
        'dashboardJsonOutput',
        'dashboardJsonDownloadBtn',
        'dashboardSaveJsonBtn',
        'dashboardKidomaticResults',
        'dashboardExportModal'
    ]) {
        assert.match(html, new RegExp(`id=["']${elementId}["']`));
    }
    for (const profile of ['TL', 'LTD']) {
        assert.match(html, new RegExp(`data-renderer-profile=["']${profile}["']`));
    }
    assert.doesNotMatch(html, /data-renderer-profile=["']RFL["']/);
    assert.doesNotMatch(html, /LTD-era|LTD-exclusive|source era is LTD/i);
});

test('dashboard render switching preserves an explicitly clicked profile', () => {
    const source = fs.readFileSync(path.join(testDirectory, '..', 'static', 'js', 'miiDashboard.js'), 'utf8');
    assert.match(source, /rendererProfile:\s*payload\?\.rendererProfile\s*\|\|\s*dashboardState\?\.rendererProfile/);
    assert.doesNotMatch(source, /rendererLocked|qrBlocked/);
    assert.match(source, /dashboardQrCard\.hidden\s*=\s*!qrAvailable/);
    assert.match(source, /\[['"]TL['"],\s*['"]LTD['"]\]\.includes\(normalizedProfile\)\s*\?\s*normalizedProfile\s*:\s*['"]Default['"]/);
    assert.match(source, /dashboardRenderAsBtn\.textContent\s*=\s*`Render As: \$\{activeProfileLabel\}`/);
    assert.match(source, /dashboardRendererStatus\.textContent\s*=\s*`\$\{activeProfileLabel\} renderer`/);
    assert.match(source, /loadingMessage:\s*`Rendering as \$\{rendererProfileLabel\}/);
    assert.match(source, /successMessage:\s*`Rendered as \$\{rendererProfileLabel\}/);
    assert.doesNotMatch(source, /\bRFL\b|Rendering as \$\{rendererProfile\}/);
    assert.doesNotMatch(source, /LTD-era|LTD-exclusive/i);
});

test('dashboard ships every configured format and its per-result policy before its controller', () => {
    const html = renderDashboard();
    const policyScriptIndex = html.indexOf('/miiDashboardFormatPolicy.js');
    const dashboardScriptIndex = html.indexOf('/miiDashboard.js');

    assert.ok(policyScriptIndex >= 0);
    assert.ok(dashboardScriptIndex > policyScriptIndex);
    for (const format of ['qr', 'rcd', 'cfcd', 'charinfo', 'ltd']) {
        assert.match(html, new RegExp(`<option value=["']${format}["']`));
    }
});
