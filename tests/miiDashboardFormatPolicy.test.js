import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const testDirectory = path.dirname(fileURLToPath(import.meta.url));
const policySource = fs.readFileSync(
    path.join(testDirectory, '..', 'static', 'js', 'miiDashboardFormatPolicy.js'),
    'utf8'
);
const context = vm.createContext({});
vm.runInContext(policySource, context);
const policy = context.InfiniMiiDashboardFormatPolicy;

test('dashboard defaults to every configured export format', () => {
    assert.deepEqual(
        Array.from(policy.getAllowedFormats({}, ['qr', 'rcd', 'cfcd', 'charinfo', 'ltd'])),
        ['qr', 'rcd', 'cfcd', 'charinfo', 'ltd']
    );
});

test('dashboard honors a server-provided LTD-only result', () => {
    const allowed = Array.from(policy.getAllowedFormats(
        { allowedExportFormats: ['LTD', 'not-configured'] },
        ['qr', 'rcd', 'ltd']
    ));

    assert.deepEqual(allowed, ['ltd']);
    assert.equal(policy.isLtdOnly(allowed), true);
});

test('dashboard does not broaden an explicit empty server policy', () => {
    assert.deepEqual(
        Array.from(policy.getAllowedFormats({ allowedExportFormats: [] }, ['qr', 'ltd'])),
        []
    );
});
