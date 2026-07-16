import assert from "node:assert/strict";
import test from "node:test";
import { resolveMiiDateMetadata } from "../miiDateMetadata.js";

const uploadedOn = Date.UTC(2024, 0, 2, 3, 4, 5);
const updatedAt = new Date(Date.UTC(2025, 1, 3, 4, 5, 6));
const pageUpdatedAt = new Date(Date.UTC(2026, 2, 4, 5, 6, 7)).toISOString();

test("non-external Miis retain publication and page-modified dates", () => {
    assert.deepEqual(
        resolveMiiDateMetadata({ uploadedOn, updatedAt }, { pageUpdatedAt }),
        {
            isExternal: false,
            publishedIso: new Date(uploadedOn).toISOString(),
            modifiedIso: pageUpdatedAt
        }
    );
});

test("external Miis omit the InfiniMii upload date", () => {
    assert.deepEqual(
        resolveMiiDateMetadata(
            { uploadedOn, updatedAt },
            { isExternal: true, pageUpdatedAt }
        ),
        {
            isExternal: true,
            publishedIso: undefined,
            modifiedIso: updatedAt.toISOString()
        }
    );
});

test("external Miis never reuse an upload-derived page date", () => {
    assert.deepEqual(
        resolveMiiDateMetadata(
            { uploadedOn },
            { isExternal: true, pageUpdatedAt: new Date(uploadedOn).toISOString() }
        ),
        {
            isExternal: true,
            publishedIso: undefined,
            modifiedIso: undefined
        }
    );
});

test("invalid stored timestamps do not produce date metadata", () => {
    assert.deepEqual(
        resolveMiiDateMetadata(
            { uploadedOn: "not-a-date", updatedAt: "also-not-a-date" },
            { pageUpdatedAt: "invalid" }
        ),
        {
            isExternal: false,
            publishedIso: undefined,
            modifiedIso: undefined
        }
    );
});
