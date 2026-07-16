const assert = require("node:assert/strict");
const test = require("node:test");

const {
    getUniqueHashMatch,
    parseArguments,
    parseMiiCharactersPage,
    processMiiCharactersIndex
} = require("../fillin.cjs");

test("parses the canonical MiiCharacters page, large QR, creator, and description", () => {
    const html = `
        <div class="qrcode">
            <a href="miis/qr_large/19086_nmesalesman.jpg">
                <img src="miis/qr_thumb/19086_nmesalesman.jpg">
            </a>
        </div>
        <p class="creator">Created by: <strong><a href="index.php?u=23115&amp;ignored=1">J1N2G &amp; Co</a></strong></p>
        <p class="description">From &quot;Kirby&quot;.<br>Salesman &amp; helper.</p>
    `;

    assert.deepEqual(parseMiiCharactersPage(html, 19086), {
        qrURL: "https://www.miicharacters.com/miis/qr_large/19086_nmesalesman.jpg",
        description: 'From "Kirby". Salesman & helper.',
        externalSource: {
            extURL: "https://www.miicharacters.com/index.php?mii=19086",
            extTitle: "MiiCharacters",
            extUser: "J1N2G & Co",
            extUserURL: "https://www.miicharacters.com/index.php?u=23115"
        }
    });
});

test("supports thumb-only pages and omits incomplete external creator attribution", () => {
    const html = `
        <img src="/miis/qr_thumb/1_einstein.jpg">
        <p class="creator">Created by: Anonymous</p>
    `;
    const parsed = parseMiiCharactersPage(html, 1);

    assert.equal(parsed.qrURL, "https://www.miicharacters.com/miis/qr_thumb/1_einstein.jpg");
    assert.equal(parsed.description, "Imported from MiiCharacters.com.");
    assert.equal(parsed.externalSource.extUser, "");
    assert.equal(parsed.externalSource.extUserURL, "");
});

test("defaults to a bounded dry run and requires an explicit uploader for writes", () => {
    const defaults = parseArguments([], {});
    assert.deepEqual(defaults, {
        start: 1,
        max: 3,
        delayMs: 3000,
        uploader: "",
        write: false,
        help: false
    });

    assert.throws(() => parseArguments(["--write"], {}), /requires --uploader/);
    assert.deepEqual(
        parseArguments(["--write", "--uploader", "Importer", "--start=5", "--max", "7", "--delay-ms=0"], {}),
        {
            start: 5,
            max: 7,
            delayMs: 0,
            uploader: "Importer",
            write: true,
            help: false
        }
    );
});

test("refuses ambiguous identity-hash matches", () => {
    const index = new Map([
        ["one", [{ id: "A0001" }]],
        ["many", [{ id: "B0002" }, { id: "A0001" }]]
    ]);

    assert.equal(getUniqueHashMatch(index, "missing"), null);
    assert.equal(getUniqueHashMatch(index, "one").id, "A0001");
    assert.throws(
        () => getUniqueHashMatch(index, "many"),
        /multiple stored Miis \(A0001, B0002\)/
    );
});

function responseFrom(value, contentType = "application/octet-stream") {
    const buffer = Buffer.from(value);
    return {
        headers: { get: name => name.toLowerCase() === "content-type" ? contentType : null },
        arrayBuffer: async () => buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength)
    };
}

const importPageHtml = `
    <a href="miis/qr_large/42_example.jpg"><img src="miis/qr_thumb/42_example.jpg"></a>
    <p class="creator">Created by: <a href="index.php?u=1234&amp;ignored=1">Source User</a></p>
    <p class="description">Source description.</p>
`;

test("a hash match replaces whole meta/general objects and sets the parsed description", async () => {
    const existing = {
        _id: "mongo-id",
        id: "MII42",
        uploader: "Stored Uploader",
        desc: "Stored description",
        extTitle: "Existing source",
        meta: { name: "Old", stale: true },
        general: { favoriteColor: 1, stale: true },
        hair: { type: 7 },
        face: { type: 2 }
    };
    const decoded = {
        meta: { name: "Decoded", creatorName: "Creator" },
        general: { favoriteColor: 6, gender: 1 },
        hair: { type: 99 },
        face: { type: 99 }
    };
    const calls = { saves: [], persists: [] };
    const operations = {
        createMiiData: async input => {
            assert.deepEqual(input, Buffer.from("qr bytes"));
            return decoded;
        },
        getMiiIdentityHash: () => "same-hash",
        saveDashboardMiiFields: async (...args) => {
            calls.saves.push(args);
            return args[1];
        },
        persistUploadedMii: async (...args) => calls.persists.push(args)
    };
    const fetcher = async url => url.includes("index.php?mii=")
        ? responseFrom(importPageHtml, "text/html; charset=ISO-8859-1")
        : responseFrom("qr bytes", "image/jpeg");

    const result = await processMiiCharactersIndex(
        42,
        { write: true, uploader: "Importer" },
        operations,
        new Map([["same-hash", [existing]]]),
        fetcher
    );

    assert.equal(result.status, "updated");
    assert.equal(calls.saves.length, 1);
    assert.equal(calls.persists.length, 0);
    assert.equal(calls.saves[0][0], existing);
    assert.deepEqual(calls.saves[0][1], {
        ...existing,
        meta: decoded.meta,
        general: decoded.general
    });
    assert.deepEqual(calls.saves[0][2], {
        description: "Source description."
    });
    assert.deepEqual(calls.saves[0][1].hair, existing.hair);
    assert.deepEqual(calls.saves[0][1].face, existing.face);
    assert.notEqual(calls.saves[0][1].meta, decoded.meta);
    assert.notEqual(calls.saves[0][1].general, decoded.general);
});

test("a new hash delegates to normal persistence with exact external attribution", async () => {
    const decoded = {
        meta: { name: "Decoded" },
        general: { favoriteColor: 6 }
    };
    const calls = [];
    const operations = {
        createMiiData: async () => decoded,
        getMiiIdentityHash: () => "new-hash",
        saveDashboardMiiFields: async () => assert.fail("save path should not run"),
        persistUploadedMii: async (...args) => {
            calls.push(args);
            return { mii: { ...decoded, id: "NEW42" } };
        }
    };
    const fetcher = async url => url.includes("index.php?mii=")
        ? responseFrom(importPageHtml, "text/html; charset=ISO-8859-1")
        : responseFrom("qr bytes", "image/jpeg");

    const result = await processMiiCharactersIndex(
        42,
        { write: true, uploader: "Importer" },
        operations,
        new Map(),
        fetcher
    );

    assert.equal(result.status, "uploaded");
    assert.equal(calls.length, 1);
    assert.equal(calls[0][0], decoded);
    assert.deepEqual(calls[0][1], {
        uploader: "Importer",
        wantsPublic: true,
        desc: "Source description.",
        externalSource: {
            extURL: "https://www.miicharacters.com/index.php?mii=42",
            extTitle: "MiiCharacters",
            extUser: "Source User",
            extUserURL: "https://www.miicharacters.com/index.php?u=1234"
        }
    });
});
