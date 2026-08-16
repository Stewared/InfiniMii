import assert from "node:assert/strict";
import test from "node:test";

import {
    MII_RENDERER_BACKENDS,
    MiiRendererSelectionError,
    getDefaultMiiRendererProfile,
    normalizeMiiRendererProfile,
    resolveMiiRendererRoute
} from "../miiRendererRouting.js";

test("era defaults route CFCD/TL to TL and RCD through the swappable RFL adapter", () => {
    assert.equal(getDefaultMiiRendererProfile({ era: "CFCD" }), "TL");
    assert.equal(getDefaultMiiRendererProfile({ era: "TL" }), "TL");
    assert.equal(getDefaultMiiRendererProfile({ era: "RCD" }), "RFL");
    assert.equal(getDefaultMiiRendererProfile({ era: "FFCD" }), "TL");
    assert.equal(getDefaultMiiRendererProfile({ era: "CHARINFO" }), "TL");
    assert.equal(MII_RENDERER_BACKENDS.RFL, "TL");
});

test("runtime authority repairs stale LTD values before selecting a renderer", () => {
    assert.equal(getDefaultMiiRendererProfile({
        era: "LTD",
        officialCategories: ["Wii/Wii Sports"]
    }), "RFL");
    assert.equal(getDefaultMiiRendererProfile({
        era: "LTD",
        tl: { island: { name: "Example" } },
        console: "Mii Studio"
    }), "TL");
});

test("non-LTD dashboards may explicitly select TL, RFL, or LTD", () => {
    assert.deepEqual(resolveMiiRendererRoute({ era: "CFCD" }, { requestedProfile: "rfl" }), {
        profile: "RFL",
        backend: "TL",
        defaultProfile: "TL",
        locked: false,
        sourceEra: "CFCD"
    });
    assert.equal(resolveMiiRendererRoute({ era: "RCD" }, { requestedProfile: "TL" }).profile, "TL");
    assert.equal(resolveMiiRendererRoute({ era: "CHARINFO" }, { requestedProfile: "LTD" }).profile, "LTD");
});

test("LTD-exclusive sources are locked and server-side overrides fail closed", () => {
    const lockedMii = { era: "LTD" };
    assert.deepEqual(resolveMiiRendererRoute(lockedMii), {
        profile: "LTD",
        backend: "LTD",
        defaultProfile: "LTD",
        locked: true,
        sourceEra: "LTD"
    });
    assert.throws(
        () => resolveMiiRendererRoute(lockedMii, { requestedProfile: "TL" }),
        error => error instanceof MiiRendererSelectionError && error.code === "LTD_RENDERER_LOCKED"
    );
    assert.throws(
        () => resolveMiiRendererRoute(lockedMii, {
            requestedProfile: "RFL",
            ltdExclusive: false
        }),
        error => error instanceof MiiRendererSelectionError && error.code === "LTD_RENDERER_LOCKED"
    );
});

test("John Doe/average is exempt only from LTD-exclusive locking", () => {
    const unresolvedAverage = { id: "average", era: "LTD" };
    const defaultRoute = resolveMiiRendererRoute(unresolvedAverage);
    assert.equal(defaultRoute.locked, false);
    assert.equal(defaultRoute.profile, "LTD");
    const route = resolveMiiRendererRoute(unresolvedAverage, { requestedProfile: "RFL" });
    assert.equal(route.locked, false);
    assert.equal(route.profile, "RFL");
    assert.equal(route.backend, "TL");
    assert.equal(getDefaultMiiRendererProfile({
        ...unresolvedAverage,
        console: "Mii Studio"
    }), "TL");
});

test("unknown renderer selections are rejected", () => {
    assert.throws(
        () => normalizeMiiRendererProfile("ffl"),
        error => error instanceof MiiRendererSelectionError
            && error.code === "INVALID_MII_RENDERER_PROFILE"
    );
});
