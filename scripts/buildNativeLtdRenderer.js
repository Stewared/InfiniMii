#!/usr/bin/env node

import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { resolveLtdRuntimePaths } from "../ltdRuntimePaths.js";

const appRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));

function readLocalEnvironment() {
  try {
    return JSON.parse(readFileSync(join(appRoot, "env.json"), "utf8"));
  } catch {
    return {};
  }
}

const localEnvironment = readLocalEnvironment();
const rendererRoot = resolveLtdRuntimePaths({
  ...localEnvironment,
  ...process.env,
}).rendererRoot;
const python =
  String(
    process.env.LTD_RENDERER_PYTHON ||
      localEnvironment.LTD_RENDERER_PYTHON ||
      "python"
  ).trim() || "python";

if (!existsSync(rendererRoot)) {
  console.error(
    `LTD renderer source is missing: ${rendererRoot}. ` +
      "Copy the LTD runtime drop into ltd-renderer or configure LTD_RENDERER_ROOT."
  );
  process.exit(1);
}

const builders = [
  join(rendererRoot, "tools", "build_native_current_draw.py"),
  join(rendererRoot, "tools", "build_native_face_target.py"),
  join(rendererRoot, "tools", "build_native_raster_kernel.py"),
];

if (process.platform === "win32") {
  const nativeRuntimeBuild = join(rendererRoot, "native_runtime", "build.ps1");
  if (!existsSync(nativeRuntimeBuild)) {
    console.error(
      `Native LTD runtime build script is missing: ${nativeRuntimeBuild}`
    );
    process.exit(1);
  }
  const completed = spawnSync(
    "powershell.exe",
    ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", nativeRuntimeBuild],
    {
      cwd: rendererRoot,
      stdio: "inherit",
      windowsHide: true,
    }
  );
  if (completed.error) {
    console.error(
      `Unable to build the native LTD runtime: ${completed.error.message}`
    );
    process.exit(1);
  }
  if (completed.status !== 0) process.exit(completed.status ?? 1);

  const nativeRuntimeExecutable = join(
    rendererRoot,
    "native_runtime",
    "build",
    "ltd_native_runtime.exe"
  );
  const probed = spawnSync(nativeRuntimeExecutable, ["--probe"], {
    cwd: rendererRoot,
    encoding: "utf8",
    windowsHide: true,
  });
  if (probed.error || probed.status !== 0) {
    console.error(
      `Unable to probe native LTD runtime activation: ${
        probed.error?.message || probed.stderr || "probe failed"
      }`
    );
    process.exit(probed.status ?? 1);
  }
  let readiness;
  try {
    const envelope = JSON.parse(String(probed.stdout || "").trim());
    readiness =
      envelope?.ok === true && envelope?.op === "readiness"
        ? envelope.result
        : null;
  } catch {
    readiness = null;
  }
  if (
    readiness?.protocol_ready !== true ||
    readiness?.activation_ready !== true ||
    readiness?.capabilities?.native_render !== true ||
    readiness?.capabilities?.native_png !== true ||
    !Array.isArray(readiness?.activation_blockers) ||
    readiness.activation_blockers.length !== 0
  ) {
    console.error(
      "Native LTD runtime did not pass its authenticated activation probe."
    );
    process.exit(1);
  }
}

for (const builder of builders) {
  const completed = spawnSync(python, [builder, "--force"], {
    cwd: rendererRoot,
    stdio: "inherit",
    windowsHide: true,
  });
  if (completed.error) {
    console.error(`Unable to launch ${python}: ${completed.error.message}`);
    process.exit(1);
  }
  if (completed.status !== 0) process.exit(completed.status ?? 1);
}

const activationCheck = [
  "import sys",
  `sys.path.insert(0, ${JSON.stringify(join(rendererRoot, "renderer"))})`,
  "import native_current_draw,native_face_target,native_raster_kernel",
  "assert native_current_draw.BACKEND_AVAILABLE, native_current_draw.IMPORT_ERROR",
  "assert native_face_target.BACKEND_AVAILABLE, native_face_target.IMPORT_ERROR",
  "assert native_raster_kernel.BACKEND_AVAILABLE, native_raster_kernel.IMPORT_ERROR",
].join(";");
const activated = spawnSync(python, ["-c", activationCheck], {
  cwd: rendererRoot,
  stdio: "inherit",
  windowsHide: true,
});
if (activated.error) {
  console.error(
    `Unable to verify native LTD renderer activation: ${activated.error.message}`
  );
  process.exit(1);
}
if (activated.status !== 0) process.exit(activated.status ?? 1);
console.log("Native LTD renderer acceleration modules are active.");
