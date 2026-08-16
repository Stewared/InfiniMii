import path from "node:path";
import { fileURLToPath } from "node:url";

export const INFINIMII_ROOT = path.dirname(fileURLToPath(import.meta.url));
export const DEFAULT_LTD_RENDERER_ROOT = path.join(
  INFINIMII_ROOT,
  "ltd-renderer",
  "dcmp"
);
export const DEFAULT_LTD_RENDERER_ASSET_ROOT = path.join(
  INFINIMII_ROOT,
  "ltd-renderer",
  "ltdDemo_converted_assets"
);

export function resolveInfiniMiiPath(configuredValue, fallback) {
  const configured = String(configuredValue ?? "").trim();
  if (!configured) return path.resolve(fallback);
  return path.resolve(
    path.isAbsolute(configured)
      ? configured
      : path.join(INFINIMII_ROOT, configured)
  );
}

export function resolveLtdRuntimePaths(environment = process.env) {
  return Object.freeze({
    rendererRoot: resolveInfiniMiiPath(
      environment.LTD_RENDERER_ROOT,
      DEFAULT_LTD_RENDERER_ROOT
    ),
    assetRoot: resolveInfiniMiiPath(
      environment.LTD_RENDERER_ASSET_ROOT,
      DEFAULT_LTD_RENDERER_ASSET_ROOT
    ),
  });
}
