import { readSiteInventory } from "./artifact.js";
import {
  readArchiveDirectory,
  readCatalogFile,
  readSiteDirectory,
  writeSiteDirectory,
} from "./filesystem.js";
import {
  renderFinal,
  renderRoutes,
  verifyCatalogArchives,
  verifyMonotonic,
  verifySite,
} from "./render.js";

export const USAGE = [
  "usage: pkgre-js check CATALOG ARCHIVE_DIRECTORY",
  "       pkgre-js render-routes CATALOG ARCHIVE_DIRECTORY PREVIOUS_SITE OUTPUT",
  "       pkgre-js render-final CATALOG ROUTES_SITE OUTPUT",
  "       pkgre-js verify CATALOG SITE",
  "       pkgre-js verify-monotonic PREVIOUS_SITE NEXT_SITE",
  "       pkgre-js --help",
].join("\n");

function success(output) {
  return { status: 0, stderr: "", stdout: `${output}\n` };
}

function usageError(message) {
  return { status: 2, stderr: `error: ${message}\n${USAGE}\n`, stdout: "" };
}

function operationalError(error) {
  const message = error instanceof Error ? error.message : "unknown operational failure";
  return { status: 1, stderr: `error: ${message}\n`, stdout: "" };
}

function counts(catalog) {
  return {
    packages: catalog.packages.length,
    versions: catalog.packages.reduce((total, entry) => total + entry.versions.length, 0),
  };
}

async function check([catalogPath, archivePath]) {
  const catalog = await readCatalogFile(catalogPath);
  const archives = await readArchiveDirectory(catalog, archivePath);
  verifyCatalogArchives(catalog, archives);
  const { packages, versions } = counts(catalog);
  return `ok command=check packages=${packages} versions=${versions} archives=${archives.size}`;
}

async function renderRoutesCommand([catalogPath, archivePath, previousPath, outputPath]) {
  const catalog = await readCatalogFile(catalogPath);
  const archives = await readArchiveDirectory(catalog, archivePath);
  const previous = await readSiteDirectory(previousPath);
  const site = renderRoutes(catalog, archives, previous);
  await writeSiteDirectory(outputPath, site);
  return `ok command=render-routes stage=routes files=${site.size}`;
}

async function renderFinalCommand([catalogPath, routesPath, outputPath]) {
  const catalog = await readCatalogFile(catalogPath);
  const routes = await readSiteDirectory(routesPath);
  const site = renderFinal(catalog, routes);
  await writeSiteDirectory(outputPath, site);
  return `ok command=render-final stage=final files=${site.size}`;
}

async function verify([catalogPath, sitePath]) {
  const catalog = await readCatalogFile(catalogPath);
  const site = await readSiteDirectory(sitePath);
  const result = verifySite(catalog, site);
  return `ok command=verify stage=${result.inventory.stage} files=${result.files}`;
}

async function verifyMonotonicCommand([previousPath, nextPath]) {
  const previous = await readSiteDirectory(previousPath);
  const next = await readSiteDirectory(nextPath);
  verifyMonotonic(previous, next);
  const inventory = readSiteInventory(next);
  return `ok command=verify-monotonic stage=${inventory.stage} files=${next.size}`;
}

const commands = new Map([
  ["check", { arity: 2, handler: check }],
  ["render-routes", { arity: 4, handler: renderRoutesCommand }],
  ["render-final", { arity: 3, handler: renderFinalCommand }],
  ["verify", { arity: 2, handler: verify }],
  ["verify-monotonic", { arity: 2, handler: verifyMonotonicCommand }],
]);

export async function run(args) {
  if (!Array.isArray(args) || args.some((argument) => typeof argument !== "string")) return usageError("arguments must be strings");
  if (args.length === 1 && (args[0] === "--help" || args[0] === "-h")) return success(USAGE);
  if (!args.length) return usageError("command is required");
  const command = commands.get(args[0]);
  if (!command) return usageError("unknown command");
  if (args.length !== command.arity + 1) return usageError(`${args[0]} requires ${command.arity} arguments`);
  try {
    return success(await command.handler(args.slice(1)));
  } catch (error) {
    return operationalError(error);
  }
}
