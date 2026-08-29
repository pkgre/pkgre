import { canonicalNpmArchiveUrl, REGISTRY_ALIAS } from "./catalog.js";
import { packageIdentity, validatePackageName, validateVersion } from "./canonical.js";

const SHA256 = /^[0-9a-f]{64}$/;

export function jsArchiveRoute(sha256) {
  if (typeof sha256 !== "string" || !SHA256.test(sha256)) throw new Error("JS archive route requires lowercase SHA-256");
  return `/v1/js/${REGISTRY_ALIAS}/${sha256}`;
}

export function renderRedirectMarker({ destination, ecosystem, kind, route }) {
  for (const [name, value] of Object.entries({ destination, ecosystem, kind, route })) {
    if (typeof value !== "string" || !value.length || !Buffer.from(value).every((byte) => byte <= 0x7f) || /[\u0000-\u0020"&<>\\]/.test(value)) {
      throw new Error(`redirect marker ${name} is unsafe`);
    }
  }
  return Buffer.from(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="pkgre-redirect" content="v1" data-ecosystem="${ecosystem}" data-route="${route}" data-kind="${kind}" data-destination="${destination}" />
<meta http-equiv="refresh" content="0;url=${destination}" />
<title>pkg.re redirect</title>
</head>
<body></body>
</html>
`, "ascii");
}

export function jsRedirectDestination(name, record) {
  validatePackageName(name);
  const version = validateVersion(record?.version);
  const source = record?.source;
  let location;
  if (source?.kind === "npmjs") location = canonicalNpmArchiveUrl(name, version);
  else if (source?.kind === "first-party") location = `https://js.pkg.re/packages/${source.sha256}.tgz`;
  else throw new Error(`${packageIdentity(name, version)} source kind cannot be rendered`);
  if (source.url !== location) throw new Error(`${packageIdentity(name, version)} source destination cannot be rendered`);
  return Object.freeze({ destinationKind: source.kind, location });
}

export function renderJsRedirectMarker(name, record) {
  const route = jsArchiveRoute(record?.source?.sha256);
  const { destinationKind, location } = jsRedirectDestination(name, record);
  return renderRedirectMarker({ destination: location, ecosystem: "js", kind: destinationKind, route });
}
