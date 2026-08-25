import { canonicalJson, packageIdentity, validatePackageName } from "./canonical.js";
import { jsArchiveRoute } from "./marker.js";

export function packageMetadataUrl(name) {
  validatePackageName(name);
  return `https://js.pkg.re/${name}`;
}

export function renderPackument(catalog, entry) {
  validatePackageName(entry.name);
  const versions = {};
  const time = { created: entry.versions[0].publishedAt, modified: catalog.evaluationTime };
  for (const record of entry.versions) {
    const version = {
      ...record.manifest,
      _id: packageIdentity(entry.name, record.version),
      dist: {
        integrity: record.source.integrity,
        shasum: record.source.sha1,
        tarball: `https://js.pkg.re${jsArchiveRoute(record.source.sha256)}`,
      },
    };
    versions[record.version] = version;
    time[record.version] = record.publishedAt;
    if (record.publishedAt < time.created) time.created = record.publishedAt;
  }
  return Buffer.from(canonicalJson({
    _id: entry.name,
    "dist-tags": entry.distTags,
    name: entry.name,
    time,
    versions,
  }), "utf8");
}
