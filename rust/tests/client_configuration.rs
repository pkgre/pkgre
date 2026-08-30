use std::collections::{BTreeSet, HashSet};

use semver::Version;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const FIXTURE: &[u8] =
    include_bytes!("../../fixtures/dynamic-registry-v1/client/configuration.json");
const CARGO_CONFIG: &[u8] =
    include_bytes!("../../fixtures/dynamic-registry-v1/client/project/.cargo/config.toml");
const DISABLED_CRATES_IO: &[u8] = include_bytes!(
    "../../fixtures/dynamic-registry-v1/client/project/.cargo/disabled-crates-io/.gitkeep"
);
const NPM_CONFIG: &[u8] =
    include_bytes!("../../fixtures/dynamic-registry-v1/client/project/.npmrc");
const JS_PACKAGE: &str = include_str!("../../js/package.json");
const JS_CLIENTS_NIX: &str = include_str!("../../nix/js-compatibility-clients.nix");

fn fixture() -> Value {
    serde_json::from_slice(FIXTURE).unwrap()
}

fn exact_keys(value: &Value, expected: &[&str]) {
    let keys = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    assert_eq!(keys, expected);
}

fn validate_id(record: &Value, ids: &mut HashSet<String>) {
    let id = record["id"].as_str().unwrap();
    let mut bytes = id.bytes();
    assert!(matches!(bytes.next(), Some(b'a'..=b'z')));
    assert!(bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'));
    assert!(ids.insert(id.to_owned()), "duplicate ID {id}");
}

fn artifact_bytes(path: &str) -> &'static [u8] {
    match path {
        "project/.cargo/config.toml" => CARGO_CONFIG,
        "project/.cargo/disabled-crates-io/.gitkeep" => DISABLED_CRATES_IO,
        "project/.npmrc" => NPM_CONFIG,
        _ => panic!("unknown artifact {path}"),
    }
}

fn source_allowed(record: &Value) -> bool {
    if record["ecosystem"] == "javascript" {
        exact_keys(&record["declaration"], &["dependency", "specifier"]);
        return record["declaration"]["specifier"]
            .as_str()
            .is_some_and(|value| Version::parse(value).is_ok());
    }
    assert_eq!(record["ecosystem"], "rust");
    exact_keys(&record["declaration"], &["dependency", "source"]);
    let source = &record["declaration"]["source"];
    let keys = source
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    if keys != ["registry", "version"] {
        return false;
    }
    source["registry"] == "pkgre"
        && source["version"].as_str().is_some_and(|value| {
            value
                .strip_prefix('=')
                .is_some_and(|version| Version::parse(version).is_ok())
        })
}

#[test]
#[allow(clippy::too_many_lines)]
fn client_configuration_artifacts_profiles_and_policy_are_exact() {
    let fixture = fixture();
    let mut canonical = serde_json::to_vec_pretty(&fixture).unwrap();
    canonical.push(b'\n');
    assert_eq!(canonical, FIXTURE);
    exact_keys(
        &fixture,
        &[
            "artifacts",
            "cacheReplayModes",
            "clientOptionMatrix",
            "clientProfiles",
            "executionEnvelope",
            "lifecycleCases",
            "policy",
            "schema",
            "sourceCases",
        ],
    );
    assert_eq!(fixture["schema"], "pkgre-client-configuration-v1");
    assert_eq!(
        fixture["artifacts"],
        json!([
            {"bytes": 212, "path": "project/.cargo/config.toml", "sha256": "4398de6da884b0608ee094415e109f469d737e29ca66dd3236a0dad0e7e62b4a"},
            {"bytes": 0, "path": "project/.cargo/disabled-crates-io/.gitkeep", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
            {"bytes": 224, "path": "project/.npmrc", "sha256": "65f2d168c79e5c802215df19811983f3eb1b824b89f2dea3156e5ee98a4c5bf5"}
        ])
    );
    for artifact in fixture["artifacts"].as_array().unwrap() {
        exact_keys(artifact, &["bytes", "path", "sha256"]);
        let bytes = artifact_bytes(artifact["path"].as_str().unwrap());
        assert_eq!(bytes.len() as u64, artifact["bytes"].as_u64().unwrap());
        assert_eq!(
            format!("{:x}", Sha256::digest(bytes)),
            artifact["sha256"].as_str().unwrap()
        );
    }
    assert_eq!(
        std::str::from_utf8(CARGO_CONFIG).unwrap(),
        "[registries.pkgre]\nindex = \"sparse+https://rust.pkg.re/\"\n\n[registry]\ndefault = \"pkgre\"\n\n[source.crates-io]\nreplace-with = \"disabled-crates-io\"\n\n[source.disabled-crates-io]\ndirectory = \".cargo/disabled-crates-io\"\n"
    );
    assert_eq!(
        std::str::from_utf8(NPM_CONFIG).unwrap(),
        "registry=https://js.pkg.re/\nallow-directory=none\nallow-file=none\nallow-git=none\nallow-remote=none\naudit=false\nfund=false\nignore-scripts=true\nreplace-registry-host=always\nsave-exact=true\nstrict-ssl=true\nupdate-notifier=false\n"
    );
    let cargo: toml::Value = toml::from_str(std::str::from_utf8(CARGO_CONFIG).unwrap()).unwrap();
    assert_eq!(
        cargo["registries"]["pkgre"]["index"].as_str(),
        Some("sparse+https://rust.pkg.re/")
    );
    assert_eq!(cargo["registry"]["default"].as_str(), Some("pkgre"));
    assert_eq!(
        cargo["source"]["crates-io"]["replace-with"].as_str(),
        Some("disabled-crates-io")
    );
    assert_eq!(
        cargo["source"]["disabled-crates-io"]["directory"].as_str(),
        Some(".cargo/disabled-crates-io")
    );
    assert!(DISABLED_CRATES_IO.is_empty());

    assert_eq!(
        fixture["clientProfiles"],
        json!([
            {"client": "cargo", "id": "cargo-minimum-current", "roles": ["minimum", "current"], "runtime": null, "runtimeVersion": null, "version": "1.95.0"},
            {"client": "npm", "id": "npm-node-minimum", "roles": ["minimum"], "runtime": "node", "runtimeVersion": "24.15.0", "version": "12.0.2"},
            {"client": "npm", "id": "npm-node-current", "roles": ["current"], "runtime": "node", "runtimeVersion": "26.7.0", "version": "12.0.2"},
            {"client": "bun", "id": "bun-minimum", "roles": ["minimum"], "runtime": null, "runtimeVersion": null, "version": "1.3.14"},
            {"client": "bun", "id": "bun-current", "roles": ["current"], "runtime": null, "runtimeVersion": null, "version": "1.4.0"},
            {"client": "deno", "id": "deno-minimum-current", "roles": ["minimum", "current"], "runtime": null, "runtimeVersion": null, "version": "2.9.5"}
        ])
    );
    let mut profile_ids = HashSet::new();
    for profile in fixture["clientProfiles"].as_array().unwrap() {
        exact_keys(
            profile,
            &[
                "client",
                "id",
                "roles",
                "runtime",
                "runtimeVersion",
                "version",
            ],
        );
        validate_id(profile, &mut profile_ids);
    }

    assert_eq!(
        fixture["policy"],
        json!({
            "approvedMetadataAuthorities": ["sparse+https://rust.pkg.re/", "https://js.pkg.re/"],
            "archiveDelivery": "integrity-bound redirects from canonical registry archive routes are allowed; redirect destinations never become metadata authorities",
            "cargo": {
                "cratesIoFallback": "replace crates-io with the committed empty project/.cargo/disabled-crates-io directory; never replace it with pkgre",
                "dependencyDeclaration": "every registry dependency explicitly sets registry = \"pkgre\" and an exact version",
                "registryAlias": "pkgre"
            },
            "configurationFiles": ["project/.cargo/config.toml", "project/.cargo/disabled-crates-io/.gitkeep", "project/.npmrc"],
            "javascript": {
                "allowedDependencySpecifier": "one exact canonical registry version",
                "deniedDependencySpecifiers": ["semver range", "dist-tag", "npm alias", "Git", "HTTP(S) URL", "file", "directory", "workspace", "JSR"],
                "deniedMetadataAuthorities": ["https://registry.npmjs.org/", "https://registry.yarnpkg.com/", "https://jsr.io/", "scope-specific registry override"],
                "lifecyclePolicy": "package lifecycle scripts are rejected during admission and disabled during npm installation",
                "lockPolicy": "committed lockfiles are required for frozen installs and warm-cache replay"
            },
            "npmConfiguration": "project/.npmrc options are normative for npm; only registry is assumed effective for Bun and Deno; all other behavior is D5 observation",
            "sourceEnforcement": "validate every declaration against sourceCases before invoking a package client; outbound isolation is defense in depth, not the primary denied-source boundary"
        })
    );
    assert_eq!(
        fixture["executionEnvelope"],
        json!({
            "forbiddenConfigurationFiles": ["bunfig.toml", "deno.json", "deno.jsonc"],
            "forbiddenOverrides": ["Cargo --config", "Cargo registry/source environment variables", "NPM_CONFIG_REGISTRY", "BUN_CONFIG_REGISTRY", "client command-line registry override", "parent, user, or global .npmrc"],
            "isolation": ["clean HOME", "clean XDG_CONFIG_HOME", "clean client cache", "outbound destination capture", "OS-enforced zero egress except the fixture registry when a scenario requires it"],
            "poisonedOverrideProbe": "each harness must prove a disallowed inherited override is detected or removed before client invocation"
        })
    );
    assert_eq!(
        fixture["clientOptionMatrix"],
        json!([
            {"client": "npm", "effectiveProjectOptions": ["allow-directory", "allow-file", "allow-git", "allow-remote", "audit", "fund", "ignore-scripts", "registry", "replace-registry-host", "save-exact", "strict-ssl", "update-notifier"], "observedOnlyOptions": []},
            {"client": "bun", "effectiveProjectOptions": ["registry"], "observedOnlyOptions": ["all other project .npmrc options"]},
            {"client": "deno", "effectiveProjectOptions": ["registry"], "observedOnlyOptions": ["all other project .npmrc options"]}
        ])
    );
    assert_eq!(
        fixture["cacheReplayModes"],
        json!([
            {"client": "cargo", "clientFlags": ["--frozen", "--offline"], "networkEnforcement": "client cache-only mode plus OS-enforced zero egress", "requireSuccess": true},
            {"client": "npm", "clientFlags": ["ci", "--offline"], "networkEnforcement": "client cache-only mode plus OS-enforced zero egress", "requireSuccess": true},
            {"client": "bun", "clientFlags": ["install", "--frozen-lockfile"], "networkEnforcement": "OS-enforced zero egress; pinned Bun versions have no reliable offline mode", "requireSuccess": true},
            {"client": "deno", "clientFlags": ["install", "--frozen", "--cached-only"], "networkEnforcement": "client cache-only mode plus OS-enforced zero egress", "requireSuccess": true}
        ])
    );
}

#[test]
fn denied_source_and_lifecycle_cases_are_closed_before_clients() {
    let fixture = fixture();
    let mut ids = HashSet::new();
    let expected = json!({
        "clientInvocation": "forbidden",
        "decision": "reject-before-client",
        "foreignNetworkRequests": 0,
        "gitProcesses": 0,
        "lifecycleSentinelCreated": false
    });
    let expected_kinds = BTreeSet::from([
        "directory",
        "dist-tag",
        "file",
        "foreign-registry",
        "git",
        "jsr",
        "npm-alias",
        "path",
        "remote-url",
        "semver-range",
        "workspace",
    ]);
    let mut kinds = BTreeSet::new();
    for record in fixture["sourceCases"].as_array().unwrap() {
        exact_keys(
            record,
            &[
                "clients",
                "declaration",
                "ecosystem",
                "expected",
                "id",
                "sourceKind",
            ],
        );
        validate_id(record, &mut ids);
        assert_eq!(record["expected"], expected);
        assert!(!source_allowed(record), "case {}", record["id"]);
        kinds.insert(record["sourceKind"].as_str().unwrap());
    }
    assert_eq!(kinds, expected_kinds);
    assert_eq!(fixture["sourceCases"].as_array().unwrap().len(), 13);

    let lifecycle = &fixture["lifecycleCases"][0];
    assert_eq!(fixture["lifecycleCases"].as_array().unwrap().len(), 1);
    exact_keys(lifecycle, &["clients", "declaration", "expected", "id"]);
    validate_id(lifecycle, &mut ids);
    assert_eq!(lifecycle["clients"], json!(["npm", "bun", "deno"]));
    assert_eq!(
        lifecycle["declaration"],
        json!({"field": "scripts.preinstall", "value": "touch pkgre-lifecycle-sentinel"})
    );
    assert_eq!(
        lifecycle["expected"],
        json!({
            "admission": "reject",
            "hostileClientFixture": "if admission is deliberately bypassed, disable lifecycle scripts and require zero sentinel execution",
            "lifecycleSentinelCreated": false
        })
    );
}

#[test]
fn profile_declarations_match_project_and_nix_pins() {
    let package: Value = serde_json::from_str(JS_PACKAGE).unwrap();
    assert_eq!(package["engines"]["node"], ">=24.15.0");
    assert_eq!(package["engines"]["npm"], ">=12.0.2");
    assert_eq!(package["packageManager"], "npm@12.0.2");
    for declaration in [
        "npmVersion = \"12.0.2\";",
        "nodeVersion = \"24.15.0\";",
        "nodeVersion = \"26.7.0\";",
        "version = \"1.3.14\";",
        "version = \"1.4.0\";",
        "version = \"2.9.5\";",
        "denoCurrent = denoMinimum;",
    ] {
        assert!(JS_CLIENTS_NIX.contains(declaration), "{declaration}");
    }
}
