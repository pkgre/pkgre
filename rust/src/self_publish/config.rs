//! Strict human-written `self-publish/crates-io.toml`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use semver::Version;
use serde::Deserialize;

use super::name;
use crate::policy::{validate_git_tag, validate_https_repository};

/// Supported `crates-io.toml` schema.
pub(crate) const CRATES_IO_CONFIG_SCHEMA: u32 = 1;

/// Maximum length of a GitHub login, in characters.
const MAX_OWNER_LOGIN_LENGTH: usize = 39;

/// The human self-publishing declarations of one catalog repository.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub(crate) struct CratesIoConfig {
    /// Wire schema.
    pub(crate) schema: u32,
    /// crates.io logins that must own every crate this workflow publishes.
    #[serde(default)]
    pub(crate) owners: Vec<String>,
    /// Self-publishing repositories, by the URL their publish declarations use.
    #[serde(default)]
    pub(crate) repositories: Vec<RepositoryDeclaration>,
    /// Optional crates.io names, keyed by the crate's `pkgre` name.
    #[serde(default)]
    pub(crate) names: BTreeMap<String, String>,
    /// Versions that will never reach crates.io.
    #[serde(default)]
    pub(crate) abandoned: Vec<AbandonedVersion>,
}

/// One self-publishing repository and its release-tag prefix.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub(crate) struct RepositoryDeclaration {
    /// Credential-free HTTPS Git repository.
    pub(crate) git: String,
    /// Prefix that turns a version into a release tag.
    pub(crate) tag_prefix: String,
    /// Registry for which the repository's release tags keep their manifests;
    /// absent means `pkgre`.
    #[serde(default)]
    pub(crate) manifests: Option<Manifests>,
}

/// The registry for which a self-publishing repository's release tags are written.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Manifests {
    /// Release tags carry manifests rewritten for the `pkgre` registry.
    #[default]
    Pkgre,
    /// Release tags keep plain crates.io manifests, and one archive serves both
    /// registries.
    CratesIo,
}

impl Manifests {
    /// Returns the value that `crates-io.toml` spells.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Pkgre => "pkgre",
            Self::CratesIo => "crates-io",
        }
    }
}

impl RepositoryDeclaration {
    /// Returns the registry for which the repository's release tags keep their
    /// manifests.
    pub(crate) fn manifests(&self) -> Manifests {
        self.manifests.unwrap_or_default()
    }
}

/// One release that crates.io never took.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct AbandonedVersion {
    /// Cargo package name, as `crates-io.lock` spells it.
    pub(crate) name: String,
    /// Exact Cargo version that was not published to crates.io.
    pub(crate) version: Version,
    /// Why crates.io did not take it.
    pub(crate) reason: String,
}

impl CratesIoConfig {
    /// Loads one regular human `crates-io.toml`.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing, unsafe, unreadable, malformed, or
    /// unsupported file, or an invalid declaration.
    pub(crate) fn load(path: &Path) -> Result<Self> {
        let metadata = fs::symlink_metadata(path)
            .with_context(|| format!("inspect self-publishing config {}", path.display()))?;
        ensure!(
            metadata.file_type().is_file(),
            "self-publishing config is not a regular file: {}",
            path.display()
        );
        let bytes = fs::read(path)
            .with_context(|| format!("read self-publishing config {}", path.display()))?;
        Self::parse(&bytes, path)
    }

    /// Parses and validates one `crates-io.toml`.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed or unsupported content, or an invalid
    /// declaration.
    pub(crate) fn parse(bytes: &[u8], path: &Path) -> Result<Self> {
        let config: Self = toml::from_slice(bytes)
            .with_context(|| format!("parse self-publishing config {}", path.display()))?;
        config
            .validate()
            .with_context(|| format!("validate self-publishing config {}", path.display()))?;
        Ok(config)
    }

    /// Returns the declaration of a self-publishing repository.
    ///
    /// Repositories are compared in their normalized form, so a URL that only
    /// differs in the host's case, a trailing `.git`, or, for GitHub, the path's
    /// case still finds its declaration; the checks then refuse the difference
    /// in spelling.
    pub(crate) fn repository(&self, git: &str) -> Option<&RepositoryDeclaration> {
        let normalized = normalized_git(git);
        self.repositories
            .iter()
            .find(|entry| normalized_git(&entry.git) == normalized)
    }

    /// Returns the release-tag prefix of a self-publishing repository.
    pub(crate) fn prefix_for(&self, git: &str) -> Option<&str> {
        self.repository(git).map(|entry| entry.tag_prefix.as_str())
    }

    /// Returns whether a repository's release tags keep crates.io manifests.
    pub(crate) fn is_native(&self, git: &str) -> bool {
        self.repository(git)
            .is_some_and(|entry| entry.manifests() == Manifests::CratesIo)
    }

    /// Returns the crates.io name of a crate of a self-publishing repository.
    ///
    /// A crate of a crates.io-native repository keeps its own name, since nothing
    /// rewrites its manifest; every other crate is mapped in `[names]`, or gets
    /// the default prefix.
    #[must_use]
    pub(crate) fn effective_name(&self, crate_name: &str, git: &str) -> String {
        if self.is_native(git) {
            return crate_name.to_owned();
        }
        self.names
            .get(crate_name)
            .cloned()
            .unwrap_or_else(|| name::default_name(crate_name))
    }

    /// Returns the record of one abandoned crate version.
    pub(crate) fn abandoned_version(
        &self,
        name: &str,
        version: &Version,
    ) -> Option<&AbandonedVersion> {
        self.abandoned
            .iter()
            .find(|record| record.name == name && record.version == *version)
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == CRATES_IO_CONFIG_SCHEMA,
            "self-publishing config schema must be {CRATES_IO_CONFIG_SCHEMA}, not {}",
            self.schema
        );
        ensure!(
            !self.owners.is_empty(),
            "self-publishing config must declare at least one crates.io owner"
        );
        let mut logins = BTreeSet::new();
        for login in &self.owners {
            validate_owner_login(login)?;
            ensure!(
                logins.insert(login.to_ascii_lowercase()),
                "self-publishing config names owner {login:?} twice"
            );
        }
        let mut repositories = BTreeSet::new();
        for repository in &self.repositories {
            validate_https_repository(&repository.git)
                .context("validate self-publishing repository")?;
            validate_tag_prefix(&repository.tag_prefix)
                .with_context(|| format!("validate tag-prefix of {:?}", repository.git))?;
            ensure!(
                repositories.insert(normalized_git(&repository.git)),
                "self-publishing config names repository {:?} twice, in two spellings",
                repository.git
            );
        }
        for crate_name in self.names.keys() {
            crate::policy::validate_package_name(crate_name)
                .with_context(|| format!("validate [names] key {crate_name:?}"))?;
        }
        let mut abandoned = BTreeSet::new();
        for record in &self.abandoned {
            crate::policy::validate_package_name(&record.name)
                .with_context(|| format!("validate abandoned record for {:?}", record.name))?;
            ensure!(
                !record.reason.trim().is_empty(),
                "abandoned record {} {} must give a reason",
                record.name,
                record.version
            );
            ensure!(
                !record.reason.chars().any(char::is_control),
                "abandoned record {} {} has a control character in its reason",
                record.name,
                record.version
            );
            ensure!(
                abandoned.insert((record.name.as_str(), record.version.clone())),
                "abandoned record {} {} is declared twice",
                record.name,
                record.version
            );
        }
        Ok(())
    }
}

/// Returns the comparison form of a Git repository URL.
///
/// The scheme and host are lowercased, a default `:443` port and empty or `.`
/// path segments are dropped, `..` segments are resolved, and a trailing `.git`
/// is removed, since they name the same repository; for GitHub the path is
/// lowercased too, since GitHub compares it case-insensitively. Every other
/// path component keeps its case, because other hosts may treat it as
/// significant.
#[must_use]
pub(crate) fn normalized_git(git: &str) -> String {
    let (scheme, rest) = git.split_once("://").unwrap_or(("", git));
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    let host = normalized_host(authority);
    let path = normalized_path(path);
    let path = if host == "github.com" {
        path.to_ascii_lowercase()
    } else {
        path
    };
    format!("{}://{host}/{path}", scheme.to_ascii_lowercase())
}

/// Lowercases a URL authority and drops the default HTTPS port.
fn normalized_host(authority: &str) -> String {
    let host = authority.to_ascii_lowercase();
    host.strip_suffix(":443").unwrap_or(&host).to_owned()
}

/// Normalizes a URL path: no empty or `.` segments, resolved `..` segments, no
/// trailing `.git`.
fn normalized_path(path: &str) -> String {
    let mut segments = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                if segments.pop().is_none() {
                    segments.push(segment);
                }
            }
            segment => segments.push(segment),
        }
    }
    if let Some(last) = segments.last_mut() {
        *last = strip_git_suffix(last);
    }
    segments.join("/")
}

/// Drops one trailing `.git`, in any case, from a URL path segment.
fn strip_git_suffix(segment: &str) -> &str {
    match segment.len().checked_sub(4) {
        Some(cut)
            if segment.is_char_boundary(cut) && segment[cut..].eq_ignore_ascii_case(".git") =>
        {
            &segment[..cut]
        }
        _ => segment,
    }
}

fn validate_owner_login(login: &str) -> Result<()> {
    ensure!(
        !login.is_empty() && login.chars().count() <= MAX_OWNER_LOGIN_LENGTH,
        "crates.io owner {login:?} must contain 1..={MAX_OWNER_LOGIN_LENGTH} characters"
    );
    ensure!(login.is_ascii(), "crates.io owner {login:?} must be ASCII");
    ensure!(
        login
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'),
        "crates.io owner {login:?} must be a GitHub login"
    );
    ensure!(
        login
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
            && login
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric),
        "crates.io owner {login:?} must start and end with an ASCII alphanumeric"
    );
    Ok(())
}

/// Validates a release-tag prefix.
///
/// The prefix is empty or `v`, or ends with `/` or `/v`, so that the tag's
/// final component is the version or `v` and the version, which is the
/// registry's own tag rule. Prefix and a version must also form a safe Git ref.
fn validate_tag_prefix(prefix: &str) -> Result<()> {
    ensure!(
        prefix.is_empty() || prefix == "v" || prefix.ends_with('/') || prefix.ends_with("/v"),
        "tag-prefix {prefix:?} must be empty, \"v\", or end with \"/\" or \"/v\""
    );
    validate_git_tag(&format!("{prefix}0.0.0"))
        .context("tag-prefix does not form a safe Git tag with a version")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"
schema = 1
owners = ["example-owner"]

[[repositories]]
git = "https://git.example.invalid/example/project"
tag-prefix = "rust/v"

[names]
example-lib = "example-lib"

[[abandoned]]
name = "example-lib"
version = "0.9.0"
reason = "crates.io refused the upload"
"#;

    fn path() -> &'static Path {
        Path::new("crates-io.toml")
    }

    #[test]
    fn a_valid_config_parses() {
        let config = CratesIoConfig::parse(VALID.as_bytes(), path()).unwrap();
        assert_eq!(config.schema, CRATES_IO_CONFIG_SCHEMA);
        assert_eq!(config.owners, ["example-owner"]);
        assert_eq!(
            config.prefix_for("https://git.example.invalid/example/project"),
            Some("rust/v")
        );
        assert_eq!(
            config.effective_name("example-lib", "https://git.example.invalid/example/project"),
            "example-lib"
        );
        assert_eq!(
            config.effective_name("example-bin", "https://git.example.invalid/example/project"),
            "pkgre-pkgs-example-bin"
        );
        assert!(
            config
                .abandoned_version("example-lib", &Version::parse("0.9.0").unwrap())
                .is_some()
        );
    }

    #[test]
    fn manifests_names_the_registry_of_a_repository_that_is_not_the_default() {
        const REPOSITORY: &str = "https://git.example.invalid/example/project";
        let native = |manifest: &str| {
            format!(
                "schema = 1\nowners = [\"example-owner\"]\n\n[[repositories]]\ngit = {REPOSITORY:?}\ntag-prefix = \"rust/v\"\nmanifests = {manifest}\n"
            )
        };
        let config = CratesIoConfig::parse(native("\"crates-io\"").as_bytes(), path()).unwrap();
        assert_eq!(
            config.repository(REPOSITORY).unwrap().manifests(),
            Manifests::CratesIo
        );
        assert!(config.is_native(REPOSITORY));
        // A native crate keeps its own name, whether or not `[names]` maps it.
        assert_eq!(
            config.effective_name("example-pkg", REPOSITORY),
            "example-pkg"
        );
        // Every repository that is not native keeps the mapping or the default.
        assert_eq!(
            config.effective_name("example-pkg", "https://git.example.invalid/other"),
            "pkgre-pkgs-example-pkg"
        );

        // The key is optional, and its absence means the `pkgre` mode.
        let config = CratesIoConfig::parse(VALID.as_bytes(), path()).unwrap();
        assert_eq!(
            config.repository(REPOSITORY).unwrap().manifests(),
            Manifests::Pkgre
        );
        assert!(!config.is_native(REPOSITORY));

        // No other value is a registry this workflow writes manifests for.
        for manifest in ["\"registry\"", "\"crates_io\"", "\"crates-io2\"", "true"] {
            let error = CratesIoConfig::parse(native(manifest).as_bytes(), path()).unwrap_err();
            let error = format!("{error:#}");
            assert!(
                error.contains("unknown variant")
                    || error.contains("invalid type")
                    || error.contains("wanted string"),
                "{manifest}: {error}"
            );
        }
    }

    #[test]
    fn unknown_fields_and_wrong_schemas_are_refused() {
        let unknown = "schema = 1\nowners = [\"example-owner\"]\nextra = true\n";
        let error = CratesIoConfig::parse(unknown.as_bytes(), path()).unwrap_err();
        let error = format!("{error:#}");
        assert!(error.contains("unknown field"), "{error}");

        let schema = "schema = 2\nowners = [\"example-owner\"]\n";
        let error = CratesIoConfig::parse(schema.as_bytes(), path()).unwrap_err();
        let error = format!("{error:#}");
        assert!(error.contains("schema must be 1"), "{error}");
    }

    #[test]
    fn invalid_declarations_are_refused() {
        for (text, expected) in [
            ("schema = 1\n", "at least one crates.io owner"),
            ("schema = 1\nowners = []\n", "at least one crates.io owner"),
            ("schema = 1\nowners = [\"-x\"]\n", "must start and end"),
            ("schema = 1\nowners = [\"Example\", \"example\"]\n", "twice"),
            (
                "schema = 1\nowners = [\"example\"]\n\n[[repositories]]\ngit = \"https://git.example.invalid/a\"\ntag-prefix = \"rust\"\n",
                "tag-prefix",
            ),
            (
                "schema = 1\nowners = [\"example\"]\n\n[[repositories]]\ngit = \"https://git.example.invalid/a\"\ntag-prefix = \"rust/v\"\n\n[[repositories]]\ngit = \"https://git.example.invalid/a\"\ntag-prefix = \"v\"\n",
                "twice",
            ),
            (
                "schema = 1\nowners = [\"example\"]\n\n[[repositories]]\ngit = \"https://git.example.invalid/a\"\ntag-prefix = \"rust/v\"\n\n[[repositories]]\ngit = \"https://GIT.example.invalid/a.git\"\ntag-prefix = \"v\"\n",
                "twice, in two spellings",
            ),
            (
                "schema = 1\nowners = [\"example\"]\n\n[[abandoned]]\nname = \"example\"\nversion = \"1.0.0\"\nreason = \" \"\n",
                "must give a reason",
            ),
            (
                "schema = 1\nowners = [\"example\"]\n\n[[abandoned]]\nname = \"example\"\nversion = \"1.0.0\"\nreason = \"a\"\n\n[[abandoned]]\nname = \"example\"\nversion = \"1.0.0\"\nreason = \"b\"\n",
                "declared twice",
            ),
        ] {
            let error = CratesIoConfig::parse(text.as_bytes(), path()).unwrap_err();
            let error = format!("{error:#}");
            assert!(error.contains(expected), "{expected:?} not in {error}");
        }
    }

    #[test]
    fn repository_urls_compare_in_normalized_form() {
        assert_eq!(
            normalized_git("https://Git.Example.Invalid/Owner/Repo.git"),
            "https://git.example.invalid/Owner/Repo"
        );
        assert_eq!(
            normalized_git("https://GitHub.com/Owner/Repo.git"),
            normalized_git("https://github.com/owner/repo")
        );
        assert_ne!(
            normalized_git("https://git.example.invalid/Owner/Repo"),
            normalized_git("https://git.example.invalid/owner/repo")
        );
        for spelling in [
            "https://git.example.invalid:443/example/project",
            "https://git.example.invalid//example/project",
            "https://git.example.invalid/example/./project",
            "https://git.example.invalid/example/other/../project",
        ] {
            assert_eq!(
                normalized_git(spelling),
                "https://git.example.invalid/example/project",
                "{spelling}"
            );
        }
        let config = CratesIoConfig::parse(
            "schema = 1\nowners = [\"example\"]\n\n[[repositories]]\ngit = \"https://git.example.invalid/Owner/Repo\"\ntag-prefix = \"rust/v\"\n"
                .as_bytes(),
            path(),
        )
        .unwrap();
        assert!(
            config
                .repository("https://GIT.example.invalid/Owner/Repo.git")
                .is_some()
        );
        assert!(
            config
                .repository("https://git.example.invalid/owner/repo")
                .is_none()
        );
    }

    #[test]
    fn every_accepted_tag_prefix_shape_forms_a_release_tag() {
        for prefix in ["", "v", "rust/", "rust/v"] {
            validate_tag_prefix(prefix).unwrap();
        }
        for prefix in ["rust", "vv", "/", "rust//", "-rust/v"] {
            assert!(validate_tag_prefix(prefix).is_err(), "{prefix:?}");
        }
        // A trailing slash after `v` is still a prefix whose tag ends in the version.
        validate_tag_prefix("v/").unwrap();
    }
}
