//! Accepted-to-candidate semantic transition validation for serving catalog updates.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use semver::Version;

use crate::download::DownloadCatalog;
use crate::schema::{Approval, Catalog, PackageState, Source};

/// Catalog-relative directory holding immutable admission manifest/lock pairs.
const ADMISSIONS_DIRECTORY: &str = "admissions";

/// Exact semantic reason one candidate catalog must be rejected as an accepted successor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RejectReason {
    /// A candidate registry declaration changed topology relevant to serving.
    RegistryTopology(String),
    /// A package identity disappeared from the candidate locks.
    MissingIdentity(String),
    /// An accepted identity changed immutable archive, source, or admission evidence.
    MutatedIdentity(String),
    /// An accepted package identity, `registry/name/version`, changed its category.
    CategoryMove(String),
    /// A retained body object is missing or does not match its content hash.
    MissingRetainedBody(String),
    /// An accepted admission manifest or generated lock is missing or differs in the candidate.
    MutatedAdmissionFile(String),
    /// An admission manifest or generated lock could not be inspected, named, or read.
    AdmissionEvidenceUnreadable(String),
    /// A crates.io identity that is new since the accepted catalog has no admission binding.
    MissingAdmissionEvidence(String),
    /// An admission binding does not name an admission batch new in the candidate.
    AdmissionBatchNotNew(String),
    /// An accepted category disappeared or changed its `may-depend-on` rule.
    CategoryRuleChanged(String),
    /// An accepted package name's permanent home, `registry/name`, changed category; this covers
    /// names with and without versions, while [`RejectReason::CategoryMove`] covers one identity.
    HomeMoved(String),
    /// An accepted package name disappeared from the candidate.
    MissingHome(String),
}

impl fmt::Display for RejectReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RegistryTopology(detail) => {
                write!(formatter, "registry topology changed: {detail}")
            }
            Self::MissingIdentity(identity) => {
                write!(formatter, "identity disappeared: {identity}")
            }
            Self::MutatedIdentity(identity) => {
                write!(formatter, "identity mutated: {identity}")
            }
            Self::CategoryMove(identity) => {
                write!(formatter, "identity changed category: {identity}")
            }
            Self::MissingRetainedBody(detail) => {
                write!(formatter, "retained body missing: {detail}")
            }
            Self::MutatedAdmissionFile(detail) => {
                write!(formatter, "admission evidence changed: {detail}")
            }
            Self::AdmissionEvidenceUnreadable(detail) => {
                write!(formatter, "admission evidence unreadable: {detail}")
            }
            Self::MissingAdmissionEvidence(identity) => {
                write!(formatter, "identity has no admission evidence: {identity}")
            }
            Self::AdmissionBatchNotNew(detail) => {
                write!(formatter, "admission batch is not new: {detail}")
            }
            Self::CategoryRuleChanged(detail) => {
                write!(formatter, "category rule changed: {detail}")
            }
            Self::HomeMoved(detail) => {
                write!(formatter, "package home moved: {detail}")
            }
            Self::MissingHome(name) => {
                write!(formatter, "package home disappeared: {name}")
            }
        }
    }
}

/// Validates that `candidate` is a legal serving successor of `accepted`.
///
/// Both catalogs must strictly load as schema 5. Registry serving topology must be identical,
/// every accepted admission manifest/lock pair must stay byte-identical, every accepted identity
/// must be retained with immutable evidence including its admission binding, every crates.io
/// identity new since the accepted catalog must be bound to an admission batch that is new in the
/// candidate, accepted category rules and package-name homes must not move or disappear, and every
/// retained body must be present with a matching SHA-256.
///
/// # Errors
///
/// Returns the first [`RejectReason`] violated by the candidate, or a load/validation error.
pub fn check_transition(accepted_root: &Path, candidate_root: &Path) -> Result<(), RejectReason> {
    let accepted =
        Catalog::load(accepted_root).map_err(|error| RejectReason::load("accepted", &error))?;
    crate::policy::validate_catalog(&accepted)
        .map_err(|error| RejectReason::load("accepted", &error))?;
    let candidate =
        Catalog::load(candidate_root).map_err(|error| RejectReason::load("candidate", &error))?;
    crate::policy::validate_catalog(&candidate)
        .map_err(|error| RejectReason::load("candidate", &error))?;

    for accepted_registry in &accepted.registries.registries {
        let candidate_registry = candidate
            .registries
            .registries
            .iter()
            .find(|registry| registry.name == accepted_registry.name)
            .ok_or_else(|| {
                RejectReason::RegistryTopology(format!(
                    "registry {:?} disappeared",
                    accepted_registry.name
                ))
            })?;
        ensure_topology(accepted_registry, candidate_registry)?;
    }
    for candidate_registry in &candidate.registries.registries {
        if !accepted
            .registries
            .registries
            .iter()
            .any(|registry| registry.name == candidate_registry.name)
        {
            return Err(RejectReason::RegistryTopology(format!(
                "registry {:?} appeared",
                candidate_registry.name
            )));
        }
    }

    let accepted_admissions = admission_files(accepted_root, "accepted")?;
    let candidate_admissions = admission_files(candidate_root, "candidate")?;
    verify_admission_files(&accepted_admissions, &candidate_admissions)?;

    verify_identities(&accepted, &candidate)?;
    verify_new_admission_bindings(
        &accepted,
        &candidate,
        &batch_digests(&accepted_admissions),
        &batch_digests(&candidate_admissions),
    )?;
    verify_category_rules(&accepted, &candidate)?;
    verify_package_homes(&accepted, &candidate)?;

    verify_retained_bodies(&candidate)
        .map_err(|error| RejectReason::MissingRetainedBody(format!("{error:#}")))?;
    Ok(())
}

impl RejectReason {
    fn load(which: &str, error: &anyhow::Error) -> Self {
        Self::MissingRetainedBody(format!("{which} catalog failed to load: {error:#}"))
    }
}

fn ensure_topology(
    accepted: &crate::schema::Registry,
    candidate: &crate::schema::Registry,
) -> Result<(), RejectReason> {
    let detail = if accepted.name != candidate.name {
        Some(format!(
            "name {:?} became {:?}",
            accepted.name, candidate.name
        ))
    } else if accepted.index != candidate.index {
        Some(format!(
            "registry {:?} index {:?} became {:?}",
            accepted.name, accepted.index, candidate.index
        ))
    } else if accepted.download != candidate.download
        && !crate::schema::is_allowed_download_migration(
            &accepted.name,
            &accepted.download,
            &candidate.download,
        )
    {
        Some(format!(
            "registry {:?} download {:?} became {:?}",
            accepted.name, accepted.download, candidate.download
        ))
    } else if accepted.audience != candidate.audience {
        Some(format!(
            "registry {:?} audience {:?} became {:?}",
            accepted.name, accepted.audience, candidate.audience
        ))
    } else if accepted.cargo_version != candidate.cargo_version {
        Some(format!(
            "registry {:?} cargo-version {:?} became {:?}",
            accepted.name, accepted.cargo_version, candidate.cargo_version
        ))
    } else {
        None
    };
    detail.map_or(Ok(()), |detail| Err(RejectReason::RegistryTopology(detail)))
}

fn identity_key(approval: &Approval) -> (String, String, Version) {
    (
        approval.registry.clone(),
        approval.name.clone(),
        approval.version.clone(),
    )
}

fn identity_name(approval: &Approval) -> String {
    format!(
        "{}/{}/{}",
        approval.registry, approval.name, approval.version
    )
}

fn verify_identities(accepted: &Catalog, candidate: &Catalog) -> Result<(), RejectReason> {
    let candidate_index = candidate
        .approvals
        .iter()
        .map(|approval| (identity_key(approval), approval))
        .collect::<BTreeMap<_, _>>();
    for accepted_approval in &accepted.approvals {
        let identity = identity_key(accepted_approval);
        let candidate_approval = candidate_index
            .get(&identity)
            .ok_or_else(|| RejectReason::MissingIdentity(identity_name(accepted_approval)))?;
        if accepted_approval.archive_sha256 != candidate_approval.archive_sha256
            || accepted_approval.index_record_sha256 != candidate_approval.index_record_sha256
            || accepted_approval.index_row_sha256 != candidate_approval.index_row_sha256
            || accepted_approval.admission_sha256 != candidate_approval.admission_sha256
            || accepted_approval.admitted_at != candidate_approval.admitted_at
            || accepted_approval.state != candidate_approval.state
            || accepted_approval.source != candidate_approval.source
        {
            return Err(RejectReason::MutatedIdentity(identity_name(
                accepted_approval,
            )));
        }
        if accepted_approval.category != candidate_approval.category {
            return Err(RejectReason::CategoryMove(identity_name(accepted_approval)));
        }
    }
    Ok(())
}

/// Returns every admission manifest and generated lock name with its complete-content SHA-256.
///
/// `side` names the catalog in diagnostics. Each entry is inspected without following links, so a
/// link swapped in after load is never read through. A failure to inspect, name, or read an entry
/// is reported as unreadable evidence, because it is not a change the candidate made.
fn admission_files(root: &Path, side: &str) -> Result<BTreeMap<String, String>, RejectReason> {
    let directory = root.join(ADMISSIONS_DIRECTORY);
    let mut files = BTreeMap::new();
    let entries = match fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(files),
        Err(error) => {
            return Err(RejectReason::AdmissionEvidenceUnreadable(format!(
                "{side}: inspect admission directory {}: {error}",
                directory.display()
            )));
        }
    };
    for entry in entries {
        let path = entry
            .map_err(|error| {
                RejectReason::AdmissionEvidenceUnreadable(format!(
                    "{side}: read admission directory {}: {error}",
                    directory.display()
                ))
            })?
            .path();
        let name = path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| {
                RejectReason::AdmissionEvidenceUnreadable(format!(
                    "{side}: admission filename is not valid UTF-8: {}",
                    path.display()
                ))
            })?
            .to_owned();
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            RejectReason::AdmissionEvidenceUnreadable(format!(
                "{side}: inspect admission file {}: {error}",
                path.display()
            ))
        })?;
        if !metadata.file_type().is_file() {
            return Err(RejectReason::MutatedAdmissionFile(format!(
                "{ADMISSIONS_DIRECTORY}/{name} is not a regular file"
            )));
        }
        let bytes = fs::read(&path).map_err(|error| {
            RejectReason::AdmissionEvidenceUnreadable(format!(
                "{side}: read admission file {}: {error}",
                path.display()
            ))
        })?;
        files.insert(name, crate::artifact::sha256_bytes(&bytes));
    }
    Ok(files)
}

fn batch_digests(files: &BTreeMap<String, String>) -> BTreeSet<String> {
    files
        .iter()
        .filter(|(name, _)| {
            Path::new(name)
                .extension()
                .is_some_and(|value| value == "lock")
        })
        .map(|(_, digest)| digest.clone())
        .collect()
}

fn verify_admission_files(
    accepted: &BTreeMap<String, String>,
    candidate: &BTreeMap<String, String>,
) -> Result<(), RejectReason> {
    for (name, digest) in accepted {
        match candidate.get(name) {
            None => {
                return Err(RejectReason::MutatedAdmissionFile(format!(
                    "{ADMISSIONS_DIRECTORY}/{name} disappeared"
                )));
            }
            Some(current) if current != digest => {
                return Err(RejectReason::MutatedAdmissionFile(format!(
                    "{ADMISSIONS_DIRECTORY}/{name} changed"
                )));
            }
            Some(_) => {}
        }
    }
    Ok(())
}

/// Requires every crates.io identity new since the accepted catalog to carry a fresh batch.
///
/// Git-tag identities have no admission evidence, and historical/bootstrap mirrors that the
/// accepted catalog already carries keep the exact binding they had, present or absent.
fn verify_new_admission_bindings(
    accepted: &Catalog,
    candidate: &Catalog,
    accepted_batches: &BTreeSet<String>,
    candidate_batches: &BTreeSet<String>,
) -> Result<(), RejectReason> {
    let accepted_identities = accepted
        .approvals
        .iter()
        .map(identity_key)
        .collect::<BTreeSet<_>>();
    for approval in &candidate.approvals {
        if accepted_identities.contains(&identity_key(approval))
            || !matches!(approval.source, Source::CratesIo)
        {
            continue;
        }
        let name = identity_name(approval);
        let Some(binding) = approval.admission_sha256.as_deref() else {
            return Err(RejectReason::MissingAdmissionEvidence(name));
        };
        if !candidate_batches.contains(binding) {
            return Err(RejectReason::AdmissionBatchNotNew(format!(
                "{name} is bound to admission batch {binding}, which the candidate catalog does not contain"
            )));
        }
        if accepted_batches.contains(binding) {
            return Err(RejectReason::AdmissionBatchNotNew(format!(
                "{name} is bound to admission batch {binding}, which the accepted catalog already contains"
            )));
        }
    }
    Ok(())
}

fn verify_category_rules(accepted: &Catalog, candidate: &Catalog) -> Result<(), RejectReason> {
    for (category, dependencies) in &accepted.categories {
        let Some(current) = candidate.categories.get(category) else {
            return Err(RejectReason::CategoryRuleChanged(format!(
                "category {category} disappeared"
            )));
        };
        let before = dependencies.iter().collect::<BTreeSet<_>>();
        let after = current.iter().collect::<BTreeSet<_>>();
        if before != after {
            return Err(RejectReason::CategoryRuleChanged(format!(
                "category {category} may-depend-on [{}] became [{}]",
                rule_text(dependencies),
                rule_text(current)
            )));
        }
    }
    Ok(())
}

fn rule_text(dependencies: &[crate::category::CategoryId]) -> String {
    dependencies
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn verify_package_homes(accepted: &Catalog, candidate: &Catalog) -> Result<(), RejectReason> {
    for (key, home) in &accepted.homes.homes {
        let name = format!("{}/{}", key.registry, key.name);
        let Some(current) = candidate.homes.get(&key.registry, &key.name) else {
            return Err(RejectReason::MissingHome(name));
        };
        if current.category != home.category {
            return Err(RejectReason::HomeMoved(format!(
                "{name} left {} for {}",
                home.category, current.category
            )));
        }
    }
    Ok(())
}

fn verify_retained_bodies(catalog: &Catalog) -> Result<()> {
    let retained_identities = DownloadCatalog::retained_route_identities(catalog);
    for approval in &catalog.approvals {
        if approval.state != PackageState::Active {
            continue;
        }
        if !retained_identities.contains(&identity_key(approval)) {
            continue;
        }
        let path = catalog
            .root
            .join("objects")
            .join("crates")
            .join(format!("{}.crate", approval.archive_sha256));
        let metadata = std::fs::symlink_metadata(&path)
            .with_context(|| format!("inspect retained body {}", path.display()))?;
        ensure!(
            metadata.file_type().is_file(),
            "retained body is not a regular file: {}",
            path.display()
        );
        let bytes = std::fs::read(&path)
            .with_context(|| format!("read retained body {}", path.display()))?;
        ensure!(
            crate::artifact::sha256_bytes(&bytes) == approval.archive_sha256,
            "retained body hash mismatch for {} {}",
            approval.name,
            approval.version
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::download::{DownloadCatalog, router_download_template};
    use crate::schema::{
        Audience, LockedName, LockedPackage, LockedRegistry, LockedSource, RegistryLock,
        SCHEMA_VERSION, serialize_lock,
    };
    use crate::update::{
        ADMISSION_MANIFEST_SCHEMA, AdmissionManifest, AdmissionRequest, ArchiveSummary,
        DORMANT_RELEASE_GAP_DAYS, DecisionReason, DependencyDelta, MIN_RELEASE_AGE_DAYS,
        PackageActivity, PlannedIdentity, SourceEvidence, UPDATE_PLAN_SCHEMA, UpdateCandidate,
        UpdateDecision, UpdatePlan, UtcTimestamp, prepare_admission_lock, write_admission_pair,
    };

    const MAIN: &str = "main";
    const MAIN_INDEX: &str = "sparse+https://rust.pkg.re/";
    const CARGO_VERSION: &str = "1.95.0";
    /// Deterministic fixture times: evidence, admission, and one day apart of publication.
    const EVALUATED_AT: &str = "2025-02-01T00:00:00Z";
    const ADMITTED_AT: &str = "2025-02-01T02:00:00Z";
    const PUBLISHED_AT: &str = "2025-01-02T00:00:00Z";

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    /// Complete generated catalogs that only differ from the standard accepted state on purpose.
    struct Fixture {
        root: PathBuf,
        rules: BTreeMap<&'static str, Vec<&'static str>>,
        mirrors: BTreeMap<&'static str, BTreeMap<&'static str, Vec<&'static str>>>,
        publishes: BTreeMap<&'static str, Vec<(&'static str, Vec<&'static str>)>>,
        packages: Vec<LockedPackage>,
    }

    impl Fixture {
        /// Standard accepted state: one admitted mirror, one reserved mirror name, one reserved
        /// Git-publish name, and one spare category that only holds a reserved name.
        fn new(label: &str) -> Self {
            let mut fixture = Self {
                root: temporary_directory(label),
                rules: BTreeMap::from([
                    ("extra", vec!["extra", "general"]),
                    ("general", vec!["general"]),
                    ("pkgre", vec!["general", "pkgre"]),
                ]),
                mirrors: BTreeMap::from([
                    ("extra", BTreeMap::from([("extra", Vec::new())])),
                    ("general", BTreeMap::from([("warp", Vec::new())])),
                    ("pkgre", BTreeMap::new()),
                ]),
                publishes: BTreeMap::from([
                    ("extra", Vec::new()),
                    ("general", Vec::new()),
                    ("pkgre", vec![("demo-tool", Vec::new())]),
                ]),
                packages: Vec::new(),
            };
            let demo = fixture.add_crates_io("general", "demo", "1.0.0");
            fixture.admit("2025-02-01-demo", ADMITTED_AT, &[(demo, "general")]);
            fixture
        }

        /// The same state, except that the mirror identity carries no admission evidence.
        fn without_admission(label: &str) -> Self {
            let mut fixture = Self::new(label);
            fs::remove_dir_all(fixture.root.join(ADMISSIONS_DIRECTORY)).unwrap();
            fixture.packages[0].admission_sha256 = None;
            fixture
        }

        fn root(&self) -> &Path {
            &self.root
        }

        fn add_crates_io(
            &mut self,
            category: &'static str,
            name: &'static str,
            version: &'static str,
        ) -> usize {
            self.mirrors
                .get_mut(category)
                .expect("fixture category exists")
                .entry(name)
                .or_default()
                .push(version);
            self.packages.push(LockedPackage {
                name: name.to_owned(),
                version: Version::parse(version).unwrap(),
                state: PackageState::Active,
                crate_sha256: archive_sha256(name, version),
                source_row_sha256: source_row_sha256(name, version),
                index_row_sha256: index_row_sha256(name, version),
                admission_sha256: None,
                admitted_at: UtcTimestamp::parse(PUBLISHED_AT).unwrap(),
                source: LockedSource::CratesIo {},
            });
            self.packages.len() - 1
        }

        fn reserve(&mut self, category: &'static str, name: &'static str) {
            self.mirrors
                .get_mut(category)
                .expect("fixture category exists")
                .entry(name)
                .or_default();
        }

        fn add_git_tag(
            &mut self,
            category: &'static str,
            name: &'static str,
            version: &'static str,
            tag: &'static str,
        ) {
            let tags = &mut self
                .publishes
                .get_mut(category)
                .expect("fixture category exists")
                .iter_mut()
                .find(|(declared, _)| *declared == name)
                .expect("fixture publish name is declared")
                .1;
            tags.push(tag);
            let body = format!("fixture archive {name} {version}");
            let archive_sha256 = crate::artifact::sha256_bytes(body.as_bytes());
            let objects = self.root.join("objects/crates");
            fs::create_dir_all(&objects).unwrap();
            fs::write(objects.join(format!("{archive_sha256}.crate")), body).unwrap();
            self.packages.push(LockedPackage {
                name: name.to_owned(),
                version: Version::parse(version).unwrap(),
                state: PackageState::Active,
                crate_sha256: archive_sha256,
                source_row_sha256: source_row_sha256(name, version),
                index_row_sha256: index_row_sha256(name, version),
                admission_sha256: None,
                admitted_at: UtcTimestamp::parse(PUBLISHED_AT).unwrap(),
                source: LockedSource::GitTag {
                    git: "https://github.com/pkgre/pkgre".to_owned(),
                    tag: tag.to_owned(),
                    tag_oid: "1".repeat(40),
                    commit: "2".repeat(40),
                    package: name.to_owned(),
                    path: PathBuf::from("."),
                    cargo_version: Version::parse(CARGO_VERSION).unwrap(),
                },
            });
        }

        /// Writes one generated admission pair covering the given packages and binds them to it.
        fn admit(&mut self, stem: &str, admitted_at: &str, members: &[(usize, &'static str)]) {
            let specs = members
                .iter()
                .map(|(index, local)| (self.packages[*index].clone(), *local))
                .collect::<Vec<_>>();
            let borrows = specs
                .iter()
                .map(|(package, local)| (package, *local))
                .collect::<Vec<_>>();
            let binding = write_batch(&self.root, stem, admitted_at, &borrows);
            for (index, _) in members {
                self.packages[*index].admission_sha256 = Some(binding.clone());
            }
        }

        fn rule(&mut self, category: &'static str, dependencies: &[&'static str]) {
            *self
                .rules
                .get_mut(category)
                .expect("fixture category exists") = dependencies.to_vec();
        }

        fn move_name(&mut self, name: &'static str, from: &'static str, to: &'static str) {
            self.mirrors
                .get_mut(from)
                .expect("fixture category exists")
                .remove(name)
                .expect("fixture reserved name exists");
            self.mirrors
                .get_mut(to)
                .expect("fixture category exists")
                .entry(name)
                .or_default();
        }

        fn remove_name(&mut self, name: &'static str, category: &'static str) {
            self.mirrors
                .get_mut(category)
                .expect("fixture category exists")
                .remove(name)
                .expect("fixture reserved name exists");
        }

        /// Drops one category after its names moved elsewhere, as a shrinking declaration would.
        fn remove_category(&mut self, category: &'static str) {
            self.rules
                .remove(category)
                .expect("fixture category exists");
            self.mirrors
                .remove(category)
                .expect("fixture category exists");
            self.publishes
                .remove(category)
                .expect("fixture category exists");
        }

        fn write(&self) {
            fs::write(self.root.join("main.toml"), self.registry_toml()).unwrap();
            let lock = serialize_lock(&self.lock()).unwrap();
            fs::write(self.root.join("main.lock"), lock).unwrap();
            let inputs = crate::schema::load_registry_inputs(&self.root).unwrap();
            let catalog = crate::schema::catalog_from_inputs(&self.root, &inputs).unwrap();
            let downloads = DownloadCatalog::from_catalog(&catalog)
                .canonical_bytes()
                .unwrap();
            fs::write(self.root.join("downloads.json"), downloads).unwrap();
        }

        fn registry_toml(&self) -> String {
            use std::fmt::Write as _;

            let mut text = format!(
                "schema = 5\n\n[registry]\nname = {MAIN:?}\nindex = {MAIN_INDEX:?}\ndownload = {download:?}\ncargo-version = {CARGO_VERSION:?}\naudience = \"public\"\n",
                download = Self::download(),
            );
            for (local, dependencies) in &self.rules {
                let rule = dependencies
                    .iter()
                    .map(|dependency| format!("\"main/{dependency}\""))
                    .collect::<Vec<_>>()
                    .join(", ");
                writeln!(text, "\n[categories.{local}]\nmay-depend-on = [{rule}]").unwrap();
                if let Some(mirrors) = self.mirrors.get(local).filter(|value| !value.is_empty()) {
                    writeln!(text, "\n[categories.{local}.mirror]").unwrap();
                    for (name, versions) in mirrors {
                        let versions = versions
                            .iter()
                            .map(|version| format!("\"{version}\""))
                            .collect::<Vec<_>>()
                            .join(", ");
                        writeln!(text, "{name} = [{versions}]").unwrap();
                    }
                }
                if let Some(publishes) = self.publishes.get(local) {
                    for (name, tags) in publishes {
                        let tags = tags
                            .iter()
                            .map(|tag| format!("\"{tag}\""))
                            .collect::<Vec<_>>()
                            .join(", ");
                        writeln!(
                            text,
                            "\n[categories.{local}.publish.{name}]\ngit = \"https://github.com/pkgre/pkgre\"\ntags = [{tags}]"
                        )
                        .unwrap();
                    }
                }
            }
            text
        }

        fn download() -> String {
            router_download_template(MAIN)
        }

        fn lock(&self) -> RegistryLock {
            let mut names = Vec::new();
            for (local, mirrors) in &self.mirrors {
                for name in mirrors.keys() {
                    names.push(LockedName {
                        name: (*name).to_owned(),
                        category: (*local).to_owned(),
                    });
                }
            }
            for (local, publishes) in &self.publishes {
                for (name, _) in publishes {
                    names.push(LockedName {
                        name: (*name).to_owned(),
                        category: (*local).to_owned(),
                    });
                }
            }
            RegistryLock {
                schema: SCHEMA_VERSION,
                registry: LockedRegistry {
                    name: MAIN.to_owned(),
                    index: MAIN_INDEX.to_owned(),
                    download: Self::download(),
                    audience: Audience::Public,
                },
                names,
                packages: self.packages.clone(),
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn write_batch(
        root: &Path,
        stem: &str,
        admitted_at: &str,
        members: &[(&LockedPackage, &'static str)],
    ) -> String {
        let mut members = members.to_vec();
        members.sort_by(|(left, _), (right, _)| {
            (left.name.to_ascii_lowercase(), left.name.as_str())
                .cmp(&(right.name.to_ascii_lowercase(), right.name.as_str()))
        });
        let manifest = AdmissionManifest {
            schema: ADMISSION_MANIFEST_SCHEMA,
            entries: members
                .iter()
                .map(|(package, local)| AdmissionRequest {
                    category: format!("main/{local}").parse().unwrap(),
                    name: package.name.clone(),
                    version: Some(package.version.clone()),
                    tag: None,
                    evidence: Vec::new(),
                })
                .collect(),
        };
        let plan = UpdatePlan {
            schema: UPDATE_PLAN_SCHEMA,
            indexer_version: env!("CARGO_PKG_VERSION").to_owned(),
            catalog_sha256: "07".repeat(32),
            evaluated_at: UtcTimestamp::parse(EVALUATED_AT).unwrap(),
            min_release_age_days: MIN_RELEASE_AGE_DAYS,
            dormant_release_gap_days: DORMANT_RELEASE_GAP_DAYS,
            candidates: members
                .iter()
                .map(|(package, local)| plan_candidate(package, local))
                .collect(),
        };
        let manifest_bytes = crate::update::serialize_admission_manifest(&manifest).unwrap();
        let (lock_bytes, binding) =
            prepare_admission_lock(&manifest, &plan, &UtcTimestamp::parse(admitted_at).unwrap())
                .unwrap();
        write_admission_pair(
            root,
            Path::new(&format!("{stem}.toml")),
            &manifest_bytes,
            &lock_bytes,
        )
        .unwrap();
        binding
    }

    fn plan_candidate(package: &LockedPackage, local: &str) -> UpdateCandidate {
        UpdateCandidate {
            registry: MAIN.to_owned(),
            category: format!("main/{local}"),
            name: package.name.clone(),
            activity: PackageActivity::New,
            lane: None,
            base: None,
            candidate: PlannedIdentity {
                version: package.version.clone(),
                published_at: UtcTimestamp::parse(PUBLISHED_AT).unwrap(),
                source_row_sha256: package.source_row_sha256.clone(),
                crate_sha256: package.crate_sha256.clone(),
            },
            sparse_index_sha256: "03".repeat(32),
            decision_history_sha256: "04".repeat(32),
            age_seconds: 30 * 24 * 60 * 60,
            dormant_gap: None,
            base_archive: None,
            candidate_archive: ArchiveSummary {
                analysis_sha256: "05".repeat(32),
                compressed_bytes: 1,
                unpacked_bytes: 1,
                files: 1,
                build_surface: BTreeMap::new(),
                vcs_commit: None,
                vcs_path: None,
            },
            archive_delta: None,
            dependencies: DependencyDelta {
                added: Vec::new(),
                removed: Vec::new(),
                new_packages: Vec::new(),
            },
            api: None,
            source: SourceEvidence::Unavailable {
                reason: "source-verification-error".to_owned(),
            },
            decision: UpdateDecision::ReviewRequired,
            reasons: vec![
                DecisionReason::NewPackage,
                DecisionReason::SourceUnavailable,
                DecisionReason::ExplicitCandidate,
            ],
        }
    }

    fn archive_sha256(name: &str, version: &str) -> String {
        crate::artifact::sha256_bytes(format!("fixture archive {name} {version}").as_bytes())
    }

    fn source_row_sha256(name: &str, version: &str) -> String {
        crate::artifact::sha256_bytes(format!("fixture row {name} {version}").as_bytes())
    }

    fn index_row_sha256(name: &str, version: &str) -> String {
        crate::artifact::sha256_bytes(format!("fixture index {name} {version}").as_bytes())
    }

    fn temporary_directory(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "pkgre-transition-{name}-{}-{}",
            std::process::id(),
            TEST_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn accepts_identical_additive_mirror_reserved_and_git_candidates() {
        let accepted = Fixture::new("accepted");
        accepted.write();
        let identical = Fixture::new("identical");
        identical.write();
        check_transition(accepted.root(), identical.root()).expect("identical catalog must pass");

        let mut additive = Fixture::new("additive");
        let added = additive.add_crates_io("general", "added", "1.0.0");
        additive.admit(
            "2025-02-02-added",
            "2025-02-02T02:00:00Z",
            &[(added, "general")],
        );
        additive.reserve("general", "later");
        additive.add_git_tag("pkgre", "demo-tool", "0.1.0", "tool/v0.1.0");
        additive.write();
        check_transition(accepted.root(), additive.root())
            .expect("additions bound by a new batch must pass");
    }

    #[test]
    fn accepts_an_unbound_accepted_mirror_beside_a_new_bound_mirror() {
        let accepted = Fixture::without_admission("unbound-accepted");
        accepted.write();
        let mut candidate = Fixture::without_admission("unbound-candidate");
        let added = candidate.add_crates_io("general", "added", "1.0.0");
        candidate.admit(
            "2025-02-02-added",
            "2025-02-02T02:00:00Z",
            &[(added, "general")],
        );
        candidate.write();
        check_transition(accepted.root(), candidate.root())
            .expect("an accepted unbound mirror must stay unbound while a new mirror is bound");
    }

    #[test]
    fn rejects_new_mirror_without_admission_evidence() {
        let accepted = Fixture::new("missing-evidence-accepted");
        accepted.write();
        let mut candidate = Fixture::new("missing-evidence-candidate");
        candidate.add_crates_io("general", "added", "1.0.0");
        candidate.write();
        assert_eq!(
            check_transition(accepted.root(), candidate.root()),
            Err(RejectReason::MissingAdmissionEvidence(
                "main/added/1.0.0".to_owned()
            ))
        );
    }

    #[test]
    fn rejects_new_mirror_bound_to_an_accepted_batch() {
        let accepted = Fixture::new("reused-batch-accepted");
        accepted.write();
        let mut candidate = Fixture::new("reused-batch-candidate");
        let added = candidate.add_crates_io("general", "added", "1.0.0");
        candidate.admit(
            "2025-02-02-added",
            "2025-02-02T02:00:00Z",
            &[(added, "general")],
        );
        candidate.write();

        // A loadable tree cannot reach this rule: load requires one exact manifest/lock pair per
        // admission-bound identity, so a batch that already covers an accepted identity cannot
        // also cover a new one. Bind the new identity to the accepted batch directly instead.
        let accepted_catalog = Catalog::load(accepted.root()).unwrap();
        let mut candidate_catalog = Catalog::load(candidate.root()).unwrap();
        let accepted_batches =
            batch_digests(&admission_files(accepted.root(), "accepted").unwrap());
        let candidate_batches =
            batch_digests(&admission_files(candidate.root(), "candidate").unwrap());
        let accepted_binding = accepted_catalog
            .approvals
            .iter()
            .find(|approval| approval.name == "demo")
            .and_then(|approval| approval.admission_sha256.clone())
            .expect("accepted fixture binds its mirror identity");
        for approval in &mut candidate_catalog.approvals {
            if approval.name == "added" {
                approval.admission_sha256 = Some(accepted_binding.clone());
            }
        }
        let reason = verify_new_admission_bindings(
            &accepted_catalog,
            &candidate_catalog,
            &accepted_batches,
            &candidate_batches,
        )
        .unwrap_err();
        assert!(
            matches!(
                &reason,
                RejectReason::AdmissionBatchNotNew(detail) if detail.contains("already contains")
            ),
            "expected a reused accepted batch, got {reason:?}"
        );
    }

    #[test]
    fn rejects_removed_and_rewritten_admission_evidence() {
        let accepted = Fixture::new("mutated-evidence-accepted");
        accepted.write();

        let removed = Fixture::without_admission("mutated-evidence-removed");
        removed.write();
        let reason = check_transition(accepted.root(), removed.root()).unwrap_err();
        assert!(
            matches!(
                &reason,
                RejectReason::MutatedAdmissionFile(detail) if detail.contains("disappeared")
            ),
            "expected removed admission evidence, got {reason:?}"
        );

        let mut rewritten = Fixture::new("mutated-evidence-rewritten");
        fs::remove_dir_all(rewritten.root.join(ADMISSIONS_DIRECTORY)).unwrap();
        rewritten.packages[0].admission_sha256 = None;
        rewritten.admit("2025-02-01-demo", "2025-02-01T03:00:00Z", &[(0, "general")]);
        rewritten.write();
        let reason = check_transition(accepted.root(), rewritten.root()).unwrap_err();
        assert!(
            matches!(
                &reason,
                RejectReason::MutatedAdmissionFile(detail) if detail.contains("changed")
            ),
            "expected rewritten admission evidence, got {reason:?}"
        );
    }

    #[test]
    fn rejects_gained_and_dropped_admission_bindings() {
        let unbound = Fixture::without_admission("binding-unbound");
        unbound.write();
        let bound = Fixture::new("binding-bound");
        bound.write();
        assert!(
            matches!(
                check_transition(unbound.root(), bound.root()),
                Err(RejectReason::MutatedIdentity(identity)) if identity == "main/demo/1.0.0"
            ),
            "an accepted identity must not gain admission evidence"
        );

        // Dropping an accepted binding needs an unloadable tree, so check the rule on loaded
        // catalogs whose binding was removed.
        let accepted_catalog = Catalog::load(bound.root()).unwrap();
        let mut candidate_catalog = Catalog::load(bound.root()).unwrap();
        for approval in &mut candidate_catalog.approvals {
            approval.admission_sha256 = None;
        }
        assert_eq!(
            verify_identities(&accepted_catalog, &candidate_catalog),
            Err(RejectReason::MutatedIdentity("main/demo/1.0.0".to_owned()))
        );
    }

    #[test]
    fn rejects_widened_and_narrowed_category_rules() {
        let accepted = Fixture::new("rules-accepted");
        accepted.write();

        let mut widened = Fixture::new("rules-widened");
        widened.rule("general", &["general", "extra"]);
        widened.write();
        assert_eq!(
            check_transition(accepted.root(), widened.root()),
            Err(RejectReason::CategoryRuleChanged(
                "category main/general may-depend-on [main/general] became [main/general, main/extra]"
                    .to_owned()
            ))
        );

        let mut narrowed = Fixture::new("rules-narrowed");
        narrowed.rule("extra", &["extra"]);
        narrowed.write();
        assert_eq!(
            check_transition(accepted.root(), narrowed.root()),
            Err(RejectReason::CategoryRuleChanged(
                "category main/extra may-depend-on [main/extra, main/general] became [main/extra]"
                    .to_owned()
            ))
        );

        let mut removed = Fixture::new("rules-removed");
        removed.move_name("extra", "extra", "general");
        removed.remove_category("extra");
        removed.write();
        assert_eq!(
            check_transition(accepted.root(), removed.root()),
            Err(RejectReason::CategoryRuleChanged(
                "category main/extra disappeared".to_owned()
            ))
        );
    }

    #[test]
    fn rejects_moved_and_removed_reserved_names() {
        let accepted = Fixture::new("homes-accepted");
        accepted.write();

        let mut moved = Fixture::new("homes-moved");
        moved.move_name("warp", "general", "extra");
        moved.write();
        assert_eq!(
            check_transition(accepted.root(), moved.root()),
            Err(RejectReason::HomeMoved(
                "main/warp left main/general for main/extra".to_owned()
            ))
        );

        let mut removed = Fixture::new("homes-removed");
        removed.remove_name("warp", "general");
        removed.write();
        assert_eq!(
            check_transition(accepted.root(), removed.root()),
            Err(RejectReason::MissingHome("main/warp".to_owned()))
        );
    }
}
