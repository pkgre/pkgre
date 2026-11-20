//! The rule on the Gitlinks and the manifest paths of a release tag's checkout.
//!
//! `pkgre` never initializes or fetches a submodule, so a Gitlink's directory
//! stays empty and Cargo leaves it out of every archive: a Gitlink is accepted
//! when the innermost workspace member whose directory contains it is not a
//! released crate, or when no member's directory contains it. A path that a
//! released crate's manifest names is another matter. Cargo copies `readme` and
//! `license-file` into the archive even from outside the package's directory, so
//! one that resolves at or below a Gitlink, outside the checkout, or by an
//! absolute path is refused. Cargo refuses a build script outside the package
//! and drops a library or binary target outside it, so a `build` or a target
//! path that does either is refused too, which is stricter than Cargo: a release
//! tag never publishes a path that only a submodule or a host file could hold.
//! As a second line of defence, no archive may hold a path at or below a
//! Gitlink.
//!
//! Both the catalog's Git-tag packaging and the derivation apply the same rule,
//! from the members that `cargo metadata --no-deps` named, so that a Gitlink a
//! mode accepts is accepted by the other.

use std::fs;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use semver::Version;

use crate::policy::validate_relative_path;

/// The Git index mode of a Gitlink.
const GITLINK_MODE: &str = "160000";

/// One workspace member that `cargo metadata --no-deps` named.
#[derive(Debug)]
pub(crate) struct Member {
    /// Cargo package name, which a refusal names.
    pub(crate) name: String,
    /// Absolute directory of the member's manifest.
    pub(crate) directory: PathBuf,
    /// Whether the tag's release publishes this member.
    pub(crate) released: bool,
    /// The paths the member's manifest names, which a release tag holds to the
    /// rule of [`ensure_release_tag_paths`].
    pub(crate) manifest_paths: Vec<ManifestPath>,
}

/// One path that a manifest names, with the field it comes from.
#[derive(Debug)]
pub(crate) struct ManifestPath {
    /// The manifest field, as a refusal names it.
    pub(crate) field: &'static str,
    /// The path: as the manifest writes it for `readme` and `license-file`, and
    /// absolute for a target, whose `src_path` Cargo reports resolved.
    pub(crate) path: PathBuf,
    /// Whether the path is `readme` or `license-file`, which Cargo copies into
    /// the archive, rather than a target's own `path`.
    pub(crate) copied: bool,
}

/// Returns the paths that one released crate's manifest names.
///
/// `readme` and `license-file` are the manifest fields that Cargo copies into
/// the archive, even from outside the package's directory. A target's own `path`
/// is the manifest's `path` key of its `[[lib]]`, `[[bin]]`, `[[test]]`,
/// `[[bench]]` or `[[example]]` table, and a build script is the `custom-build`
/// target of the package, so Cargo reports both among the targets; it refuses a
/// build script outside the package and drops a library or binary target
/// outside it. `include` holds patterns, which cannot reach outside the
/// package's directory, and Cargo's exclusion of a nested package wins over
/// them, so neither can carry a Gitlink's files into an archive.
pub(crate) fn manifest_paths(
    readme: Option<&Path>,
    license_file: Option<&Path>,
    target_paths: &[PathBuf],
) -> Vec<ManifestPath> {
    let mut paths = Vec::new();
    for (field, path) in [("readme", readme), ("license-file", license_file)] {
        if let Some(path) = path {
            paths.push(ManifestPath {
                field,
                path: path.to_path_buf(),
                copied: true,
            });
        }
    }
    paths.extend(target_paths.iter().map(|path| ManifestPath {
        field: "target path",
        path: path.clone(),
        copied: false,
    }));
    paths
}

/// Returns the Gitlinks of one `git ls-files --stage` output.
///
/// Git quotes a path that holds a control character, a backslash or a non-ASCII
/// byte, which the checkout's own path rules refuse, so a Gitlink that Git
/// quoted is refused when the rule validates the path it read.
pub(crate) fn gitlinks_in_index(staged: &str) -> Vec<PathBuf> {
    staged
        .lines()
        .filter_map(|line| {
            let (mode, rest) = line.split_once(' ')?;
            if mode != GITLINK_MODE {
                return None;
            }
            let (_, path) = rest.split_once('\t')?;
            Some(PathBuf::from(path))
        })
        .collect()
}

/// Refuses the paths and Gitlinks that a release tag's checkout may not hold.
///
/// `gitlinks` are the repository-relative paths that Git's index records,
/// `checkout` is the root they are relative to, and `members` are every
/// workspace member that `cargo metadata --no-deps` named of the same checkout.
///
/// Two rules apply. A Gitlink is accepted when the innermost member whose
/// directory contains it is not a released crate, or when no member's directory
/// contains it. And a path that a released crate's manifest names resolves
/// inside the tag's checkout and outside the checkout's own `.git` directory,
/// which Git writes on the host: a path that `..` components take outside the
/// checkout, one whose first component under the checkout is `.git`, or one at
/// or below a Gitlink is refused, naming the crate, the field and the path. An
/// absolute `readme` or `license-file` is refused as well, since Cargo copies
/// it into the archive; a target's path is held to the containment rule alone,
/// because `cargo metadata` reports it resolved and absolute. The checkout, not
/// the workspace root, is the boundary, because a workspace root may sit below
/// the checkout while a member sits above it, and the checkout is the tag's
/// whole tree either way.
///
/// # Errors
///
/// Returns an error for a Gitlink path that is not a safe repository-relative
/// path, a Gitlink whose innermost member is a released crate, a released
/// crate's manifest path that is absolute, that resolves outside the checkout,
/// that resolves inside the checkout's `.git` directory, or that resolves at or
/// below a Gitlink, or a checkout or member directory that cannot be resolved.
pub(crate) fn ensure_release_tag_paths(
    checkout: &Path,
    gitlinks: &[PathBuf],
    members: &[Member],
) -> Result<()> {
    let checkout = fs::canonicalize(checkout)
        .with_context(|| format!("canonicalize release tag checkout {}", checkout.display()))?;
    let mut located = Vec::with_capacity(gitlinks.len());
    for gitlink in gitlinks {
        validate_relative_path(gitlink, false)
            .with_context(|| format!("Gitlink path {:?}", gitlink.display().to_string()))?;
        located.push(checkout.join(gitlink));
    }
    let directories = members
        .iter()
        .map(|member| {
            fs::canonicalize(&member.directory)
                .with_context(|| format!("canonicalize the directory of package {}", member.name))
        })
        .collect::<Result<Vec<_>>>()?;
    for (member, directory) in members.iter().zip(&directories) {
        if !member.released {
            continue;
        }
        for manifest_path in &member.manifest_paths {
            ensure!(
                !manifest_path.copied || !manifest_path.path.is_absolute(),
                "the released package \"{}\" names its {} with the absolute path \"{}\"; a release tag's manifests name every path inside its checkout, relative to the package's directory",
                member.name,
                manifest_path.field,
                manifest_path.path.display()
            );
            let resolved = resolve_lexically(directory, &manifest_path.path);
            ensure!(
                resolved.starts_with(&checkout),
                "the released package \"{}\" names its {} at \"{}\", which resolves to \"{}\" outside the checkout \"{}\" of the release tag; a release tag's manifests name every path inside its checkout",
                member.name,
                manifest_path.field,
                manifest_path.path.display(),
                resolved.display(),
                checkout.display()
            );
            ensure!(
                !inside_git_directory(&checkout, &resolved),
                "the released package \"{}\" names its {} at \"{}\", which resolves to \"{}\" inside the checkout's own .git directory; Git writes that directory on the host, so a release tag's manifests name no path in it",
                member.name,
                manifest_path.field,
                manifest_path.path.display(),
                resolved.display()
            );
            let Some(gitlink) = gitlinks
                .iter()
                .zip(&located)
                .find(|(_, absolute)| resolved.starts_with(absolute))
                .map(|(gitlink, _)| gitlink)
            else {
                continue;
            };
            let consequence = if manifest_path.copied {
                "Cargo copies such a file into the archive"
            } else {
                "Cargo refuses or drops such a target, and this refusal is stricter than Cargo"
            };
            bail!(
                "the released package \"{}\" names its {} at \"{}\", which is at or below the Gitlink \"{}\"; {consequence}, and a release tag may hold a Gitlink only outside its released packages",
                member.name,
                manifest_path.field,
                manifest_path.path.display(),
                gitlink.display()
            );
        }
    }
    if gitlinks.is_empty() {
        return Ok(());
    }
    for (gitlink, absolute) in gitlinks.iter().zip(&located) {
        let mut innermost: Option<(&Member, usize)> = None;
        for (member, directory) in members.iter().zip(&directories) {
            if absolute.starts_with(directory) {
                let depth = directory.components().count();
                if innermost.is_none_or(|(_, current)| current < depth) {
                    innermost = Some((member, depth));
                }
            }
        }
        if let Some((member, _)) = innermost {
            ensure!(
                !member.released,
                "release tag checkout holds a Gitlink at \"{}\" inside the released package \"{}\"; a release tag may hold a Gitlink only outside its released packages",
                gitlink.display(),
                member.name
            );
        }
    }
    Ok(())
}

/// Returns whether a resolved path lies in the checkout's own `.git` directory.
///
/// Git writes that directory on the host, so it holds the host's identity, its
/// timestamps and the fetch's own state, and no release tag may publish it. The
/// name is compared case-insensitively, as the checkout's own path rules compare
/// it, since a case-insensitive filesystem reaches the same directory through
/// any spelling.
fn inside_git_directory(checkout: &Path, resolved: &Path) -> bool {
    let Ok(relative) = resolved.strip_prefix(checkout) else {
        return false;
    };
    relative
        .components()
        .next()
        .and_then(|component| component.as_os_str().to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case(".git"))
}

/// Refuses an archive that holds a path at or below a Gitlink.
///
/// `gitlinks` are the checkout's repository-relative Gitlinks, and
/// `package_directory` is the repository-relative directory of the package the
/// archive holds.
///
/// # Errors
///
/// Returns an error for an archive that cannot be read, or that holds a path at
/// or below a Gitlink.
pub(crate) fn ensure_archive_outside_gitlinks(
    gitlinks: &[PathBuf],
    package_directory: &Path,
    name: &str,
    version: &Version,
    archive: &[u8],
) -> Result<()> {
    if gitlinks.is_empty() {
        return Ok(());
    }
    let archive = crate::update::read_crate_archive(name, version, archive, &[])
        .with_context(|| format!("read the packaged archive of {name} {version}"))?;
    for path in archive.files.keys() {
        let Some(resolved) = relative_to(package_directory, path) else {
            continue;
        };
        let Some(gitlink) = gitlinks
            .iter()
            .find(|gitlink| resolved.starts_with(gitlink))
        else {
            continue;
        };
        bail!(
            "the packaged archive of {name} {version} holds \"{path}\", which is at or below the Gitlink \"{}\"; a release tag may hold a Gitlink only outside its released packages",
            gitlink.display()
        );
    }
    Ok(())
}

/// Joins one archive path to the repository-relative directory of its package.
///
/// Returns `None` for a path that leaves that directory, which the archive reader
/// cannot produce.
fn relative_to(package_directory: &Path, path: &str) -> Option<PathBuf> {
    let mut resolved = PathBuf::new();
    for component in package_directory
        .components()
        .chain(Path::new(path).components())
    {
        match component {
            Component::CurDir => {}
            Component::Normal(part) => resolved.push(part),
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    Some(resolved)
}

/// Resolves a path that a manifest writes against the directory of its manifest.
///
/// A manifest path may not exist, since the directory of a Gitlink stays empty,
/// so the resolution is lexical: `.` components are dropped and each `..` pops
/// the component before it.
fn resolve_lexically(directory: &Path, path: &Path) -> PathBuf {
    let mut resolved = if path.is_absolute() {
        PathBuf::new()
    } else {
        directory.to_path_buf()
    };
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::RootDir | Component::Prefix(_) => {
                resolved = PathBuf::from(component.as_os_str());
            }
            Component::ParentDir => {
                resolved.pop();
            }
            Component::Normal(part) => resolved.push(part),
        }
    }
    resolved
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Write as _;

    use flate2::Compression;
    use flate2::write::GzEncoder;

    use super::*;
    use crate::package::TemporaryDirectory;

    /// One workspace member as a test builds it: name, directory, and whether
    /// the release publishes it.
    fn member(name: &str, directory: &Path, released: bool) -> Member {
        Member {
            name: name.to_owned(),
            directory: directory.to_path_buf(),
            released,
            manifest_paths: Vec::new(),
        }
    }

    /// Creates every member directory and every Gitlink directory of a checkout.
    ///
    /// A Gitlink that pkgre never initializes stays an empty directory, which is
    /// what "no submodule fetch" leaves behind.
    fn directories(checkout: &Path, members: &[Member], gitlinks: &[&str]) {
        fs::create_dir_all(checkout).unwrap();
        for member in members {
            fs::create_dir_all(&member.directory).unwrap();
        }
        for gitlink in gitlinks {
            fs::create_dir_all(checkout.join(gitlink)).unwrap();
        }
    }

    fn gitlinks(paths: &[&str]) -> Vec<PathBuf> {
        paths.iter().map(PathBuf::from).collect()
    }

    #[test]
    fn reads_the_gitlinks_of_an_index() {
        let staged = "\
100644 1111111111111111111111111111111111111111 0\tCargo.toml
160000 2222222222222222222222222222222222222222 0\tvendor/sub
120000 3333333333333333333333333333333333333333 0\tlink
";
        assert_eq!(gitlinks_in_index(staged), gitlinks(&["vendor/sub"]));
        assert!(gitlinks_in_index("").is_empty());
    }

    #[test]
    fn accepts_a_gitlink_inside_a_member_the_release_does_not_publish() {
        let temporary = TemporaryDirectory::new("pkgre-gitlinks-unreleased").unwrap();
        let members = vec![
            member("demo", &temporary.path().join("crates/demo"), true),
            member("tools", &temporary.path().join("tools"), false),
        ];
        directories(temporary.path(), &members, &["tools/vendor"]);
        ensure_release_tag_paths(temporary.path(), &gitlinks(&["tools/vendor"]), &members).unwrap();
    }

    #[test]
    fn refuses_a_gitlink_inside_a_released_package() {
        let temporary = TemporaryDirectory::new("pkgre-gitlinks-released").unwrap();
        let members = vec![member("demo", &temporary.path().join("crates/demo"), true)];
        directories(temporary.path(), &members, &["crates/demo/vendor"]);
        let error = ensure_release_tag_paths(
            temporary.path(),
            &gitlinks(&["crates/demo/vendor"]),
            &members,
        )
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("crates/demo/vendor"), "{message}");
        assert!(message.contains("\"demo\""), "{message}");
    }

    #[test]
    fn refuses_a_gitlink_in_a_root_package_outside_every_nested_member() {
        let temporary = TemporaryDirectory::new("pkgre-gitlinks-root").unwrap();
        let members = vec![
            member("demo", temporary.path(), true),
            member("tools", &temporary.path().join("tools"), false),
        ];
        directories(temporary.path(), &members, &["vendor/sub"]);
        let error =
            ensure_release_tag_paths(temporary.path(), &gitlinks(&["vendor/sub"]), &members)
                .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("vendor/sub"), "{message}");
        assert!(message.contains("\"demo\""), "{message}");
    }

    #[test]
    fn accepts_a_gitlink_below_a_nested_member_of_a_root_package() {
        let temporary = TemporaryDirectory::new("pkgre-gitlinks-nested").unwrap();
        let members = vec![
            member("demo", temporary.path(), true),
            member("res", &temporary.path().join("tests/res"), false),
        ];
        directories(temporary.path(), &members, &["tests/res/data"]);
        ensure_release_tag_paths(temporary.path(), &gitlinks(&["tests/res/data"]), &members)
            .unwrap();
    }

    #[test]
    fn accepts_a_gitlink_outside_every_member() {
        let temporary = TemporaryDirectory::new("pkgre-gitlinks-outside").unwrap();
        let members = vec![member("demo", &temporary.path().join("crates/demo"), true)];
        directories(temporary.path(), &members, &["vendor/data"]);
        ensure_release_tag_paths(temporary.path(), &gitlinks(&["vendor/data"]), &members).unwrap();
    }

    #[test]
    fn refuses_a_manifest_path_at_or_below_an_accepted_gitlink() {
        let temporary = TemporaryDirectory::new("pkgre-gitlinks-readme").unwrap();
        let mut members = vec![
            member("demo", &temporary.path().join("crates/demo"), true),
            member("tools", &temporary.path().join("tools"), false),
        ];
        directories(temporary.path(), &members, &["tools/vendor"]);
        members[0].manifest_paths = vec![ManifestPath {
            field: "readme",
            path: PathBuf::from("../../tools/vendor/README.md"),
            copied: true,
        }];
        let error =
            ensure_release_tag_paths(temporary.path(), &gitlinks(&["tools/vendor"]), &members)
                .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("readme"), "{message}");
        assert!(
            message.contains("../../tools/vendor/README.md"),
            "{message}"
        );
        assert!(message.contains("tools/vendor"), "{message}");
    }

    #[test]
    fn refuses_an_absolute_manifest_path() {
        let temporary = TemporaryDirectory::new("pkgre-gitlinks-absolute").unwrap();
        let mut members = vec![member("demo", &temporary.path().join("crates/demo"), true)];
        directories(temporary.path(), &members, &[]);
        members[0].manifest_paths = vec![ManifestPath {
            field: "readme",
            path: temporary.path().join("outside/README.md"),
            copied: true,
        }];
        let error = ensure_release_tag_paths(temporary.path(), &[], &members).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("absolute"), "{message}");
        assert!(message.contains("outside/README.md"), "{message}");
    }

    #[test]
    fn refuses_a_manifest_path_that_leaves_the_checkout() {
        let temporary = TemporaryDirectory::new("pkgre-gitlinks-outside-checkout").unwrap();
        let workspace = temporary.path().join("workspace");
        let mut members = vec![member("demo", &workspace.join("crates/demo"), true)];
        directories(&workspace, &members, &[]);
        members[0].manifest_paths = vec![ManifestPath {
            field: "license-file",
            path: PathBuf::from("../../../LICENSE"),
            copied: true,
        }];
        let error = ensure_release_tag_paths(&workspace, &[], &members).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("license-file"), "{message}");
        assert!(message.contains("outside the checkout"), "{message}");
    }

    #[test]
    fn refuses_a_manifest_path_inside_the_checkouts_git_directory() {
        for path in [
            "../../.git/logs/HEAD",
            "../../.git/config",
            "../../.GIT/index",
        ] {
            let temporary = TemporaryDirectory::new("pkgre-gitlinks-git-directory").unwrap();
            let workspace = temporary.path().join("workspace");
            let mut members = vec![member("demo", &workspace.join("crates/demo"), true)];
            directories(&workspace, &members, &[]);
            members[0].manifest_paths = vec![ManifestPath {
                field: "readme",
                path: PathBuf::from(path),
                copied: true,
            }];
            let error = ensure_release_tag_paths(&workspace, &[], &members).unwrap_err();
            let message = format!("{error:#}");
            assert!(message.contains(".git directory"), "{path}: {message}");
        }
    }

    #[test]
    fn accepts_a_manifest_path_that_stays_inside_the_checkout() {
        let temporary = TemporaryDirectory::new("pkgre-gitlinks-inside-checkout").unwrap();
        let workspace = temporary.path().join("workspace");
        let mut members = vec![member("demo", &workspace.join("crates/demo"), true)];
        directories(&workspace, &members, &[]);
        members[0].manifest_paths = vec![
            ManifestPath {
                field: "readme",
                path: PathBuf::from("../../README.md"),
                copied: true,
            },
            ManifestPath {
                field: "target path",
                path: PathBuf::from("src/lib.rs"),
                copied: false,
            },
        ];
        ensure_release_tag_paths(&workspace, &[], &members).unwrap();
    }

    #[test]
    fn accepts_a_manifest_path_outside_every_gitlink() {
        let temporary = TemporaryDirectory::new("pkgre-gitlinks-readme-ok").unwrap();
        let mut members = vec![member("demo", &temporary.path().join("crates/demo"), true)];
        directories(temporary.path(), &members, &["vendor/data"]);
        members[0].manifest_paths = vec![ManifestPath {
            field: "readme",
            path: PathBuf::from("README.md"),
            copied: true,
        }];
        ensure_release_tag_paths(temporary.path(), &gitlinks(&["vendor/data"]), &members).unwrap();
    }

    #[test]
    fn refuses_an_archive_path_at_or_below_a_gitlink() {
        let archive = archive(&[
            ("src/lib.rs", "pub fn answer() {}\n"),
            ("vendor/sub/data.txt", "x"),
        ]);
        let version = Version::parse("1.2.3").unwrap();
        let error = ensure_archive_outside_gitlinks(
            &gitlinks(&["vendor/sub"]),
            Path::new("."),
            "demo",
            &version,
            &archive,
        )
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("vendor/sub/data.txt"), "{message}");
        ensure_archive_outside_gitlinks(
            &gitlinks(&["other/vendor"]),
            Path::new("."),
            "demo",
            &version,
            &archive,
        )
        .unwrap();
        ensure_archive_outside_gitlinks(
            &gitlinks(&["vendor/sub"]),
            Path::new("crates/demo"),
            "demo",
            &version,
            &archive,
        )
        .unwrap();
    }

    /// Writes one gzipped ustar archive of `demo` 1.2.3 with the named files.
    fn archive(files: &[(&str, &str)]) -> Vec<u8> {
        let mut tar = Vec::new();
        for (path, contents) in files {
            let full = format!("demo-1.2.3/{path}");
            let mut header = [0_u8; 512];
            header[..full.len()].copy_from_slice(full.as_bytes());
            set_octal(&mut header[100..108], 0o644);
            set_octal(&mut header[108..116], 0);
            set_octal(&mut header[116..124], 0);
            set_octal(&mut header[124..136], contents.len() as u64);
            set_octal(&mut header[136..148], 0);
            header[148..156].fill(b' ');
            header[156] = b'0';
            header[257..263].copy_from_slice(b"ustar\0");
            header[263..265].copy_from_slice(b"00");
            let checksum = header.iter().map(|byte| u64::from(*byte)).sum();
            set_octal(&mut header[148..156], checksum);
            tar.extend_from_slice(&header);
            tar.extend_from_slice(contents.as_bytes());
            tar.resize(tar.len() + (512 - contents.len() % 512) % 512, 0);
        }
        tar.resize(tar.len() + 1024, 0);
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&tar).unwrap();
        encoder.finish().unwrap()
    }

    /// Writes one octal field of a tar header.
    fn set_octal(field: &mut [u8], value: u64) {
        let digits = format!("{:0width$o}", value, width = field.len() - 2);
        assert_eq!(digits.len(), field.len() - 2);
        field[..digits.len()].copy_from_slice(digits.as_bytes());
        field[field.len() - 2] = 0;
        field[field.len() - 1] = b' ';
    }
}
