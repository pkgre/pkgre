//! Cargo end-to-end test for transparent same-registry categories and cross-registry dependencies.

use std::fmt::Write as _;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use pkgre_indexer::artifact::sha256_file;
use pkgre_indexer::index::index_path;
use serde_json::{Value, json};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[test]
fn cargo_builds_locked_with_clean_cache_across_two_registries() {
    let temporary = TemporaryDirectory::new("pkgre-cargo-e2e");
    let site = temporary.path().join("site");
    fs::create_dir_all(&site).unwrap();
    let server = StaticServer::start(site.clone());
    let base = server.base_url();
    let universe = format!("sparse+{base}/universe/");
    let pkgre = format!("sparse+{base}/pkgre/");

    write_registry_config(&site, "universe", &base);
    write_registry_config(&site, "pkgre", &base);
    add_package(
        &temporary,
        &site,
        "universe",
        "leaf-core",
        "pub fn value() -> u32 { 40 }\n",
        &[],
    );
    add_package(
        &temporary,
        &site,
        "universe",
        "matrix-middle",
        "pub fn value() -> u32 { leaf_core::value() + 1 }\n",
        &[("leaf-core", None)],
    );
    add_package(
        &temporary,
        &site,
        "pkgre",
        "pkgre-top",
        "pub fn value() -> u32 { matrix_middle::value() + 1 }\n",
        &[("matrix-middle", Some(&universe))],
    );

    let project = temporary.path().join("consumer");
    fs::create_dir_all(project.join(".cargo")).unwrap();
    fs::create_dir_all(project.join("src")).unwrap();
    let disabled = temporary.path().join("disabled-source");
    fs::create_dir(&disabled).unwrap();
    fs::write(
        project.join("Cargo.toml"),
        "[package]\nname = \"consumer\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[dependencies]\npkgre-top = { version = \"1\", registry = \"pkgre\" }\n",
    )
    .unwrap();
    fs::write(
        project.join("src/main.rs"),
        "fn main() { assert_eq!(pkgre_top::value(), 42); }\n",
    )
    .unwrap();
    fs::write(
        project.join(".cargo/config.toml"),
        format!(
            "[registries.universe]\nindex = {universe:?}\n\n[registries.pkgre]\nindex = {pkgre:?}\n\n[registry]\ndefault = \"pkgre\"\n\n[source.crates-io]\nreplace-with = \"disabled\"\n\n[source.disabled]\ndirectory = {:?}\n",
            disabled.display().to_string()
        ),
    )
    .unwrap();

    run_cargo(
        &project,
        &temporary.path().join("cargo-home-lock"),
        &["generate-lockfile"],
    );
    let lock = fs::read_to_string(project.join("Cargo.lock")).unwrap();
    assert!(lock.contains(&universe));
    assert!(lock.contains(&pkgre));
    assert!(!lock.contains("crates.io"));

    let clean_home = temporary.path().join("cargo-home-build");
    run_cargo(
        &project,
        &clean_home,
        &["metadata", "--locked", "--format-version", "1"],
    );
    run_cargo(&project, &clean_home, &["build", "--locked"]);
    let status = Command::new(project.join("target/debug/consumer"))
        .status()
        .unwrap();
    assert!(status.success());

    let requests = server.requests();
    assert!(requests.iter().any(|path| path.starts_with("/universe/")));
    assert!(requests.iter().any(|path| path.starts_with("/pkgre/")));
    assert!(requests.iter().any(|path| path.starts_with("/crates/")));
    assert!(requests.iter().all(|path| !path.contains("crates.io")));
    server.stop();
}

fn add_package(
    temporary: &TemporaryDirectory,
    site: &Path,
    registry: &str,
    name: &str,
    source: &str,
    dependencies: &[(&str, Option<&str>)],
) {
    let version = "1.0.0";
    let stage = temporary.path().join(format!("stage-{name}"));
    let root_name = format!("{name}-{version}");
    let root = stage.join(&root_name);
    fs::create_dir_all(root.join("src")).unwrap();
    let mut manifest =
        format!("[package]\nname = {name:?}\nversion = {version:?}\nedition = \"2024\"\n");
    if !dependencies.is_empty() {
        manifest.push_str("\n[dependencies]\n");
        for (dependency, _) in dependencies {
            writeln!(manifest, "{dependency} = \"1\"").unwrap();
        }
    }
    fs::write(root.join("Cargo.toml"), manifest).unwrap();
    fs::write(root.join("src/lib.rs"), source).unwrap();

    let archive_directory = site.join("crates");
    fs::create_dir_all(&archive_directory).unwrap();
    let temporary_archive = temporary.path().join(format!("{name}.crate"));
    let status = Command::new("tar")
        .args(["-czf"])
        .arg(&temporary_archive)
        .args(["-C"])
        .arg(&stage)
        .arg(&root_name)
        .status()
        .unwrap();
    assert!(status.success());
    let checksum = sha256_file(&temporary_archive).unwrap();
    fs::copy(
        &temporary_archive,
        archive_directory.join(format!("{checksum}.crate")),
    )
    .unwrap();

    let dependency_rows = dependencies
        .iter()
        .map(|(dependency, index)| {
            json!({
                "name": dependency,
                "req": "^1",
                "features": [],
                "optional": false,
                "default_features": true,
                "target": Value::Null,
                "kind": "normal",
                "registry": index,
            })
        })
        .collect::<Vec<_>>();
    let mut row = serde_json::to_vec(&json!({
        "name": name,
        "vers": version,
        "deps": dependency_rows,
        "cksum": checksum,
        "features": {},
        "yanked": false,
    }))
    .unwrap();
    row.push(b'\n');
    write_file(&site.join(registry).join(index_path(name)), &row);
}

fn write_registry_config(site: &Path, registry: &str, base: &str) {
    let config = serde_json::to_vec(&json!({
        "dl": format!("{base}/crates/{{sha256-checksum}}.crate"),
    }))
    .unwrap();
    write_file(&site.join(registry).join("config.json"), &config);
}

fn write_file(path: &Path, contents: &[u8]) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, contents).unwrap();
}

fn run_cargo(project: &Path, cargo_home: &Path, arguments: &[&str]) {
    fs::create_dir_all(cargo_home).unwrap();
    let output = Command::new(env!("CARGO"))
        .args(arguments)
        .current_dir(project)
        .env("CARGO_HOME", cargo_home)
        .env("CARGO_TERM_COLOR", "never")
        .env_remove("CARGO_REGISTRY_TOKEN")
        .env_remove("CARGO_REGISTRIES_CRATES_IO_TOKEN")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "cargo {arguments:?} failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

struct StaticServer {
    address: std::net::SocketAddr,
    stop: Arc<AtomicBool>,
    requests: Arc<Mutex<Vec<String>>>,
    thread: Option<JoinHandle<std::io::Result<()>>>,
}

impl StaticServer {
    fn start(root: PathBuf) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let thread_stop = Arc::clone(&stop);
        let thread_requests = Arc::clone(&requests);
        let thread = thread::spawn(move || {
            while !thread_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => serve(stream, &root, &thread_requests)?,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => return Err(error),
                }
            }
            Ok(())
        });
        Self {
            address,
            stop,
            requests,
            thread: Some(thread),
        }
    }

    fn base_url(&self) -> String {
        format!("http://{}", self.address)
    }

    fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }

    fn stop(mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = TcpStream::connect(self.address);
        self.thread.take().unwrap().join().unwrap().unwrap();
    }
}

impl Drop for StaticServer {
    fn drop(&mut self) {
        if let Some(thread) = self.thread.take() {
            self.stop.store(true, Ordering::Release);
            let _ = TcpStream::connect(self.address);
            let _ = thread.join();
        }
    }
}

fn serve(mut stream: TcpStream, root: &Path, requests: &Mutex<Vec<String>>) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut request = Vec::new();
    let mut buffer = [0_u8; 4096];
    while !request.windows(4).any(|window| window == b"\r\n\r\n") && request.len() < 16 * 1024 {
        let count = stream.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        request.extend_from_slice(&buffer[..count]);
    }
    let first_line = String::from_utf8_lossy(&request)
        .lines()
        .next()
        .unwrap_or_default()
        .to_owned();
    let mut fields = first_line.split_ascii_whitespace();
    let method = fields.next().unwrap_or_default();
    let target = fields.next().unwrap_or_default();
    if !matches!(method, "GET" | "HEAD") {
        return response(&mut stream, 405, b"method not allowed", method == "HEAD");
    }
    let path = target.split('?').next().unwrap_or_default();
    requests.lock().unwrap().push(path.to_owned());
    let relative = path.strip_prefix('/').unwrap_or(path);
    if relative
        .split('/')
        .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return response(&mut stream, 400, b"invalid path", method == "HEAD");
    }
    let file = root.join(relative);
    match fs::read(file) {
        Ok(contents) => response(&mut stream, 200, &contents, method == "HEAD"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            response(&mut stream, 404, b"not found", method == "HEAD")
        }
        Err(error) => Err(error),
    }
}

fn response(stream: &mut TcpStream, status: u16, body: &[u8], head: bool) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Error",
    };
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    if !head {
        stream.write_all(body)?;
    }
    stream.flush()
}

struct TemporaryDirectory {
    path: PathBuf,
}

impl TemporaryDirectory {
    fn new(prefix: &str) -> Self {
        let sequence = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("{prefix}-{}-{sequence}", std::process::id()));
        match fs::remove_dir_all(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("remove stale temporary directory: {error}"),
        }
        fs::create_dir(&path).unwrap();
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.path).unwrap();
    }
}
