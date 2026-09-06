#!/usr/bin/env python3
"""pkgre-vendor: patch vendored crate manifests so re-resolution matches Cargo.lock.

Run inside the cargoDeps fixed-output derivation, after a real
`cargo vendor --locked <dir>`:

    python3 pkgre-vendor.py <vendor-dir> <Cargo.lock>

Why: dependency manifests served by curated registries (and crates.io) are
cargo-normalized with unqualified dependency entries. When such a vendored
tree is re-resolved, those entries normalize to crates.io, split the package
identity away from the lock rows (which point at the curated registry), and
cargo is forced to update the lock (upstream cargo#15323). This script reads
the truth from Cargo.lock and inserts `registry-index = "<url>"` into every
unqualified dependency whose lock row resolves to a non-crates.io registry —
the same URL form `cargo package` writes into published manifests, so cargo
demonstrably reads it from registry-sourced manifests.

Rules:
- deps already qualified with `registry-index` are left untouched
- name-form `registry = "<name>"` qualifiers are normalized to
  `registry-index = "<lock-url>"` (the lock row is the authority)
- git, path, and `workspace = true` dependencies are skipped
- deps whose lock row resolves to crates.io (or has no lock source) are left
  unqualified — crates.io is the correct default for them
- a normal or build dependency that cannot be found in the lock is a hard
  failure; it is never guessed to be crates.io. A dev-dependency or an
  `optional = true` dependency missing from the lock is only noted (they are
  outside the consumer's resolve graph until activated)
- after patching a manifest, only its own `.cargo-checksum.json` is updated:
  `files["Cargo.toml"]` is recomputed from the patched bytes; `package` (equal
  to the lock row checksum) is never touched. Crates with nothing to patch are
  left byte-identical to `cargo vendor` output, checksum file included

Config emission for consumers:

    python3 pkgre-vendor.py --emit-config <Cargo.lock> \
        [--registries-from <consumer .cargo/config.toml>] [--vendor-dir-var NAME]

prints a `.cargo/config.toml` mapping every non-crates.io lock source to a
shared `vendored-sources` directory (placeholder `@vendor@` unless
`--vendor-dir-var` is given), keeping the `[source.crates-io] replace-with`
belt so any stray crates.io-normalized dependency fails loudly instead of
silently hitting the network, and copying the consumer's `[registries.*]`
tables so name-form `registry = "<name>"` dependencies keep resolving.

Hand-vendoring caveat: raw `cargo vendor` output has exactly the #15323
re-resolution hazard this script closes. Hand vendors must run this script
themselves (or accept that `--locked` builds force a lock update).

Self-test (no network, no cargo):

    python3 pkgre-vendor.py --self-test
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
import tempfile
import tomllib
from pathlib import Path

CRATES_IO_SOURCES = frozenset(
    {
        "registry+https://github.com/rust-lang/crates.io-index",
        "sparse+https://index.crates.io/",
    }
)

DEP_KINDS = ("dependencies", "dev-dependencies", "build-dependencies")
DEP_KIND_SET = frozenset(DEP_KINDS)

VENDOR_DIR_PLACEHOLDER = "@vendor@"

HEADER_RE = re.compile(r"^\[(?!\[)(?P<path>[^\]]+)\][ \t]*$")
KEY_RE = re.compile(r"^(?P<key>[A-Za-z0-9_.-]+)[ \t]*=(?P<value>.*)$")
PLAIN_DEP_ENTRY_RE = re.compile(r"^(?P<key>[A-Za-z0-9_-]+)[ \t]*=[ \t]*(?P<value>.+)$")

# A dependency table header path, dot-separated, with optionally quoted
# segments: [target."cfg(unix)".dev-dependencies.flate2]
SEGMENT_RE = re.compile(r"""("[^"]*"|'[^']*'|[^."]+)""")


class VendorError(Exception):
    """Loud, actionable failure — never swallow into a silent wrong patch."""


def fail(message: str) -> VendorError:
    return VendorError(f"pkgre-vendor: ERROR: {message}")


# ---------------------------------------------------------------------------
# semver subset: enough to pick lock rows for dependency requirements
# ---------------------------------------------------------------------------


class Version:
    __slots__ = ("major", "minor", "patch", "pre")

    def __init__(self, text: str) -> None:
        core, _, _meta = text.partition("+")
        core, _, pre = core.partition("-")
        parts = core.split(".")
        if len(parts) > 3 or not all(p.isdigit() for p in parts):
            raise fail(f"unsupported version {text!r}")
        nums = [int(p) for p in parts] + [0] * (3 - len(parts))
        self.major, self.minor, self.patch = nums[0], nums[1], nums[2]
        self.pre = tuple(p for p in pre.split(".") if pre) if pre else None

    def key(self) -> tuple:
        # build metadata ignored; release sorts after any pre-release
        pre_key = (0, self.pre) if self.pre is not None else (1, ())
        return (self.major, self.minor, self.patch, pre_key)

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"{self.major}.{self.minor}.{self.patch}"


def _matches_one(op: str, text: str, version: Version) -> bool:
    bound = Version(text)
    v, b = version.key(), bound.key()
    if op in ("=", "=="):
        return v == b
    if op == ">=":
        return v >= b
    if op == ">":
        return v > b
    if op == "<=":
        return v <= b
    if op == "<":
        return v < b
    if op == "^":
        if not v >= b:
            return False
        if bound.major > 0:
            return version.major == bound.major
        if bound.minor > 0:
            return version.minor == bound.minor
        return version.patch == bound.patch
    if op == "~":
        if not v >= b:
            return False
        if len([p for p in text.split(".") if p]) >= 2:
            return version.major == bound.major and version.minor == bound.minor
        return version.major == bound.major
    raise fail(f"unsupported requirement operator {op!r}")


class Req:
    """Small cargo-compatible requirement: =, bare caret, ~, comparators."""

    def __init__(self, text: str) -> None:
        self.terms: list[tuple[str, str]] = []
        text = text.strip()
        if not text:
            return  # no requirement: matches anything
        for raw in text.split(","):
            raw = raw.strip()
            if not raw:
                continue
            for op in (">=", "<=", "==", ">", "<", "=", "~", "^"):
                if raw.startswith(op):
                    self.terms.append((op, raw[len(op) :].strip()))
                    break
            else:
                self.terms.append(("^", raw))

    def matches(self, version: Version) -> bool:
        if not self.terms:
            return True
        return all(_matches_one(op, text, version) for op, text in self.terms)


# ---------------------------------------------------------------------------
# lock parsing
# ---------------------------------------------------------------------------


class Lock:
    def __init__(self, path: Path) -> None:
        with path.open("rb") as fh:
            data = tomllib.load(fh)
        self.rows: dict[tuple[str, str], dict] = {}
        self.by_name: dict[str, list[dict]] = {}
        for package in data.get("package", []):
            row = {
                "name": package["name"],
                "version": package["version"],
                "source": package.get("source"),
                "checksum": package.get("checksum"),
            }
            self.rows[(row["name"], row["version"])] = row
            self.by_name.setdefault(row["name"], []).append(row)

    def lookup(self, name: str, req_text: str | None):
        """Rows for `name` filtered by requirement: (unambiguous row, candidates)."""
        rows = self.by_name.get(name, [])
        if req_text is None:
            return (rows[0] if len(rows) == 1 else None, rows)
        req = Req(req_text)
        matched = [row for row in rows if req.matches(Version(row["version"]))]
        if len(matched) == 1:
            return (matched[0], rows)
        return (None, matched)

    def sources(self) -> list[str]:
        """Distinct non-crates.io, non-path sources in the lock, sorted."""
        found = {
            row["source"]
            for row in self.rows.values()
            if row["source"] and row["source"] not in CRATES_IO_SOURCES
        }
        return sorted(found)


# ---------------------------------------------------------------------------
# manifest line scanning
# ---------------------------------------------------------------------------


def split_table_path(raw: str) -> list[str]:
    segments = []
    for match in SEGMENT_RE.finditer(raw):
        segment = match.group(1)
        if len(segment) >= 2 and segment[0] in "\"'":
            segments.append(segment[1:-1])
        else:
            segments.append(segment.strip())
    return segments


def classify_table(segments: list[str]):
    """Return (kind, dep_name) for dependency tables, else None.

    Recognizes [dependencies], [dependencies.<name>],
    [target.<t>.<kind>], and [target.<t>.<kind>.<name>].
    """
    if not segments:
        return None
    if segments[0] == "workspace":
        return None  # workspace dependency definitions are not graph deps
    if segments[0] == "target":
        if len(segments) == 3 and segments[2] in DEP_KIND_SET:
            return (segments[2], None)  # plain section inside a target table
        if len(segments) == 4 and segments[2] in DEP_KIND_SET:
            return (segments[2], segments[3])
        return None
    if len(segments) == 1 and segments[0] in DEP_KIND_SET:
        return (segments[0], None)  # plain section, entries follow as key lines
    if len(segments) == 2 and segments[0] in DEP_KIND_SET:
        return (segments[0], segments[1])
    return None


def strip_quotes(text: str) -> str:
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        return text[1:-1]
    return text


def _split_inline(value_text: str) -> list[str]:
    body = value_text.strip()
    if not (body.startswith("{") and body.endswith("}")):
        raise fail(f"unsupported multi-line or malformed inline table: {body!r}")
    inner = body[1:-1]
    parts: list[str] = []
    depth = 0
    current = ""
    quote: str | None = None
    for char in inner:
        if quote:
            current += char
            if char == quote:
                quote = None
            continue
        if char in "\"'":
            quote = char
            current += char
        elif char in "[{":
            depth += 1
            current += char
        elif char in "]}":
            depth -= 1
            current += char
        elif char == "," and depth == 0:
            parts.append(current)
            current = ""
        else:
            current += char
    if current.strip():
        parts.append(current)
    return parts


def inline_table_get(value_text: str, key: str) -> str | None:
    """Fetch a scalar from a single-line inline table value."""
    for part in _split_inline(value_text):
        key_match = KEY_RE.match(part.strip())
        if key_match and key_match.group("key") == key:
            return strip_quotes(key_match.group("value"))
    return None


def inline_table_set(value_text: str, key: str, value: str) -> str:
    body = value_text.strip()
    if not (body.startswith("{") and body.endswith("}")):
        raise fail(f"unsupported multi-line inline table: {body!r}")
    inner = body[1:-1].rstrip()
    if not inner:
        return "{ " + key + " = " + value + " }"
    return body[:-1].rstrip() + ", " + key + " = " + value + " }"


class Manifest:
    """Line-oriented view of a cargo-normalized crate manifest."""

    def __init__(self, text: str) -> None:
        self.lines = text.split("\n")
        self.package_name: str | None = None
        self.package_version: str | None = None
        self.dep_entries: list[dict] = []
        self._scan()

    def _scan(self) -> None:
        section: dict | None = None  # current plain-section record, if any
        for index, line in enumerate(self.lines):
            if line.startswith("["):
                section = None
                header = HEADER_RE.match(line)
                if not header:
                    continue  # [[array-of-tables]] or unparseable: boundary only
                segments = split_table_path(header.group("path"))
                if segments == ["package"]:
                    section = {"kind": "package"}
                    self.dep_entries.append(section)
                    continue
                classified = classify_table(segments)
                if classified:
                    kind, dep_name = classified
                    if dep_name is None:
                        section = {
                            "kind": kind,
                            "plain": True,
                            "entries": [],
                        }
                        self.dep_entries.append(section)
                    else:
                        section = None
                        self.dep_entries.append(
                            {
                                "kind": kind,
                                "name": dep_name,
                                "header_index": index,
                                "header_line": line,
                            }
                        )
                continue
            if section is None:
                continue
            key_match = KEY_RE.match(line)
            if not key_match:
                continue
            if section["kind"] == "package":
                if key_match.group("key") in ("name", "version"):
                    value = strip_quotes(key_match.group("value"))
                    if key_match.group("key") == "name":
                        self.package_name = value
                    else:
                        self.package_version = value
            elif section.get("plain"):
                entry = PLAIN_DEP_ENTRY_RE.match(line)
                if entry:
                    section["entries"].append(
                        {
                            "key": entry.group("key"),
                            "value": entry.group("value"),
                            "line_index": index,
                        }
                    )

    def iter_deps(self):
        """Yield dep records with patch anchors."""
        for entry in self.dep_entries:
            if entry["kind"] == "package":
                continue
            if entry.get("plain"):
                for item in entry["entries"]:
                    yield {
                        "kind": entry["kind"],
                        "key": item["key"],
                        "value_text": item["value"],
                        "line_index": item["line_index"],
                        "inline": True,
                    }
            else:
                keys: dict[str, str] = {}
                key_lines: dict[str, int] = {}
                for offset, line in enumerate(self.lines[entry["header_index"] + 1 :]):
                    if line.startswith("["):
                        break
                    key_match = KEY_RE.match(line)
                    if key_match:
                        key = key_match.group("key")
                        keys[key] = key_match.group("value").strip()
                        key_lines[key] = entry["header_index"] + 1 + offset
                yield {
                    "kind": entry["kind"],
                    "key": entry["name"],
                    "keys": keys,
                    "key_lines": key_lines,
                    "header_index": entry["header_index"],
                    "header_line": entry["header_line"],
                    "inline": False,
                }


# ---------------------------------------------------------------------------
# patching
# ---------------------------------------------------------------------------


class Patcher:
    def __init__(self, vendor_dir: Path, lock: Lock, verbose: bool = True) -> None:
        self.vendor_dir = vendor_dir
        self.lock = lock
        self.verbose = verbose
        self.patched = 0
        self.scanned = 0
        self.notes: list[str] = []

    def note(self, message: str) -> None:
        self.notes.append(message)
        if self.verbose:
            print(f"pkgre-vendor: {message}", file=sys.stderr)

    def patch(self) -> int:
        crate_dirs = sorted(
            child
            for child in self.vendor_dir.iterdir()
            if child.is_dir() and not child.name.startswith(".")
        )
        if not crate_dirs:
            raise fail(f"no vendored crates found under {self.vendor_dir}")
        for crate_dir in crate_dirs:
            self._patch_crate(crate_dir)
        return self.patched

    def _patch_crate(self, crate_dir: Path) -> None:
        manifest_path = crate_dir / "Cargo.toml"
        checksum_path = crate_dir / ".cargo-checksum.json"
        if not manifest_path.is_file():
            raise fail(f"vendored crate {crate_dir.name} has no Cargo.toml")
        original = manifest_path.read_text()
        manifest = Manifest(original)
        if not manifest.package_name or not manifest.package_version:
            raise fail(f"cannot read [package] name/version from {manifest_path}")
        self.scanned += 1
        lock_row = self.lock.rows.get((manifest.package_name, manifest.package_version))
        if lock_row is None:
            raise fail(
                f"vendored crate {manifest.package_name}"
                f"-{manifest.package_version} is not in the Cargo.lock — "
                "refusing to patch an unknown crate"
            )

        edits: list[tuple[int, str, str]] = []  # (original_index, op, text)
        for dep in manifest.iter_deps():
            outcome = self._dep_outcome(manifest, dep)
            if outcome is None:
                continue
            action, url = outcome
            if dep["inline"]:
                new_value = self._patch_inline(dep, action, url)
                line = manifest.lines[dep["line_index"]]
                key = PLAIN_DEP_ENTRY_RE.match(line).group("key")
                edits.append((dep["line_index"], "set", f"{key} = {new_value}"))
            elif action == "insert":
                edits.append(
                    (
                        dep["header_index"],
                        "insert-after",
                        f'registry-index = "{url}"',
                    )
                )
            else:
                # name-form `registry = "<name>"` lives on a body line in the
                # longhand form; replace exactly that line
                registry_line = dep.get("key_lines", {}).get("registry")
                if registry_line is None:
                    raise fail(
                        "could not locate name-form registry qualifier for "
                        f"{dep['key']!r} in {manifest_path}"
                    )
                edits.append((registry_line, "set", f'registry-index = "{url}"'))

        if not edits:
            return
        # apply bottom-up so original indices stay valid
        for index, op, text in sorted(edits, key=lambda edit: -edit[0]):
            if op == "set":
                manifest.lines[index] = text
            else:
                manifest.lines.insert(index + 1, text)
        patched_text = "\n".join(manifest.lines)
        manifest_path.write_text(patched_text)
        if not checksum_path.is_file():
            raise fail(
                f"patched {manifest_path} but {checksum_path} is missing — "
                "cargo vendor output must carry .cargo-checksum.json for "
                "registry sources"
            )
        checksum = json.loads(checksum_path.read_text())
        files = checksum.setdefault("files", {})
        files["Cargo.toml"] = hashlib.sha256(patched_text.encode("utf-8")).hexdigest()
        checksum_path.write_text(
            json.dumps(checksum, separators=(",", ":"), ensure_ascii=False) + "\n"
        )
        self.patched += 1

    def _dep_outcome(self, manifest: Manifest, dep: dict):
        """Decide (action, url) for one dep entry; None = leave untouched."""
        if dep["inline"]:
            value_text = dep["value_text"]
            is_table = value_text.strip().startswith("{")
            if is_table:
                if not value_text.rstrip().endswith("}"):
                    raise fail(
                        "multi-line inline dependency tables are not "
                        f"supported: {manifest.package_name} {dep['key']}"
                    )
                if inline_table_get(value_text, "workspace") is not None:
                    return None
                if inline_table_get(value_text, "git") is not None:
                    return None
                if inline_table_get(value_text, "path") is not None:
                    return None
                if inline_table_get(value_text, "registry-index") is not None:
                    return None
                real_name = inline_table_get(value_text, "package") or dep["key"]
                req = inline_table_get(value_text, "version")
                existing_registry = inline_table_get(value_text, "registry")
                optional = inline_table_get(value_text, "optional") == "true"
            else:
                real_name = dep["key"]
                req = strip_quotes(value_text)
                existing_registry = None
                optional = False
        else:
            keys = dep["keys"]
            if "workspace" in keys or "git" in keys or "path" in keys:
                return None
            if "registry-index" in keys:
                return None
            real_name = strip_quotes(keys.get("package", dep["key"]))
            req = strip_quotes(keys["version"]) if keys.get("version") else None
            existing_registry = (
                strip_quotes(keys["registry"]) if "registry" in keys else None
            )
            optional = keys.get("optional") == "true"

        row, candidates = self.lock.lookup(real_name, req)
        if row is None:
            if candidates:
                # ambiguous version match: qualification only needs the
                # SOURCE; the unmodified lock still binds each usage to its
                # version, so a range spanning several rows of one registry
                # is unambiguous at the source level
                sources = {c["source"] for c in candidates}
                curated = {s for s in sources if s and s not in CRATES_IO_SOURCES}
                if len(curated) == 1 and len(sources) == 1:
                    return ("replace" if existing_registry else "insert", curated.pop())
                if not curated and not existing_registry:
                    # every candidate is crates.io: the default-registry belt
                    # plus the lock resolve this without patching
                    return None
                raise fail(
                    f"{manifest.package_name}: dep {dep['key']!r} "
                    f"(req {req!r}) matches lock rows "
                    f"{[c['version'] for c in candidates]} across sources "
                    f"{sorted(str(s or 'none') for s in sources)} — refusing "
                    "to guess"
                )
            if existing_registry:
                raise fail(
                    f"{manifest.package_name}: dep {dep['key']!r} "
                    f"(registry = {existing_registry!r}, req {req!r}) has no "
                    f"matching lock row; candidates: "
                    f"{[c['version'] for c in candidates]}"
                )
            if dep["kind"] == "dev-dependencies" or optional:
                self.note(
                    f"{manifest.package_name}: {dep['kind']} dep {real_name!r} "
                    f"(req {req!r}) not in lock — left unqualified (outside "
                    "resolve graph)"
                )
                return None
            raise fail(
                f"{manifest.package_name}: {dep['kind']} dep {real_name!r} "
                f"(req {req!r}) not found in Cargo.lock; candidates: "
                f"{[c['version'] for c in candidates]} — refusing to guess "
                "crates.io"
            )

        source = row["source"]
        if source is None or source in CRATES_IO_SOURCES:
            return None
        return ("replace" if existing_registry else "insert", source)

    def _patch_inline(self, dep: dict, action: str, url: str) -> str:
        value_text = dep["value_text"]
        if action == "replace":
            patched = re.sub(
                r"registry[ \t]*=[ \t]*\"[^\"]*\"",
                f'registry-index = "{url}"',
                value_text,
            )
            if patched == value_text:
                raise fail(f"could not normalize inline qualifier {value_text!r}")
            return patched
        if value_text.strip().startswith("{"):
            return inline_table_set(value_text, "registry-index", f'"{url}"')
        return "{ version = " + value_text + f', registry-index = "{url}"' + " }"


# ---------------------------------------------------------------------------
# config emission
# ---------------------------------------------------------------------------


def emit_config(lock: Lock, registries_from: Path | None, vendor_dir_var: str) -> str:
    lines: list[str] = []
    registries: dict = {}
    if registries_from is not None:
        with registries_from.open("rb") as fh:
            consumer = tomllib.load(fh)
        registries = consumer.get("registries", {})
    for name in sorted(registries):
        table = registries[name]
        if not isinstance(table, dict):
            raise fail(f"[registries.{name}] is not a table")
        lines.append(f"[registries.{name}]")
        for key in sorted(table):
            value = table[key]
            if isinstance(value, bool):
                rendered = "true" if value else "false"
            elif isinstance(value, (int, float)):
                rendered = str(value)
            elif isinstance(value, str):
                rendered = json.dumps(value)
            else:
                raise fail(
                    f"[registries.{name}].{key} has unsupported type "
                    f"{type(value).__name__}"
                )
            lines.append(f"{key} = {rendered}")
        lines.append("")

    for source in lock.sources():
        if source.startswith("git+"):
            url, _, fragment = source.partition("#")
            base, _, query = url.partition("?")
            lines.append(f'[source."{source}"]')
            lines.append(f"git = {json.dumps(base)}")
            for param in query.split("&"):
                key, _, value = param.partition("=")
                if key in ("branch", "tag", "rev"):
                    lines.append(f"{key} = {json.dumps(value)}")
            if fragment:
                lines.append(f"rev = {json.dumps(fragment)}")
        else:
            lines.append(f'[source."{source}"]')
            lines.append(f"registry = {json.dumps(source)}")
        lines.append('replace-with = "vendored-sources"')
        lines.append("")

    lines.append("[source.vendored-sources]")
    lines.append(f"directory = {json.dumps(vendor_dir_var)}")
    lines.append("")
    lines.append("[source.crates-io]")
    lines.append('replace-with = "vendored-sources"')
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# self-test
# ---------------------------------------------------------------------------

SELF_TEST_LOCK = """\
# This file is automatically @generated by Cargo.
version = 4

[[package]]
name = "scratch"
version = "0.1.0"

[[package]]
name = "alpha"
version = "1.2.3"
source = "sparse+https://rust.pkg.re/"
checksum = "aaaa"

[[package]]
name = "alpha"
version = "2.0.0"
source = "sparse+https://rust.pkg.re/"
checksum = "bbbb"

[[package]]
name = "beta"
version = "0.4.1+meta.7"
source = "sparse+https://other.example/reg/"
checksum = "cccc"

[[package]]
name = "gamma"
version = "5.0.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "dddd"

[[package]]
name = "wsa"
version = "0.52.0"
source = "sparse+https://rust.pkg.re/"
checksum = "ffff"

[[package]]
name = "wsa"
version = "0.61.2"
source = "sparse+https://rust.pkg.re/"
checksum = "abab"

[[package]]
name = "mix"
version = "1.0.0"
source = "sparse+https://rust.pkg.re/"
checksum = "cdcd"

[[package]]
name = "mix"
version = "2.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "efef"

[[package]]
name = "ioonly"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "1234"

[[package]]
name = "ioonly"
version = "2.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "5678"

[[package]]
name = "delta"
version = "0.1.0"
source = "sparse+https://rust.pkg.re/"
checksum = "1357"

[[package]]
name = "epsilon"
version = "0.1.0"
source = "sparse+https://rust.pkg.re/"
checksum = "2468"

[[package]]
name = "zeta"
version = "0.1.0"
source = "sparse+https://rust.pkg.re/"
checksum = "3579"

[[package]]
name = "qualified"
version = "1.0.0"
source = "sparse+https://rust.pkg.re/"
checksum = "eeee"
"""

SELF_TEST_ALPHA = """\
# THIS FILE IS AUTOMATICALLY GENERATED BY CARGO
[package]
name = "alpha"
version = "2.0.0"

[dependencies.beta]
version = "0.4"

[dependencies.gamma]
version = "5.0"

[dependencies.alpha]
version = "1"

[dev-dependencies.missing-dev]
version = "9"

[dependencies.optional-missing]
version = "3"
optional = true

[dependencies.qualified]
version = "1"
registry = "pkgre"

[dependencies.explicit]
version = "1"
registry-index = "sparse+https://rust.pkg.re/"

[dependencies.renamed]
package = "beta"
version = "0.4"

[target."cfg(unix)".dependencies.alpha]
version = "2"

[build-dependencies.gamma]
version = "5"

[workspace.dependencies]
alpha = "2"
"""

SELF_TEST_CRATES_IO = """\
[package]
name = "gamma"
version = "5.0.1"

[dependencies.alpha]
version = "2"
"""

SELF_TEST_BETA = """\
[package]
name = "beta"
version = "0.4.1+meta.7"

[dependencies.gamma]
version = "5"
"""


SELF_TEST_RANGE = """\
[package]
name = "delta"
version = "0.1.0"

[dependencies.wsa]
version = ">=0.52, <0.62"
"""

SELF_TEST_MIX = """\
[package]
name = "epsilon"
version = "0.1.0"

[dependencies.mix]
version = ">=1"
"""

SELF_TEST_IOONLY = """\
[package]
name = "zeta"
version = "0.1.0"

[dependencies.ioonly]
version = ">=1"
"""


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def self_test() -> int:
    failures: list[str] = []

    def check(name: str, condition: bool, detail: str = "") -> None:
        if not condition:
            failures.append(f"{name}: {detail}")

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        lock_path = _write(root / "Cargo.lock", SELF_TEST_LOCK)
        lock = Lock(lock_path)

        # --- patch semantics -------------------------------------------------
        vendor = root / "vendor"
        alpha = _write(vendor / "alpha-2.0.0" / "Cargo.toml", SELF_TEST_ALPHA)
        alpha_checksum = _write(
            vendor / "alpha-2.0.0" / ".cargo-checksum.json",
            json.dumps(
                {
                    "files": {
                        "Cargo.toml": hashlib.sha256(SELF_TEST_ALPHA.encode()).hexdigest(),
                        "src/lib.rs": "f" * 64,
                    },
                    "package": "aaaa",
                }
            ),
        )
        gamma = _write(vendor / "gamma-5.0.1" / "Cargo.toml", SELF_TEST_CRATES_IO)
        gamma_checksum_text = '{"files":{"Cargo.toml":"g"},"package":"dddd"}'
        gamma_checksum = _write(
            vendor / "gamma-5.0.1" / ".cargo-checksum.json", gamma_checksum_text
        )
        beta = _write(vendor / "beta-0.4.1+meta.7" / "Cargo.toml", SELF_TEST_BETA)
        beta_checksum_text = '{"files":{"Cargo.toml":"b"},"package":"bbbb"}'
        beta_checksum = _write(
            vendor / "beta-0.4.1+meta.7" / ".cargo-checksum.json", beta_checksum_text
        )

        patcher = Patcher(vendor, lock)
        patched_count = patcher.patch()
        check("patched-count", patched_count == 2, f"got {patched_count}")

        patched_alpha = alpha.read_text()
        pkgre = "sparse+https://rust.pkg.re/"
        other = "sparse+https://other.example/reg/"
        check(
            "longhand-insert",
            '[dependencies.beta]\nregistry-index = "%s"\nversion = "0.4"' % other
            in patched_alpha,
            patched_alpha,
        )
        check(
            "crates-io-left",
            '[dependencies.gamma]\nversion = "5.0"' in patched_alpha,
            patched_alpha,
        )
        check(
            "multi-version-caret-1",
            '[dependencies.alpha]\nregistry-index = "%s"\nversion = "1"' % pkgre
            in patched_alpha,
            patched_alpha,
        )
        check(
            "dev-missing-skipped",
            '[dev-dependencies.missing-dev]\nversion = "9"' in patched_alpha,
            patched_alpha,
        )
        check(
            "optional-missing-skipped",
            'optional-missing]\nversion = "3"\noptional = true' in patched_alpha,
            patched_alpha,
        )
        check(
            "name-form-normalized",
            '[dependencies.qualified]\nversion = "1"\nregistry-index = "%s"' % pkgre
            in patched_alpha,
            patched_alpha,
        )
        check(
            "existing-registry-index-untouched",
            '[dependencies.explicit]\nversion = "1"\nregistry-index = "'
            + pkgre
            + '"' in patched_alpha,
            patched_alpha,
        )
        check(
            "rename-lookup",
            '[dependencies.renamed]\nregistry-index = "%s"\npackage = "beta"' % other
            in patched_alpha,
            patched_alpha,
        )
        check(
            "target-longhand",
            '[target."cfg(unix)".dependencies.alpha]\nregistry-index = "%s"' % pkgre
            in patched_alpha,
            patched_alpha,
        )
        check(
            "build-dep-crates-io-left",
            '[build-dependencies.gamma]\nversion = "5"' in patched_alpha,
            patched_alpha,
        )
        check(
            "workspace-deps-untouched",
            '[workspace.dependencies]\nalpha = "2"' in patched_alpha,
            patched_alpha,
        )

        checksum = json.loads(alpha_checksum.read_text())
        check(
            "checksum-files-updated",
            checksum["files"]["Cargo.toml"]
            == hashlib.sha256(patched_alpha.encode()).hexdigest(),
            checksum["files"]["Cargo.toml"],
        )
        check("checksum-package-untouched", checksum["package"] == "aaaa")
        check(
            "checksum-other-files-kept",
            checksum["files"].get("src/lib.rs") == "f" * 64,
        )

        # gamma is a crates.io-sourced vendored crate whose dep alpha-2
        # resolves to the pkgre copy — its manifest must still be patched.
        gamma_text = gamma.read_text()
        check(
            "crates-io-crate-dep-patched",
            '[dependencies.alpha]\nregistry-index = "%s"\nversion = "2"' % pkgre
            in gamma_text,
            gamma_text,
        )
        gamma_checksum_now = json.loads(gamma_checksum.read_text())
        check(
            "gamma-checksum-updated",
            gamma_checksum_now["files"]["Cargo.toml"]
            == hashlib.sha256(gamma_text.encode()).hexdigest(),
            gamma_checksum_now["files"]["Cargo.toml"],
        )
        check("gamma-checksum-package-untouched", gamma_checksum_now["package"] == "dddd")

        # beta (build-metadata version) matches gamma 5.0.1 → crates.io → untouched
        beta_text = beta.read_text()
        check(
            "build-metadata-version-parsed",
            '[dependencies.gamma]\nversion = "5"' in beta_text
            and "registry-index" not in beta_text,
            beta_text,
        )
        check("unpatched-crate-byte-identical", beta_text == SELF_TEST_BETA)
        check(
            "unpatched-checksum-untouched",
            beta_checksum.read_text() == beta_checksum_text,
        )

        # --- hard failure: normal dep missing from lock -----------------------
        hard_vendor = root / "hard-vendor"
        _write(
            hard_vendor / "gamma-5.0.1" / "Cargo.toml",
            '[package]\nname = "gamma"\nversion = "5.0.1"\n\n'
            '[dependencies.does-not-exist]\nversion = "1"\n',
        )
        _write(
            hard_vendor / "gamma-5.0.1" / ".cargo-checksum.json",
            '{"files":{},"package":"dddd"}',
        )
        try:
            Patcher(hard_vendor, lock).patch()
            check("hard-fail-missing", False, "no exception raised")
        except VendorError as error:
            check(
                "hard-fail-missing",
                "does-not-exist" in str(error) and "refusing to guess" in str(error),
                str(error),
            )

        # --- hard failure: name-form registry dep missing from lock ------------
        hard_reg_vendor = root / "hard-reg-vendor"
        _write(
            hard_reg_vendor / "gamma-5.0.1" / "Cargo.toml",
            '[package]\nname = "gamma"\nversion = "5.0.1"\n\n'
            '[dependencies.absent-qualified]\nversion = "1"\n'
            'registry = "pkgre"\n',
        )
        _write(
            hard_reg_vendor / "gamma-5.0.1" / ".cargo-checksum.json",
            '{"files":{},"package":"dddd"}',
        )
        try:
            Patcher(hard_reg_vendor, lock).patch()
            check("hard-fail-name-form", False, "no exception raised")
        except VendorError as error:
            check(
                "hard-fail-name-form",
                "absent-qualified" in str(error) and "has no matching lock row" in str(error),
                str(error),
            )

        # --- ambiguous range across two rows of one source qualifies ----------
        range_vendor = root / "range-vendor"
        delta = _write(range_vendor / "delta-0.1.0" / "Cargo.toml", SELF_TEST_RANGE)
        _write(
            range_vendor / "delta-0.1.0" / ".cargo-checksum.json",
            '{"files":{},"package":"9999"}',
        )
        Patcher(range_vendor, lock).patch()
        delta_text = delta.read_text()
        check(
            "range-two-rows-one-source",
            '[dependencies.wsa]\nregistry-index = "%s"\nversion = ">=0.52, <0.62"'
            % pkgre in delta_text,
            delta_text,
        )

        # --- ambiguous range across sources refused ---------------------------
        mix_vendor = root / "mix-vendor"
        _write(mix_vendor / "epsilon-0.1.0" / "Cargo.toml", SELF_TEST_MIX)
        _write(
            mix_vendor / "epsilon-0.1.0" / ".cargo-checksum.json",
            '{"files":{},"package":"8888"}',
        )
        try:
            Patcher(mix_vendor, lock).patch()
            check("hard-fail-mixed-sources", False, "no exception raised")
        except VendorError as error:
            check(
                "hard-fail-mixed-sources",
                "across sources" in str(error),
                str(error),
            )

        # --- ambiguous all-crates.io range left to the belt -------------------
        io_vendor = root / "io-vendor"
        zeta = _write(io_vendor / "zeta-0.1.0" / "Cargo.toml", SELF_TEST_IOONLY)
        _write(
            io_vendor / "zeta-0.1.0" / ".cargo-checksum.json",
            '{"files":{},"package":"7777"}',
        )
        Patcher(io_vendor, lock).patch()
        check(
            "range-all-crates-io-unpatched",
            zeta.read_text() == SELF_TEST_IOONLY,
            zeta.read_text(),
        )

        # --- loud failure: vendored crate absent from lock ---------------------
        rogue = root / "rogue-vendor"
        _write(
            rogue / "ghost-9.9.9" / "Cargo.toml",
            '[package]\nname = "ghost"\nversion = "9.9.9"\n',
        )
        _write(rogue / "ghost-9.9.9" / ".cargo-checksum.json", '{"files":{},"package":"x"}')
        try:
            Patcher(rogue, lock).patch()
            check("hard-fail-rogue-crate", False, "no exception raised")
        except VendorError as error:
            check("hard-fail-rogue-crate", "not in the Cargo.lock" in str(error), str(error))

        # --- config emission ----------------------------------------------------
        consumer_config = _write(
            root / "consumer-config.toml",
            '[registries]\npkgre = { index = "sparse+https://rust.pkg.re/" }\n\n'
            '[source.crates-io]\nreplace-with = "ignored"\n',
        )
        emitted = emit_config(lock, consumer_config, VENDOR_DIR_PLACEHOLDER)
        check(
            "emit-registries",
            '[registries.pkgre]\nindex = "sparse+https://rust.pkg.re/"' in emitted,
            emitted,
        )
        check(
            "emit-source-pkgre",
            '[source."sparse+https://rust.pkg.re/"]\n'
            'registry = "sparse+https://rust.pkg.re/"\n'
            'replace-with = "vendored-sources"' in emitted,
            emitted,
        )
        check(
            "emit-source-other",
            '[source."sparse+https://other.example/reg/"]' in emitted,
            emitted,
        )
        check(
            "emit-no-crates-io-source-entry",
            "index.crates.io" not in emitted
            and "rust-lang/crates.io-index" not in emitted,
            emitted,
        )
        check(
            "emit-belt",
            '[source.crates-io]\nreplace-with = "vendored-sources"' in emitted,
        )
        check("emit-vendor-dir", 'directory = "@vendor@"' in emitted)
        check("emit-no-consumer-source", "ignored" not in emitted)

    if failures:
        for failure in failures:
            print(f"pkgre-vendor self-test FAIL: {failure}", file=sys.stderr)
        return 1
    print("pkgre-vendor self-test: ok")
    return 0


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------


def main(argv: list[str]) -> int:
    args = argv[1:]
    if not args:
        print(__doc__, file=sys.stderr)
        return 2
    if args[0] == "--self-test":
        return self_test()
    if args[0] == "--emit-config":
        rest = args[1:]
        lock_path: Path | None = None
        registries_from: Path | None = None
        vendor_dir_var = VENDOR_DIR_PLACEHOLDER
        index = 0
        while index < len(rest):
            arg = rest[index]
            if arg == "--registries-from":
                index += 1
                registries_from = Path(rest[index])
            elif arg == "--vendor-dir-var":
                index += 1
                vendor_dir_var = rest[index]
            else:
                lock_path = Path(arg)
            index += 1
        if lock_path is None:
            print(
                "pkgre-vendor: --emit-config requires a Cargo.lock path",
                file=sys.stderr,
            )
            return 2
        print(emit_config(Lock(lock_path), registries_from, vendor_dir_var), end="")
        return 0
    if args[0].startswith("-"):
        print(f"pkgre-vendor: unknown option {args[0]}", file=sys.stderr)
        return 2
    if len(args) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    vendor_dir, lock_path = Path(args[0]), Path(args[1])
    patcher = Patcher(vendor_dir, Lock(lock_path))
    patched = patcher.patch()
    print(
        f"pkgre-vendor: scanned {patcher.scanned} crates, "
        f"patched {patched} manifests ({len(patcher.notes)} notes)"
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except VendorError as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
