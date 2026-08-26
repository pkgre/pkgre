#!/usr/bin/env python3
"""Deterministically validate distilled pkgre D0 evidence;stdlib only;no network/subprocess."""
import hashlib,json,re,sys,tomllib
from pathlib import Path,PurePosixPath
ROOT=Path(__file__).resolve().parent
EXPECTED_SOURCE="sparse+https://rust.pkg.re/"
checks=[]
def ok(name,details=None):checks.append({"name":name,"status":"pass",**({"details":details} if details is not None else {})})
def require(condition,message):
 if not condition:raise AssertionError(message)
def load_json(rel):return json.loads((ROOT/rel).read_text())
def sha256(path):
 h=hashlib.sha256()
 with path.open("rb") as f:
  for chunk in iter(lambda:f.read(1<<20),b""):h.update(chunk)
 return h.hexdigest()
def fixed_files():return sorted((p for p in ROOT.rglob("*") if p.is_file() and p.name!="SHA256SUMS"),key=lambda p:p.relative_to(ROOT).as_posix())
def verify_existing_sums():
 p=ROOT/"SHA256SUMS"
 if not p.exists():return
 rows=p.read_text().splitlines();expected={}
 for line in rows:
  m=re.fullmatch(r"([0-9a-f]{64})  (.+)",line);require(m is not None,f"invalid SHA256SUMS row:{line!r}");require(m.group(2) not in expected,f"duplicate SHA256SUMS path:{m.group(2)}");expected[m.group(2)]=m.group(1)
 actual={p.relative_to(ROOT).as_posix():sha256(p) for p in fixed_files()}
 require(expected==actual,"pre-existing SHA256SUMS mismatch")
verify_existing_sums();ok("preexisting_sha256sums_if_present")
# Stabilize the generated file set before counts/scans;final content replaces this placeholder.
(ROOT/"validation.json").write_text("{}\n")
# Parse every JSON artifact currently present.
json_paths=sorted(p.relative_to(ROOT).as_posix() for p in ROOT.rglob("*.json"))
for rel in json_paths:load_json(rel)
ok("all_json_parse",{"file_count":len(json_paths)})
inv=load_json("inventory.json");require(inv["evidence_schema"]=="pkgre-d0-toolchain-closure-v1","inventory schema")
commit=(ROOT/"logs/commit").read_text().strip();require(re.fullmatch(r"[0-9a-f]{40}",commit) is not None,"commit format");require(commit==inv["implementation_basis"]["git_commit"],"commit mismatch");require(commit.startswith(inv["implementation_basis"]["short_commit"]),"short commit mismatch")
tar_line=(ROOT/"logs/source.tar.sha256").read_text().strip();require(tar_line.split()[0]==inv["implementation_basis"]["source_archive"]["sha256"],"source tar hash reference")
ok("implementation_basis",{"commit":commit,"source_tar_sha256":tar_line.split()[0]})
# Lock/pin/config versions.
flake=load_json("config/flake.lock");require(flake["version"]==inv["flake_pins"]["lock_version"]==7,"flake lock version")
for key in ("nixpkgs","rust-overlay"):
 locked=flake["nodes"][key]["locked"];pin=inv["flake_pins"][key]
 for field in ("owner","repo","rev","narHash","lastModified"):require(locked[field]==pin[field],f"flake pin {key}.{field}")
npm=load_json("config/package-lock.json");require(npm["lockfileVersion"]==inv["lock_and_schema_versions"]["npm_lockfile"]==3,"npm lock version")
package=load_json("config/package.json");require(package["engines"]=={"node":">=24.15.0","npm":">=12.0.2"},"package engine minimums");require(package["packageManager"]=="npm@12.0.2","package manager")
rust_toolchain=(ROOT/"config/rust-toolchain.toml").read_text();require('channel = "1.95.0"' in rust_toolchain and 'components = ["clippy", "rustfmt"]' in rust_toolchain,"Rust toolchain config")
cargo_cfg=(ROOT/"config/cargo-config.toml").read_text();require(f'index = "{EXPECTED_SOURCE}"' in cargo_cfg and 'default = "pkgre"' in cargo_cfg and 'replace-with = "disabled-crates-io"' in cargo_cfg and 'directory = "vendor/empty"' in cargo_cfg,"Cargo registry config");ok("lock_pins_versions_and_registry_config")
# Tool path evidence+direct source pins+explicit Deno alias.
paths=load_json("logs/toolchain-paths.json");tool_by_id={x["id"]:x for x in inv["tools"]};path_map={"git-flake":"git","rust-toolchain":"rustToolchain","node-indexer":"nodejs24","node-minimum":"nodeMinimum","node-current":"nodeCurrent","bun-minimum":"bunMinimum","bun-current":"bunCurrent","deno-minimum":"denoMinimum","deno-current":"denoCurrent","pkgre-rust":"rustPackage","pkgre-proxy":"proxyPackage","pkgre-js":"jsPackage","dev-shell":"devShell"}
for tid,key in path_map.items():
 require(tool_by_id[tid]["drv_path"]==paths[key]["drvPath"],f"drv {tid}");require(tool_by_id[tid]["output_path"]==paths[key]["outputPath"],f"out {tid}")
compat=(ROOT/"config/js-compatibility-clients.nix").read_text()
fixed_sources=[]
for t in inv["tools"]:
 sources=t["source"] if isinstance(t["source"],list) else [t["source"]]
 for source in sources:
  if source and source.get("kind")=="fixed_output_archive":
   url=source["url"]
   if "nodejs.org" in url:require('https://nodejs.org/dist/v${nodeVersion}/node-v${nodeVersion}-linux-${target.nodeArch}.tar.xz' in compat and url.split('/v',1)[1].split('/',1)[0] in compat and 'nodeArch = "x64";' in compat,f"source URL template absent:{t['id']}")
   elif "registry.npmjs.org" in url:require('https://registry.npmjs.org/npm/-/npm-${npmVersion}.tgz' in compat and 'npmVersion = "12.0.2";' in compat,f"source URL template absent:{t['id']}")
   elif "oven-sh/bun" in url:require('https://github.com/oven-sh/bun/releases/download/bun-v${version}/bun-linux-${target.bunArch}.zip' in compat and url.split('bun-v',1)[1].split('/',1)[0] in compat and 'bunArch = "x64";' in compat,f"source URL template absent:{t['id']}")
   elif "denoland/deno" in url:require('https://github.com/denoland/deno/releases/download/v${version}/deno-${target.denoArch}-unknown-linux-gnu.zip' in compat and url.split('/v',1)[1].split('/',1)[0] in compat and 'denoArch = "x86_64";' in compat,f"source URL template absent:{t['id']}")
   else:raise AssertionError(f"unknown fixed source URL:{url}")
   require(source["hash_sri_sha256"] in compat,f"source hash absent from config:{t['id']}");fixed_sources.append((source["url"],source["hash_sri_sha256"]))
dmin=tool_by_id["deno-minimum"];dcur=tool_by_id["deno-current"]
for tid in ("node-minimum","node-current"):
 t=tool_by_id[tid];out=t["output_path"];require(t["effective_executables"]=={"node":f"{out}/bin/node","npm":f"{out}/bin/npm"},f"effective Node/npm executables:{tid}")
require(dmin["drv_path"]==dcur["drv_path"] and dmin["output_path"]==dcur["output_path"],"Deno path alias");require(dmin["aliasing"]["minimum_equals_current"] and dcur["aliasing"]["minimum_equals_current"],"Deno alias flag");require("denoCurrent = denoMinimum;" in compat,"Deno source alias")
ok("tool_paths_sources_wrappers_and_deno_alias",{"tool_count":len(inv["tools"]),"fixed_source_rows":len(fixed_sources),"unique_fixed_sources":len(set(fixed_sources))})
# Complete Cargo closure reproduced from metadata resolve graph and matched against summary+lock.
metadata=load_json("closure/cargo-metadata.json");summary=load_json("closure/cargo-closure-summary.json")
lock=tomllib.loads((ROOT/"closure/Cargo.lock").read_text());require(lock["version"]==inv["lock_and_schema_versions"]["cargo_lock"]==4,"Cargo lock version")
packages={p["id"]:p for p in metadata["packages"]};nodes={n["id"]:n for n in metadata["resolve"]["nodes"]};require(set(packages)==set(nodes),"metadata package/node identity")
require(len(packages)==len(lock["package"])==summary["lock_package_count"]==174,"Cargo package counts")
meta_sources=[p["source"] for p in packages.values()];lock_sources=[p.get("source") for p in lock["package"]]
require(meta_sources.count(EXPECTED_SOURCE)==lock_sources.count(EXPECTED_SOURCE)==172,"third-party source counts");require(meta_sources.count(None)==lock_sources.count(None)==2,"workspace source-less counts");require(all(x in (None,EXPECTED_SOURCE) for x in meta_sources+lock_sources),"unexpected Cargo source")
lock_rows=sorted((p["name"],p["version"],p.get("source")) for p in lock["package"]);meta_rows=sorted((p["name"],p["version"],p["source"]) for p in packages.values());require(lock_rows==meta_rows,"Cargo lock/metadata package rows")
union=set();root_metrics={}
for root_name,row in summary["roots"].items():
 require(row["root_id"] in nodes,f"root id:{root_name}");seen=set();stack=[row["root_id"]]
 while stack:
  node_id=stack.pop()
  if node_id in seen:continue
  seen.add(node_id);stack.extend(nodes[node_id]["dependencies"])
 union|=seen
 reproduced=sorted((packages[i]["name"],packages[i]["version"],packages[i]["source"],sorted(nodes[i]["features"])) for i in seen)
 recorded=sorted((p["name"],p["version"],p["source"],p["features"]) for p in row["packages"])
 require(reproduced==recorded,f"closure row equivalence:{root_name}")
 metrics=(len(seen),sum(packages[i]["source"] is not None for i in seen),sum(len(nodes[i]["features"]) for i in seen))
 require(metrics==(row["package_count_including_root"],row["third_party_package_count"],row["selected_feature_pair_count"]),f"closure metrics:{root_name}")
 root_metrics[root_name]={"packages_including_root":metrics[0],"third_party":metrics[1],"selected_package_feature_pairs":metrics[2]}
require(union==set(packages),"workspace union identity");union_metrics=(len(union),sum(packages[i]["source"] is not None for i in union),sum(len(nodes[i]["features"]) for i in union));u=summary["workspace_union"];require(union_metrics==(u["package_count_including_two_roots"],u["third_party_package_count"],u["selected_feature_pair_count"])==(174,172,347),"union metrics")
require(summary["workspace_members"]==["pkgre-rust","pkgre-proxy"],"summary member names");require(set(metadata["workspace_members"])=={summary["roots"][x]["root_id"] for x in summary["roots"]},"metadata workspace roots")
ok("cargo_complete_closure_and_source_proof",{"roots":root_metrics,"union":{"packages_including_roots":174,"third_party":172,"selected_package_feature_pairs":347},"required_source":EXPECTED_SOURCE})
# Machine result logs and metrics.
result_time={"nix_build":"toolchain-build.time.json","flake_check":"flake-check.time.json","rust_workspace_test_clean":"rust-workspace-test-clean.time.json","rust_workspace_test_initial":"rust-workspace-test.time.json","js_node_test":"js-node-test.time.json"}
for key,file in result_time.items():
 t=load_json("logs/"+file);r=inv["results"][key];require(t["exit"]==r["exit"],f"exit:{key}");require(t["elapsed_seconds"]==r["elapsed_seconds"],f"elapsed:{key}");rss=t.get("ru_maxrss_kib",t.get("nix_client_ru_maxrss_kib"));expected=r.get("ru_maxrss_kib",r.get("nix_client_ru_maxrss_kib"));require(rss==expected,f"rss:{key}")
flake_log=(ROOT/"logs/flake-check.stderr").read_text();require("running 0 flake checks..." in flake_log and "all checks passed!" in flake_log and "aarch64-linux" in flake_log,"flake log result")
rust_log=(ROOT/"logs/rust-workspace-test-clean.stdout").read_text();pass_groups=[int(x) for x in re.findall(r"test result: ok\. (\d+) passed; 0 failed;",rust_log)];require(pass_groups==inv["results"]["rust_workspace_test_clean"]["summary_group_pass_counts"],"Rust pass groups");require(sum(pass_groups)==173,"Rust pass total")
js_log=(ROOT/"logs/js-node-test.stdout").read_text();require(re.search(r"ℹ tests 47\n.*ℹ pass 47\nℹ fail 0",js_log,re.S) is not None,"JS pass summary")
excerpt=(ROOT/"logs/rust-workspace-test-initial-failure-excerpt.txt").read_text();require("cargo_builds_locked_with_clean_cache_from_root_registry ... FAILED" in excerpt and 'No such file or directory' in excerpt and "rust-test-target" in excerpt,"bounded diagnostic excerpt")
ok("build_and_test_result_consistency",{"rust_pass_total":173,"js_pass_total":47})
# Performance timing and copied output inventories.
ops={x["id"]:x for x in inv["performance"]["operations"]}
for op in ops.values():
 t=load_json(op["log"]);require(t["exit"]==0,f"performance exit:{op['id']}");require(t["elapsed_seconds"]==op["elapsed_seconds"],f"performance elapsed:{op['id']}");require(t["ru_maxrss_kib"]==op["ru_maxrss_kib"],f"performance rss:{op['id']}")
 if op["output"]:
  output=op["output"];p=ROOT/output["inventory_copy"];require(sha256(p)==output["inventory_sha256"],f"inventory hash:{op['id']}")
  count=0;total=0;seen=set()
  for line in p.read_text().splitlines():
   m=re.fullmatch(r"([0-9a-f]{64})  ([0-9]+)  (.+)",line);require(m is not None,f"inventory row:{line!r}");rel=m.group(3);q=PurePosixPath(rel);require(not q.is_absolute() and ".." not in q.parts and rel not in seen,f"unsafe/duplicate inventory path:{rel}");seen.add(rel);count+=1;total+=int(m.group(2))
  require(count==output["file_count"] and total==output["byte_count"],f"inventory totals:{op['id']}")
require("packages=747" in (ROOT/"logs/rust-check.stderr").read_text(),"Rust check package log");require("all generated artifact verifications and JS canonical-tree diffs passed" in (ROOT/"logs/artifact-verification.stdout").read_text(),"artifact verification log")
ok("performance_records_and_output_inventories",{"operation_count":len(ops)})
# Bounded secret scan over every evidence file except generated checksum manifest;known hash material is not a credential.
secret_patterns=[re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),re.compile(rb"AKIA[0-9A-Z]{16}"),re.compile(rb"gh[pousr]_[A-Za-z0-9]{30,}"),re.compile(rb"github_pat_[A-Za-z0-9_]{40,}"),re.compile(rb"(?i)(?:password|passwd|api[_-]?key|access[_-]?token|secret[_-]?key)\s*[:=]\s*['\"]?[A-Za-z0-9+/=_-]{12,}")]
findings=[]
for p in fixed_files():
 data=p.read_bytes()
 for pattern in secret_patterns:
  if pattern.search(data):findings.append({"path":p.relative_to(ROOT).as_posix(),"pattern":pattern.pattern.decode(errors="replace")})
require(not findings,f"potential secrets:{findings}");ok("secret_scan",{"files_scanned":len(fixed_files()),"findings":0,"pattern_classes":len(secret_patterns)})
report=(ROOT/"REPORT.md").read_text();require(commit in report and EXPECTED_SOURCE in report,"report basis");require("Direct upstream archive URL/hash is absent" in report,"report direct source absence");require(any(row["id"]=="direct-source-provenance" for row in inv["blockers"]),"inventory direct source blocker")
ok("report_basis_consistency")
# Deterministic validation output,then complete checksum manifest excluding only itself (self-hashing is impossible).
validation={"schema":"pkgre-d0-validation-v1","status":"pass","check_count":len(checks),"checks":checks,"notes":["stdlib-only;no network or subprocess","SHA256SUMS covers every regular file except SHA256SUMS itself","rendered trees and source archive are referenced rather than copied;their original verification is provenance-log evidence"]}
(ROOT/"validation.json").write_text(json.dumps(validation,indent=2,sort_keys=True)+"\n")
# Parse and scan the final generated JSON too (the earlier scan used its deterministic placeholder).
json.loads((ROOT/"validation.json").read_text())
final_validation_bytes=(ROOT/"validation.json").read_bytes()
require(not any(pattern.search(final_validation_bytes) for pattern in secret_patterns),"potential secret in final validation.json")
rows=[f"{sha256(p)}  {p.relative_to(ROOT).as_posix()}" for p in fixed_files()]
(ROOT/"SHA256SUMS").write_text("\n".join(rows)+"\n")
# Immediate generated-manifest check.
for line in rows:
 digest,rel=line.split("  ",1);require(sha256(ROOT/rel)==digest,f"generated manifest:{rel}")
print(json.dumps({"status":"pass","checks":len(checks),"hashed_files":len(rows)},sort_keys=True))
