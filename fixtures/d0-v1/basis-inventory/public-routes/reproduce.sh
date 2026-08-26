#!/usr/bin/env bash
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; work="$here/.reproduce"
rm -rf "$work";mkdir -p "$work/pkgre" "$work/pkgre-rust" "$work/pkgre-js"
git -C /home/dev0/repos/pkgre archive 066293df21743cbf41fb571a38f2bb94059e7274 | tar -x -C "$work/pkgre"
git -C /home/dev0/repos/pkgre-rust archive f9b5ffaf14c2b9278c9d4828dc4e8b9ef8f6518b | tar -x -C "$work/pkgre-rust"
git -C /home/dev0/repos/pkgre-js archive f43bd58bd3d4e36f8b3f4df3c002735c977acd17 | tar -x -C "$work/pkgre-js"
(cd "$work/pkgre";nix develop -c cargo run --quiet --manifest-path rust/Cargo.toml -- render "$work/pkgre-rust/registry" "$work/rust-render";nix develop -c cargo run --quiet --manifest-path rust/Cargo.toml -- verify "$work/pkgre-rust/registry" "$work/rust-render")
args=();[[ "${1:-}" == --probe ]]&&args+=(--probe)
"$here/build_inventory.py" --out "$here" --rust-render "$work/rust-render" --pkgre-repo /home/dev0/repos/pkgre --rust-repo /home/dev0/repos/pkgre-rust --js-repo /home/dev0/repos/pkgre-js "${args[@]}"
rm -rf "$work"
