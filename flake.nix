{
  description = "Declarative curated package registry tooling";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    rust-overlay.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
      ...
    }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ rust-overlay.overlays.default ];
          };
          rustToolchain = pkgs.rust-bin.stable."1.95.0".default.override {
            extensions = [
              "clippy"
              "rustfmt"
            ];
          };
          rustPlatform = pkgs.makeRustPlatform {
            cargo = rustToolchain;
            rustc = rustToolchain;
          };
          cargoDepsSrc = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [
              ./.cargo/config.toml
              ./Cargo.lock
              ./Cargo.toml
              ./rust
            ];
          };
          pkgreCargoDeps = self.lib.${system}.rust.cargoDeps {
            src = cargoDepsSrc;
            cargoHash = "sha256-RBh+tpSZcPmc2+65z93ai6gkUzlqepyP94Ebpm+OQS0=";
            name = "pkgre-rust-cargo-deps";
          };
          source = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [
              ./Cargo.lock
              ./Cargo.toml
              ./fixtures/dynamic-registry-v1
              ./fixtures/redirect-marker-v1
              ./js/package.json
              ./nix/js-compatibility-clients.nix
              ./rust
              ./rust-toolchain.toml
            ];
          };
          mkRustPackage =
            {
              packageDirectory,
              description,
              mainProgram,
              nativeCheckInputs ? [ ],
              runtimeInputs ? [ ],
            }:
            let
              manifest = builtins.fromTOML (builtins.readFile ./${packageDirectory}/Cargo.toml);
              packageName = manifest.package.name;
            in
            rustPlatform.buildRustPackage {
              pname = packageName;
              inherit (manifest.package) version;
              src = source;
              nativeBuildInputs = pkgs.lib.optionals (runtimeInputs != [ ]) [ pkgs.makeWrapper ];
              postInstall = pkgs.lib.optionalString (runtimeInputs != [ ]) ''
                wrapProgram "$out/bin/${mainProgram}" \
                  --prefix PATH : ${pkgs.lib.makeBinPath runtimeInputs}
              '';
              cargoDeps = pkgreCargoDeps;
              inherit nativeCheckInputs;
              cargoBuildFlags = [
                "--package"
                packageName
                "--locked"
              ];
              PKGRE_CARGO = "${rustToolchain}/bin/cargo";
              doCheck = true;
              checkPhase = ''
                runHook preCheck
                cargo test --package ${packageName} --frozen
                cargo clippy --package ${packageName} --all-targets --frozen -- -D warnings
                runHook postCheck
              '';
              meta = {
                inherit description mainProgram;
                homepage = "https://github.com/pkgre/pkgre";
                license = pkgs.lib.licenses.asl20;
              };
            };
          rustIndexer = mkRustPackage {
            packageDirectory = "rust";
            description = "Declarative reconciler and renderer for curated Cargo sparse registries";
            mainProgram = "pkgre-rust";
            nativeCheckInputs = [
              pkgs.git
              pkgs.gnutar
            ];
          };
          rustServe = mkRustPackage {
            packageDirectory = "rust/serve";
            description = "Immutable catalog snapshot serving origin for dynamic pkgre registries";
            mainProgram = "pkgre-rust-serve";
            nativeCheckInputs = [
              pkgs.git
              pkgs.gnutar
            ];
            runtimeInputs = [
              pkgs.git
              pkgs.gnutar
            ];
          };
          jsCompatibilityClients = import ./nix/js-compatibility-clients.nix { inherit pkgs system; };
          jsManifest = builtins.fromJSON (builtins.readFile ./js/package.json);
          jsSource = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [
              ./fixtures/dynamic-registry-v1
              ./fixtures/redirect-marker-v1
              ./js
              ./nix/js-compatibility-clients.nix
            ];
          };
          pkgreJs = pkgs.stdenvNoCC.mkDerivation {
            pname = jsManifest.name;
            inherit (jsManifest) version;
            src = jsSource;
            nativeBuildInputs = [ pkgs.makeWrapper ];
            nativeCheckInputs = [
              pkgs.git
              pkgs.nodejs_24
            ];
            dontConfigure = true;
            dontBuild = true;
            doCheck = true;
            checkPhase = ''
              runHook preCheck
              node --test js/test/*.test.js
              runHook postCheck
            '';
            installPhase = ''
              runHook preInstall
              mkdir -p "$out/bin" "$out/lib/pkgre-js"
              cp js/package.json js/package-lock.json "$out/lib/pkgre-js/"
              cp -R js/src "$out/lib/pkgre-js/src"
              makeWrapper ${pkgs.nodejs_24}/bin/node "$out/bin/pkgre-js" \
                --add-flags "$out/lib/pkgre-js/src/main.js"
              makeWrapper ${pkgs.nodejs_24}/bin/node "$out/bin/pkgre-js-serve" \
                --add-flags "$out/lib/pkgre-js/src/serve/main.js" \
                --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.git ]}
              runHook postInstall
            '';
            meta = {
              description = "Deterministic indexer for the curated js.pkg.re registry";
              mainProgram = "pkgre-js";
              homepage = "https://github.com/pkgre/pkgre";
              license = pkgs.lib.licenses.asl20;
            };
          };
        in
        {
          default = rustIndexer;
          rust = rustIndexer;
          indexer = rustIndexer;
          js = pkgreJs;
          js-client-node-minimum = jsCompatibilityClients.nodeMinimum;
          js-client-node-current = jsCompatibilityClients.nodeCurrent;
          js-client-bun-minimum = jsCompatibilityClients.bunMinimum;
          js-client-bun-current = jsCompatibilityClients.bunCurrent;
          js-client-deno-minimum = jsCompatibilityClients.denoMinimum;
          js-client-deno-current = jsCompatibilityClients.denoCurrent;
          serve = rustServe;
        }
      );

      checks = forAllSystems (
        system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ rust-overlay.overlays.default ];
          };
          rustToolchain = pkgs.rust-bin.stable."1.95.0".default.override {
            extensions = [ "rustfmt" ];
          };
          jsCompatibilitySource = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = ./js;
          };
          jsCompatibilityNode = self.packages.${system}.js-client-node-minimum;
          mkJsCompatibilityCheck =
            {
              name,
              client,
              package,
              executable,
            }:
            pkgs.runCommand "pkgre-js-compatibility-${name}" { nativeBuildInputs = [ package ]; } ''
              cp -R ${jsCompatibilitySource} source
              chmod -R u+w source
              cd source
              ${jsCompatibilityNode}/bin/node js/compatibility/fixture.js ${client} ${package}/bin/${executable}
              touch "$out"
            '';
          source = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [
              ./Cargo.lock
              ./Cargo.toml
              ./fixtures/dynamic-registry-v1
              ./fixtures/redirect-marker-v1
              ./js/package.json
              ./nix/js-compatibility-clients.nix
              ./rust
              ./rust-toolchain.toml
            ];
          };
        in
        {
          build-and-test = self.packages.${system}.rust;
          js = self.packages.${system}.js;
          js-compatibility-node-minimum = mkJsCompatibilityCheck {
            name = "node-minimum";
            client = "npm";
            package = self.packages.${system}.js-client-node-minimum;
            executable = "npm";
          };
          js-compatibility-node-current = mkJsCompatibilityCheck {
            name = "node-current";
            client = "npm";
            package = self.packages.${system}.js-client-node-current;
            executable = "npm";
          };
          js-compatibility-bun-minimum = mkJsCompatibilityCheck {
            name = "bun-minimum";
            client = "bun";
            package = self.packages.${system}.js-client-bun-minimum;
            executable = "bun";
          };
          js-compatibility-bun-current = mkJsCompatibilityCheck {
            name = "bun-current";
            client = "bun";
            package = self.packages.${system}.js-client-bun-current;
            executable = "bun";
          };
          js-compatibility-deno-minimum = mkJsCompatibilityCheck {
            name = "deno-minimum";
            client = "deno";
            package = self.packages.${system}.js-client-deno-minimum;
            executable = "deno";
          };
          js-compatibility-deno-current = mkJsCompatibilityCheck {
            name = "deno-current";
            client = "deno";
            package = self.packages.${system}.js-client-deno-current;
            executable = "deno";
          };
          serve = self.packages.${system}.serve;
          pkgre-vendor-script-self-test =
            pkgs.runCommand "pkgre-vendor-script-self-test" { nativeBuildInputs = [ pkgs.python3 ]; }
              ''
                python3 ${./nix/pkgre-vendor.py} --self-test
                touch "$out"
              '';
          pkgre-vendor-integration =
            let
              pkgreVendorScript = ./nix/pkgre-vendor.py;
            in
            pkgs.stdenvNoCC.mkDerivation {
              name = "pkgre-vendor-integration";
              dontUnpack = true;
              nativeBuildInputs = [
                rustToolchain
                pkgs.cacert
                pkgs.python3
              ];
              impureEnvVars = pkgs.lib.fetchers.proxyImpureEnvVars;
              outputHashAlgo = "sha256";
              outputHash = "sha256-AjEXQvkohr7q4wUYvnpsGzFllDC4m3IjSAYg9gR0UPo=";
              outputHashMode = "recursive";
              SSL_CERT_FILE = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";
              CARGO_HTTP_CA_BUNDLE = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";
              buildPhase = ''
                runHook preBuild
                cp -R ${./fixtures/vendor-scratch} fixture
                chmod -R u+w fixture
                cd fixture
                mkdir -p .cargo
                cat > .cargo/config.toml <<'EOF'
                [registries]
                pkgre = { index = "sparse+https://rust.pkg.re/" }
                EOF
                export CARGO_HOME="$NIX_BUILD_TOP/cargo-home"
                cargo vendor --locked vendor > /dev/null
                cp -R vendor vendor-control
                python3 ${pkgreVendorScript} vendor Cargo.lock
                python3 - <<'PYEOF'
                import hashlib
                import json
                import pathlib
                for crate_dir in sorted(pathlib.Path("vendor").iterdir()):
                    if not crate_dir.is_dir():
                        continue
                    manifest = (crate_dir / "Cargo.toml").read_bytes()
                    checksum = json.loads((crate_dir / ".cargo-checksum.json").read_text())
                    expected = hashlib.sha256(manifest).hexdigest()
                    actual = checksum["files"]["Cargo.toml"]
                    assert actual == expected, f"{crate_dir}: checksum {actual} != {expected}"
                assert "crates.io" not in pathlib.Path("Cargo.lock").read_text()
                serde_manifest = pathlib.Path("vendor/serde/Cargo.toml").read_text()
                assert 'registry-index = "sparse+https://rust.pkg.re/"' in serde_manifest
                print("pkgre-vendor: integration assertions ok")
                PYEOF
                python3 ${pkgreVendorScript} --emit-config Cargo.lock --registries-from .cargo/config.toml > emitted-config.toml
                sed "s|@vendor@|$PWD/vendor|" emitted-config.toml > .cargo/config.toml
                cargo build --locked --offline
                control="$NIX_BUILD_TOP/control"
                mkdir -p "$control"
                cp Cargo.toml Cargo.lock "$control"/
                cp -R src "$control"/src
                cp -R vendor-control "$control"/vendor
                mkdir -p "$control"/.cargo
                sed "s|@vendor@|$control/vendor|" emitted-config.toml > "$control"/.cargo/config.toml
                (
                  cd "$control"
                  if cargo build --locked --offline > control.log 2>&1; then
                    echo "control: unpatched vendor must fail cargo build --locked --offline" >&2
                    cat control.log >&2
                    exit 1
                  fi
                  grep -q "lock file" control.log
                )
                cp -R vendor vendor-tamper
                echo "// tampered" >> vendor-tamper/anyhow/src/lib.rs
                sed "s|@vendor@|$PWD/vendor-tamper|" emitted-config.toml > .cargo/config-tamper.toml
                if CARGO_TARGET_DIR="$PWD/target-tamper" cargo build --locked --offline --config .cargo/config-tamper.toml > tamper.log 2>&1; then
                  echo "tamper: modified vendored file must fail checksum verification" >&2
                  cat tamper.log >&2
                  exit 1
                fi
                grep -qi "checksum" tamper.log
                runHook postBuild
              '';
              installPhase = ''
                runHook preInstall
                cd "$NIX_BUILD_TOP/fixture"
                mkdir -p "$out/.cargo"
                cp -R vendor/. "$out"/
                cp Cargo.lock "$out"/Cargo.lock
                cp emitted-config.toml "$out"/.cargo/config.toml
                runHook postInstall
              '';
            };
          formatting = pkgs.runCommand "pkgre-formatting" { nativeBuildInputs = [ rustToolchain ]; } ''
            cp -R ${source} source
            chmod -R u+w source
            cd source
            mkdir -p .cargo vendor/empty
            cp ${./.cargo/config.toml} .cargo/config.toml
            cargo fmt --all --check
            touch $out
          '';
        }
      );

      devShells = forAllSystems (
        system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ rust-overlay.overlays.default ];
          };
          rustToolchain = pkgs.rust-bin.stable."1.95.0".default.override {
            extensions = [
              "clippy"
              "rustfmt"
            ];
          };
        in
        {
          default = pkgs.mkShell {
            packages = [
              rustToolchain
              pkgs.curl
              pkgs.git
              pkgs.gnutar
              pkgs.nixfmt
              pkgs.nodejs_24
            ];
            PKGRE_CARGO = "${rustToolchain}/bin/cargo";
          };
        }
      );

      lib = forAllSystems (
        system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ rust-overlay.overlays.default ];
          };
          rustToolchain = pkgs.rust-bin.stable."1.95.0".default;
          pkgreVendorScript = ./nix/pkgre-vendor.py;
        in
        {
          rust.cargoDeps =
            {
              src,
              lockFile ? null,
              cargoHash,
              name ? "cargo-deps",
              registriesFrom ? null,
            }:
            pkgs.stdenvNoCC.mkDerivation {
              inherit name;
              dontUnpack = true;
              # vendored crates carry shebangs; fixup would rewrite them into
              # store-path references, which fixed-output derivations forbid
              dontFixup = true;
              nativeBuildInputs = [
                rustToolchain
                pkgs.cacert
                pkgs.python3
              ];
              impureEnvVars = pkgs.lib.fetchers.proxyImpureEnvVars;
              outputHashAlgo = "sha256";
              outputHash = cargoHash;
              outputHashMode = "recursive";
              SSL_CERT_FILE = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";
              CARGO_HTTP_CA_BUNDLE = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";
              # the registry edge 503s under parallel sparse-index request
              # bursts; keep requests on separate HTTP/1 connections and retry
              # through transient rejections
              CARGO_HTTP_MULTIPLEXING = "false";
              CARGO_NET_RETRY = "20";
              buildPhase = ''
                runHook preBuild
                cp -R ${src} src-tree
                chmod -R u+w src-tree
                cd src-tree
                ${pkgs.lib.optionalString (lockFile != null) "cp ${lockFile} Cargo.lock"}
                export CARGO_HOME="$NIX_BUILD_TOP/cargo-home"
                # the consumer config may map crates-io to an empty directory;
                # keep it present so name-form `registry = "<name>"` deps resolve
                mkdir -p vendor/empty
                cargo vendor --locked vendor > /dev/null
                rm -rf vendor/empty
                python3 ${pkgreVendorScript} vendor Cargo.lock
                ${
                  if registriesFrom != null then
                    "cp ${registriesFrom} registries.toml"
                  else
                    ''
                      if [ -f .cargo/config.toml ]; then
                        cp .cargo/config.toml registries.toml
                      else
                        : > registries.toml
                      fi
                    ''
                }
                python3 ${pkgreVendorScript} --emit-config Cargo.lock --registries-from registries.toml > emitted-config.toml
                runHook postBuild
              '';
              installPhase = ''
                runHook preInstall
                mkdir -p "$out/.cargo"
                cp -R vendor/. "$out"/
                cp Cargo.lock "$out"/Cargo.lock
                cp emitted-config.toml "$out"/.cargo/config.toml
                runHook postInstall
              '';
              meta = {
                description = "Vendored cargo dependencies with registry-index-patched manifests for non-crates.io lock sources";
              };
            };
        }
      );

      formatter = forAllSystems (system: nixpkgs.legacyPackages.${system}.nixfmt);
    };
}
