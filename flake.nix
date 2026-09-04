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
          pkgreRegistry = "sparse+https://rust.pkg.re/";
          cargoVendorRegistry = "registry+https://github.com/rust-lang/crates.io-index";
          lockText = builtins.readFile ./Cargo.lock;
          lock = builtins.fromTOML lockText;
          vendorLock = builtins.toFile "pkgre-rust-vendor-Cargo.lock" (
            builtins.replaceStrings [ pkgreRegistry ] [ cargoVendorRegistry ] lockText
          );
          registryPackages = builtins.filter (package: package ? source) lock.package;
          registryArchives = map (
            package:
            assert package.source == pkgreRegistry;
            {
              inherit package;
              archive = pkgs.fetchurl {
                url = "https://static.crates.io/crates/${package.name}/${package.name}-${package.version}.crate";
                sha256 = package.checksum;
              };
            }
          ) registryPackages;
          cargoDeps = pkgs.runCommand "pkgre-rust-cargo-vendor" { nativeBuildInputs = [ pkgs.gnutar ]; } ''
            mkdir -p "$out/.cargo"
            cp ${vendorLock} "$out/Cargo.lock"
            cat > "$out/.cargo/config.toml" <<'EOF'
            # Cargo normalizes unqualified dependencies in imported manifests to crates.io.
            # A synthetic offline identity unifies those with explicit `registry = "pkgre"` dependencies.
            [registries.pkgre]
            index = "https://github.com/rust-lang/crates.io-index"

            [source.crates-io]
            replace-with = "vendored-sources"

            [source.vendored-sources]
            directory = "@vendor@"
            EOF
            ${pkgs.lib.concatMapStringsSep "\n" (
              entry:
              let
                inherit (entry) archive package;
              in
              ''
                mkdir -p "$out/${package.name}-${package.version}"
                tar -xf ${archive} -C "$out/${package.name}-${package.version}" --strip-components=1
                printf '{"files":{},"package":"%s"}\n' '${package.checksum}' > "$out/${package.name}-${package.version}/.cargo-checksum.json"
              ''
            ) registryArchives}
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
              postPatch = ''
                cp ${vendorLock} Cargo.lock
              '';
              nativeBuildInputs = pkgs.lib.optionals (runtimeInputs != [ ]) [ pkgs.makeWrapper ];
              postInstall = pkgs.lib.optionalString (runtimeInputs != [ ]) ''
                wrapProgram "$out/bin/${mainProgram}" \
                  --prefix PATH : ${pkgs.lib.makeBinPath runtimeInputs}
              '';
              inherit cargoDeps nativeCheckInputs;
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
          pkgreProxy = mkRustPackage {
            packageDirectory = "rust/proxy";
            description = "Stateless immutable download redirect service for pkgre registries";
            mainProgram = "pkgre-proxy";
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
            nativeCheckInputs = [ pkgs.nodejs_24 ];
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
                --add-flags "$out/lib/pkgre-js/src/serve/main.js"
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
          proxy = pkgreProxy;
          download-serve = pkgreProxy;
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
          proxy = self.packages.${system}.proxy;
          download-serve = self.packages.${system}.download-serve;
          serve = self.packages.${system}.serve;
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

      formatter = forAllSystems (system: nixpkgs.legacyPackages.${system}.nixfmt);
    };
}
