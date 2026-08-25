{
  description = "Declarative curated Cargo registry tooling";

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
              ./download-serve
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
          downloadServe = mkRustPackage {
            packageDirectory = "download-serve";
            description = "Stateless immutable download redirect service for pkgre registries";
            mainProgram = "pkgre-download-serve";
          };
        in
        {
          default = rustIndexer;
          rust = rustIndexer;
          indexer = rustIndexer;
          download-serve = downloadServe;
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
          source = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [
              ./Cargo.lock
              ./Cargo.toml
              ./download-serve
              ./rust
              ./rust-toolchain.toml
            ];
          };
        in
        {
          build-and-test = self.packages.${system}.rust;
          download-serve = self.packages.${system}.download-serve;
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
            ];
            PKGRE_CARGO = "${rustToolchain}/bin/cargo";
          };
        }
      );

      formatter = forAllSystems (system: nixpkgs.legacyPackages.${system}.nixfmt);
    };
}
