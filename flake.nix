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
          source = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [
              ./Cargo.lock
              ./Cargo.toml
              ./indexer
              ./rust-toolchain.toml
            ];
          };
          indexer = rustPlatform.buildRustPackage {
            pname = "pkgre-indexer";
            version = "0.1.0";
            src = source;
            cargoLock.lockFile = ./Cargo.lock;
            cargoBuildFlags = [ "--workspace" ];
            nativeCheckInputs = [
              pkgs.git
              pkgs.gnutar
            ];
            PKGRE_CARGO = "${rustToolchain}/bin/cargo";
            doCheck = true;
            checkPhase = ''
              runHook preCheck
              cargo test --workspace --offline
              cargo clippy --workspace --all-targets --offline -- -D warnings
              runHook postCheck
            '';
            meta = {
              description = "Deterministic renderer for curated Cargo sparse registries";
              homepage = "https://github.com/pkgre/pkgre";
              license = pkgs.lib.licenses.asl20;
              mainProgram = "pkgre-indexer";
            };
          };
        in
        {
          default = indexer;
          inherit indexer;
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
              ./indexer
              ./rust-toolchain.toml
            ];
          };
        in
        {
          build-and-test = self.packages.${system}.indexer;
          formatting = pkgs.runCommand "pkgre-formatting" { nativeBuildInputs = [ rustToolchain ]; } ''
            cp -R ${source} source
            chmod -R u+w source
            cd source
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
