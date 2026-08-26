let
  f = builtins.getFlake "path:/home/dev0/.talent/agents/01a0368b-4cd1-7930-b789-daf0a9a11164/workspace/d0-pkgre-066293df/source";
  system = "x86_64-linux";
  pkgs = import f.inputs.nixpkgs { inherit system; overlays = [ f.inputs.rust-overlay.overlays.default ]; };
  rustToolchain = pkgs.rust-bin.stable."1.95.0".default.override { extensions = [ "clippy" "rustfmt" ]; };
  one = p: { drvPath = p.drvPath; outputPath = builtins.toString p; version = p.version or null; pname = p.pname or null; };
in builtins.mapAttrs (name: p: one p) {
  rustToolchain = rustToolchain;
  git = pkgs.git;
  nodejs24 = pkgs.nodejs_24;
  rustPackage = f.packages.${system}.rust;
  proxyPackage = f.packages.${system}.proxy;
  jsPackage = f.packages.${system}.js;
  nodeMinimum = f.packages.${system}.js-client-node-minimum;
  nodeCurrent = f.packages.${system}.js-client-node-current;
  bunMinimum = f.packages.${system}.js-client-bun-minimum;
  bunCurrent = f.packages.${system}.js-client-bun-current;
  denoMinimum = f.packages.${system}.js-client-deno-minimum;
  denoCurrent = f.packages.${system}.js-client-deno-current;
  devShell = f.devShells.${system}.default;
}
