{ pkgs, system }:

let
  target =
    {
      x86_64-linux = {
        bunArch = "x64";
        denoArch = "x86_64";
        nodeArch = "x64";
        hashes = {
          bun-1-3-14 = "sha256-lR7iruhV8IWVruxiJSJqKY0/6oOj3NZGXAnLzN9+hI8=";
          bun-1-4-0 = "sha256-LQP7X7g6yLVnrKCigbLOGhoZ1Ij1bClo2Iw/Jekv5FI=";
          deno-2-9-5 = "sha256-iwEKOxpKAYimfNuKeic0iypQGveK7H/HTyrOFnNo1TA=";
          node-24-15-0 = "sha256-RyZVWB+4UVWXMMSHY+DJ07wll1xZ1RgAP8CEnT5LoPY=";
          node-26-7-0 = "sha256-mCqiTdi+TIicaoqzN93/OwiWZFsg9COTVugFUsFid+4=";
        };
      };
      aarch64-linux = {
        bunArch = "aarch64";
        denoArch = "aarch64";
        nodeArch = "arm64";
        hashes = {
          bun-1-3-14 = "sha256-on/7Y6gxA3WDbg1vZorhf6jY0YuIw3yCHGUzGXOhmjs=";
          bun-1-4-0 = "sha256-SxozLuhhmD65O8/m93D/+U4+MbLDiL2uo8jtNeWO7Q4=";
          deno-2-9-5 = "sha256-a3yuOo/EOFpZ3qMUb8uLrX/qQjDgrTaoxpKvrLwlS+A=";
          node-24-15-0 = "sha256-89Wnl7XSEM6OLLJlVEyOSC6u3LiqQJqLRtp+hZXQ3aA=";
          node-26-7-0 = "sha256-r8egBAGEhQkqyJhbgXsNVoRHK9lHLgtX0quIc35QCQ0=";
        };
      };
    }
    .${system};
  npmVersion = "12.0.2";
  npmArchive = pkgs.fetchurl {
    url = "https://registry.npmjs.org/npm/-/npm-${npmVersion}.tgz";
    hash = "sha256-XbuGxx0HoZV/LpBzQJLdali9zZ68LY1ByhxuaiHTZOE=";
  };
  mkNodeNpm =
    {
      nodeVersion,
      nodeHash,
    }:
    let
      nodeArchive = pkgs.fetchurl {
        url = "https://nodejs.org/dist/v${nodeVersion}/node-v${nodeVersion}-linux-${target.nodeArch}.tar.xz";
        hash = nodeHash;
      };
    in
    pkgs.stdenvNoCC.mkDerivation {
      pname = "pkgre-js-compat-node-npm";
      version = "${nodeVersion}-${npmVersion}";
      dontUnpack = true;
      nativeBuildInputs = [
        pkgs.autoPatchelfHook
        pkgs.gnutar
        pkgs.makeWrapper
        pkgs.xz
      ];
      buildInputs = [ pkgs.stdenv.cc.cc.lib ];
      installPhase = ''
        runHook preInstall
        mkdir -p "$out"
        tar -xJf ${nodeArchive} --strip-components=1 -C "$out"
        rm -rf "$out/lib/node_modules/npm"
        mkdir -p "$out/lib/node_modules/npm"
        tar -xzf ${npmArchive} --strip-components=1 -C "$out/lib/node_modules/npm"
        rm -f "$out/bin/npm" "$out/bin/npx"
        makeWrapper "$out/bin/node" "$out/bin/npm" \
          --add-flags "$out/lib/node_modules/npm/bin/npm-cli.js"
        makeWrapper "$out/bin/node" "$out/bin/npx" \
          --add-flags "$out/lib/node_modules/npm/bin/npx-cli.js"
        runHook postInstall
      '';
      doInstallCheck = true;
      installCheckPhase = ''
        runHook preInstallCheck
        test "$("$out/bin/node" --version)" = v${nodeVersion}
        test "$("$out/bin/npm" --version)" = ${npmVersion}
        runHook postInstallCheck
      '';
      meta = {
        description = "Pinned Node and npm pair for js.pkg.re compatibility checks";
        license = [
          pkgs.lib.licenses.mit
          pkgs.lib.licenses.artistic2
        ];
        platforms = [ system ];
      };
    };
  mkBun =
    {
      version,
      hash,
    }:
    let
      archive = pkgs.fetchurl {
        url = "https://github.com/oven-sh/bun/releases/download/bun-v${version}/bun-linux-${target.bunArch}.zip";
        inherit hash;
      };
    in
    pkgs.stdenvNoCC.mkDerivation {
      pname = "pkgre-js-compat-bun";
      inherit version;
      dontUnpack = true;
      nativeBuildInputs = [
        pkgs.autoPatchelfHook
        pkgs.unzip
      ];
      buildInputs = [ pkgs.glibc ];
      installPhase = ''
        runHook preInstall
        unzip -q ${archive}
        install -Dm755 bun-linux-${target.bunArch}/bun "$out/bin/bun"
        runHook postInstall
      '';
      doInstallCheck = true;
      installCheckPhase = ''
        runHook preInstallCheck
        test "$("$out/bin/bun" --version)" = ${version}
        runHook postInstallCheck
      '';
      meta = {
        description = "Pinned Bun for js.pkg.re compatibility checks";
        license = pkgs.lib.licenses.mit;
        platforms = [ system ];
      };
    };
  mkDeno =
    {
      version,
      hash,
    }:
    let
      archive = pkgs.fetchurl {
        url = "https://github.com/denoland/deno/releases/download/v${version}/deno-${target.denoArch}-unknown-linux-gnu.zip";
        inherit hash;
      };
    in
    pkgs.stdenvNoCC.mkDerivation {
      pname = "pkgre-js-compat-deno";
      inherit version;
      dontUnpack = true;
      nativeBuildInputs = [
        pkgs.autoPatchelfHook
        pkgs.unzip
      ];
      buildInputs = [ pkgs.stdenv.cc.cc.lib ];
      installPhase = ''
        runHook preInstall
        unzip -q ${archive}
        install -Dm755 deno "$out/bin/deno"
        runHook postInstall
      '';
      doInstallCheck = true;
      installCheckPhase = ''
        runHook preInstallCheck
        test "$("$out/bin/deno" --version | head -1)" = "deno ${version} (stable, release, ${target.denoArch}-unknown-linux-gnu)"
        runHook postInstallCheck
      '';
      meta = {
        description = "Pinned Deno for js.pkg.re compatibility checks";
        license = pkgs.lib.licenses.mit;
        platforms = [ system ];
      };
    };
  nodeMinimum = mkNodeNpm {
    nodeVersion = "24.15.0";
    nodeHash = target.hashes.node-24-15-0;
  };
  nodeCurrent = mkNodeNpm {
    nodeVersion = "26.7.0";
    nodeHash = target.hashes.node-26-7-0;
  };
  bunMinimum = mkBun {
    version = "1.3.14";
    hash = target.hashes.bun-1-3-14;
  };
  bunCurrent = mkBun {
    version = "1.4.0";
    hash = target.hashes.bun-1-4-0;
  };
  denoMinimum = mkDeno {
    version = "2.9.5";
    hash = target.hashes.deno-2-9-5;
  };
in
{
  inherit
    bunCurrent
    bunMinimum
    denoMinimum
    nodeCurrent
    nodeMinimum
    ;
  denoCurrent = denoMinimum;
}
