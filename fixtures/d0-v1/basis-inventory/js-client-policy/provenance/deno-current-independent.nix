{ pkgs ? import /nix/store/d6mryll7gbj6hbczvyrvnflcyxxq11zn-source { system = "x86_64-linux"; } }:
let
  archive = /nix/store/mic0h6lymr3lanvknzdzjsj703rnzz19-deno-x86_64-unknown-linux-gnu.zip;
in
pkgs.stdenvNoCC.mkDerivation {
  pname = "pkgre-js-compat-deno-current-independent";
  version = "2.9.5";
  dontUnpack = true;
  nativeBuildInputs = [ pkgs.autoPatchelfHook pkgs.unzip ];
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
    test "$("$out/bin/deno" --version | head -1)" = "deno 2.9.5 (stable, release, x86_64-unknown-linux-gnu)"
    runHook postInstallCheck
  '';
  passthru.provenance = {
    role = "current-independent";
    nixpkgsRevision = "2c423e03bbafcff28bfadc6781a4a8257f205cb5";
    upstreamUrl = "https://github.com/denoland/deno/releases/download/v2.9.5/deno-x86_64-unknown-linux-gnu.zip";
    upstreamNixHash = "sha256-iwEKOxpKAYimfNuKeic0iypQGveK7H/HTyrOFnNo1TA=";
  };
}
