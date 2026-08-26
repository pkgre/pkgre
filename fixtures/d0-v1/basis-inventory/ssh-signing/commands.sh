#!/usr/bin/env bash
# Exact proof command shape; all mutable paths confined to <PROOF_ROOT>/.ephemeral.*.
# Source Git revision is read-only and exact; --no-update-lock-file prevents lock mutation.
PKGRE=/home/dev0/repos/pkgre
SOURCE_REV=1d44dfeaeafef2b1a5341c13bf73647dcbc925ec
SYSTEM=x86_64-linux
FLAKE_URI='git+file:///home/dev0/repos/pkgre?ref=refs/heads/main&rev=1d44dfeaeafef2b1a5341c13bf73647dcbc925ec'
NIXPKGS_REV=2c423e03bbafcff28bfadc6781a4a8257f205cb5
DEV_SHELL_DRV=/nix/store/0d7b506d024c2w7pmc0yydvgmm7adn0b-nix-shell.drv
GIT_OUT=/nix/store/8wxs6573l730vxkqd6wp58kvxa19csll-git-2.55.0
OPENSSH_OUT=/nix/store/aw4kb88y82xv4pl48lb388mhs48iq7iv-openssh-10.5p1
# Tool entry: nix develop --no-update-lock-file "$FLAKE_URI" -c <isolated-script>
# Key: "$OPENSSH_OUT/bin/ssh-keygen" -q -t ed25519 -N '' -C 'state-contract-v1-compat@example.invalid' -f <EPHEMERAL_WORKSPACE>/state-contract-v1-test-ed25519
# Repository: git init --object-format=sha1 --initial-branch=main <EPHEMERAL_WORKSPACE>/sha1-repo
# Signing config: gpg.format=ssh; user.signingKey=<EPHEMERAL_PRIVATE_KEY>; gpg.ssh.program="$OPENSSH_OUT/bin/ssh-keygen"; commit.gpgSign=true
# Commit: git commit -S -m 'D0 state-contract-v1 SSH signing compatibility fixture'
# Verification: git -c gpg.format=ssh -c gpg.ssh.allowedSignersFile=<PROOF_ROOT>/fixtures/allowed_signers -c gpg.ssh.program="$OPENSSH_OUT/bin/ssh-keygen" verify-commit --raw 3bb4f9586f506ce3f7baf37d3a7a016cd9f46157
# Cleanup occurred before packaging: rm -f <EPHEMERAL_PRIVATE_KEY>; rm -rf <EPHEMERAL_REPOSITORY> <ISOLATED_HOME>
