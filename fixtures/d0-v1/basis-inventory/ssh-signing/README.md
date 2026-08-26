# D0 state-contract-v1 Git SSH-Ed25519 compatibility proof

Status:PASS | scope:non-secret isolated compatibility fixture | generated:2026-08-26T12:23:35Z

## Claim boundary

Proves:the exact `pkgre` source revision+flake lock resolve Git 2.55.0 from `pkgs.git`;an ephemeral Ed25519 key can create an SSH-format signed commit in an explicitly SHA-1 Git repository;Git verifies that commit against an `allowedSigners` file with namespace `git`;the retained public-only bundle re-verifies after private-key+temporary-repository deletion.

Does not prove:production signer identity,key custody,authorization,Git source admission policy,deterministic validator time,revocation handling,or deployment readiness. **This fixture is not a production identity and must never be admitted as one.**

## Identities

- source repo(read-only):`/home/dev0/repos/pkgre`@1d44dfeaeafef2b1a5341c13bf73647dcbc925ec
- source flake:`git+file:///home/dev0/repos/pkgre?ref=refs/heads/main&rev=1d44dfeaeafef2b1a5341c13bf73647dcbc925ec` + `--no-update-lock-file`
- locked nixpkgs:`2c423e03bbafcff28bfadc6781a4a8257f205cb5`
- dev shell derivation:`/nix/store/0d7b506d024c2w7pmc0yydvgmm7adn0b-nix-shell.drv`
- Git out path:`/nix/store/8wxs6573l730vxkqd6wp58kvxa19csll-git-2.55.0`
- OpenSSH out path(same locked nixpkgs):`/nix/store/aw4kb88y82xv4pl48lb388mhs48iq7iv-openssh-10.5p1`
- fixture principal(non-production):`state-contract-v1-compat@example.invalid`
- public-key fingerprint:`SHA256:+uZsRMJhsMrNNuIpWh9wzwU8B9w5T6TMpEsmT2eBxvA`
- object format:`sha1`
- signed commit:`3bb4f9586f506ce3f7baf37d3a7a016cd9f46157`
- tree:`c944e104ba5647c995239e48baded28c5df194e4`

## Isolation+secret disposal

- isolated `HOME`+XDG config;`GIT_CONFIG_NOSYSTEM=1`;`GIT_CONFIG_GLOBAL=/dev/null`;`SSH_AUTH_SOCK` unset;local Git identity+signing config only
- private key generated only at `<PROOF_ROOT>/.ephemeral.*/state-contract-v1-test-ed25519`;recorded mode:600;never printed or retained
- private key deleted before bundle re-verification+artifact hashing;ephemeral repository+isolated homes removed
- retained:`public-key.pub`,`allowed_signers`,signed public Git objects in bundle,sanitized outputs;all non-secret
- validation scans every retained regular file for an OpenSSH private-key PEM marker and confirms no ephemeral private-key path/file remains

## Files

- `proof.json`:machine-readable claim,toolchain,identities,results,artifact digests
- `SHA256SUMS`:digest of every retained regular file except itself
- `commands.sh`:exact pinned identities+sanitized command shape(no secret)
- `fixtures/`:public key,allowed signers,fixture content,signed commit bundle
- `evidence/`:sanitized command outputs,commit object,fingerprint,toolchain,source before/after status

## Validation

Run from this directory:`sha256sum -c SHA256SUMS`;`python3 -m json.tool proof.json >/dev/null`. Public verification command is recorded in `commands.sh`. Results:initial verify exit=0;post-deletion public-bundle verify exit=0;bundle HEAD match=true;bundle object format=sha1;source status unchanged=true;private marker absent=true.
