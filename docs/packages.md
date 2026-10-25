# Packages and releases

The repository publishes one version across the C core and every binding. The
machine-readable contract is [`release-artifacts.json`](../release-artifacts.json).
`scripts/check-release-inventory.py` rejects missing ecosystems, targets, or
version drift before artifact construction begins.

## Consumer packages

- C and C++ consumers use the signed source archive or a platform-native archive.
- Python consumers install `dfc-core` from PyPI. CPython 3.11 through 3.14
  wheels cover Linux x86-64/arm64, macOS x86-64/arm64, and Windows x64; the
  source distribution supports other toolchain-equipped hosts.
- Rust consumers use `dfc-core`; it depends on the lower-level `dfc-core-sys` crate.
- Java consumers use `com.cindersocket:dfc-core` plus its matching native
  classifier for their operating system and architecture.
- Android consumers use `com.cindersocket:dfc-core-android`.
- .NET consumers use `Dfc`, which carries native libraries under `runtimes/`.

Package metadata records its description, license, repository location, and
security reporting link where the registry supports one. Examples are tested
against the constructed package rather than the source tree before publication.

## Release workflow

`.github/workflows/release.yml` has a validation-only manual mode. Publication
requires both an explicit `publish` input and a cryptographically verified
`v<version>` tag whose version matches every package manifest. The workflow
builds once, smoke-tests the downloaded artifacts, creates one checksum
manifest, and then publishes those same bytes. PyPI, NuGet, and crates.io use
short-lived identity tokens. Maven Central signing and portal credentials are
confined to its release environment.

The `2.0.0` entry remains unreleased. Manual runs with `publish: false` perform
the complete validation path and stop after uploading the verified bundle.

Before the first publication, protect the `release`, `pypi`, `crates-io`,
`nuget`, and `maven-central` environments. Register `release.yml` as the PyPI,
crates.io, and NuGet trusted publisher, and set the `NUGET_USER` environment
variable. Scope the Maven Central portal and signing credentials to
`maven-central`. Validation runs operate without registry credentials.

crates.io permits trusted-publisher configuration only after a crate exists.
For the first publication of these new crate names, store a narrowly scoped
token as `CARGO_BOOTSTRAP_TOKEN` in the protected `crates-io` environment and
run once with `bootstrap_crates: true`. Remove the token immediately, configure
`release.yml` as the trusted publisher for both crates, and leave
`bootstrap_crates` false for every later release.
