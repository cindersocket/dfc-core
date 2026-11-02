# Release procedure

dfc-core releases are cut from a clean `master` checkout. Source archives and
every supported binding package are built from the same validated commit. The
complete contract is in `release-artifacts.json`.

## Version 2.0 artifact contract

The GitHub release contains the complete verified artifact bundle, including:

- `dfc-core-$version.tar.gz`
- `dfc-core-$version.zip`
- `SHA256SUMS`
- native archives for every supported desktop target;
- Python wheels and a source distribution;
- Rust crate archives;
- Java, JNI classifier, and Android artifacts; and
- the NuGet package and symbols.

The repository version governs every build. CI produces the following
artifacts from both source archives and exercises their consumer entry points:

- native libraries through CMake on the platforms in the `native` CI matrix;
- the four-ABI Android AAR and sample APK through the checked-in Gradle wrapper;
- the NuGet package through `dotnet pack`;
- the Python wheel through `uv build`;
- Java/JNI classes and the native JNI library through CMake and JDK 17; and
- both Rust crates, the hosted workspace, and the Rust example through Cargo.

## 1. Prepare the release commit

1. Confirm that every intended change is on `master`, the worktree is clean,
   and the version agrees across all package metadata.
2. Replace `(Unreleased)` in the first `CHANGELOG.md` heading with the release
   date in strict `YYYY-MM-DD` form. Review the notes as a user-facing summary
   of every change since the preceding release.
3. Run the repository's formatting and metadata gates:

   ```sh
   ./scripts/check-format.sh
   python3 tests/test_check_docs.py
python3 tests/test_binding_documentation_ci.py
   python3 tests/test_check_stack_usage.py
   python3 tests/test_ci_unit_workflow.py
   python3 tests/test_check_version.py
   python3 tests/test_checksums.py
   python3 tests/test_release_process.py
   python3 scripts/check-docs.py
   python3 scripts/check-version.py
   ```

4. Fetch the exact tiny-crypto-c revision pinned by `CMakeLists.txt`, verify the
   checkout, then run the native configuration, footprint, and unit gates:

   ```sh
   tiny_crypto_revision=64fccd69ae2405574575f971f8b72f5e3e403f56
   mkdir -p dependencies
   git init dependencies/tiny-crypto-c
   git -C dependencies/tiny-crypto-c remote add origin https://github.com/mistial-dev/tiny-crypto-c.git
   git -C dependencies/tiny-crypto-c fetch --depth=1 origin "$tiny_crypto_revision"
   git -C dependencies/tiny-crypto-c checkout --detach "$tiny_crypto_revision"
   test "$(git -C dependencies/tiny-crypto-c rev-parse HEAD)" = "$tiny_crypto_revision"
   TINY_CRYPTO_DIR="$PWD/dependencies/tiny-crypto-c" python3 scripts/check-cmake-pic.py
   TINY_CRYPTO_DIR="$PWD/dependencies/tiny-crypto-c" ./scripts/check-embedded-footprint.sh
   make -C tests test CRYPTO_BACKEND=mbedtls
   make -C tests test CRYPTO_BACKEND=mbedtls SANITIZE=address,undefined
   make -C tests test CRYPTO_BACKEND=tiny TINY_CRYPTO_DIR=../dependencies/tiny-crypto-c
   make -C tests test CRYPTO_BACKEND=tiny TINY_CRYPTO_DIR=../dependencies/tiny-crypto-c SANITIZE=address,undefined
   make -C tests test CRYPTO_BACKEND=tiny TINY_CRYPTO_DIR=../dependencies/tiny-crypto-c SANITIZE=memory CC=clang
   make -C tests test CRYPTO_BACKEND=tiny TINY_CRYPTO_DIR=../dependencies/tiny-crypto-c RELEASE=1
   ```

5. Run these hosted binding preflight checks:

   ```sh
   cargo test --workspace
   ./scripts/check-binding-examples.sh
   cargo clippy --workspace --all-targets -- -D warnings
   dotnet test bindings/dotnet/Dfc.sln -c Release
   (cd bindings/python && uv run --frozen --extra test pytest)
   (cd bindings/android && ./gradlew --no-daemon :dfc:assembleRelease :sample:assembleDebug :dfc:lintRelease)
   ```

   Push the signed release commit. The full GitHub Actions matrix for that
   exact commit is the authoritative Java JNI, cross-platform native,
   package-construction, Rust 1.85, embedded `no_std`, example, and fuzz
   validation. Require every matrix entry to pass.

Required CI jobs (exact IDs):

- `vector-provenance`
- `format-docs`
- `source-archives`
- `fuzz`
- `cmake-configuration`
- `embedded-footprint`
- `unit`
- `native`
- `mismatch-native`
- `dotnet`
- `java`
- `android`
- `python`
- `rust`
- `rust-msrv`
- `pack`

## 2. Sign and verify the tag

Set the release version explicitly, and ensure the target is the validated
release commit:

```sh
version=2.0.0
python3 scripts/release-notes.py "$version" > release-notes.md
git tag -s -a "v$version" -m "dfc-core $version"
git tag -v "v$version"
git push origin "v$version"
```

Verify that the pushed tag resolves to the same commit before publishing any
release assets.

## 3. Build source artifacts and checksums

Build both archives from the signed tag:

```sh
mkdir -p "dist/v$version"
git archive --format=tar.gz --prefix="dfc-core-$version/" \
  -o "dist/v$version/dfc-core-$version.tar.gz" "v$version"
git archive --format=zip --prefix="dfc-core-$version/" \
  -o "dist/v$version/dfc-core-$version.zip" "v$version"
python3 scripts/checksums.py create --output "dist/v$version/SHA256SUMS" \
  "dist/v$version/dfc-core-$version.tar.gz" \
  "dist/v$version/dfc-core-$version.zip"
python3 scripts/checksums.py check "dist/v$version/SHA256SUMS"
python3 scripts/check-release-artifacts.py inspect \
  --version "$version" \
  --tar "dist/v$version/dfc-core-$version.tar.gz" \
  --zip "dist/v$version/dfc-core-$version.zip"
for entry_point in native android dotnet python java rust; do
  python3 scripts/check-release-artifacts.py smoke \
    --version "$version" \
    --tar "dist/v$version/dfc-core-$version.tar.gz" \
    --zip "dist/v$version/dfc-core-$version.zip" \
    --entry-point "$entry_point" \
    --tiny-crypto-dir "$PWD/dependencies/tiny-crypto-c"
done
```

The gate requires matching archive contents under the versioned root, verifies
every supported source entry point, extracts each format independently, and
builds and uses each entry point from both extracted trees. The release
workflow combines those archives with the installable binding packages.

## 4. Build and publish packages

Run the release workflow against the signed tag with `publish` disabled first.
It builds and installs every package, checks the complete artifact inventory,
creates checksums and provenance, and uploads one immutable validation bundle.

After that run passes, approve the protected release environments and rerun the
same tag with `publish` enabled. Registry jobs publish the already verified
artifacts. PyPI, NuGet, and crates.io use trusted publishing. Maven Central
credentials are scoped to its own environment. The workflow publishes the
verified Rust crate archives in dependency order and uploads one signed Maven
Central bundle.

Start both passes explicitly against the signed tag:

```sh
gh workflow run release.yml --ref "v$version" -f publish=false
gh run watch --exit-status
gh workflow run release.yml --ref "v$version" -f publish=true
gh run watch --exit-status
gh release view "v$version"
```

For the first release of the two new crates.io packages only, place a
crate-scoped token in the protected `crates-io` environment as
`CARGO_BOOTSTRAP_TOKEN` and add `-f bootstrap_crates=true` to the publishing
run. crates.io requires this initial publication before its trusted publisher
can be registered. Remove the token and register `release.yml` for both crates
immediately afterward. All later releases leave `bootstrap_crates=false` and
use the short-lived identity token.

Download and verify the published bundle before announcing the release:

```sh
mkdir -p "dist/verify-v$version"
gh release download "v$version" --dir "dist/verify-v$version"
python3 scripts/checksums.py check "dist/verify-v$version/SHA256SUMS"
```
