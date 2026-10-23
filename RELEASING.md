# Release procedure

dfc-core releases are cut manually from a clean `master` checkout. Version 2.0
ships reproducible source archives and their checksums. CI builds native
libraries, an Android AAR, and a NuGet package as validation artifacts. Issue
#111 tracks future binary and package-registry distribution.

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

- `format-docs`
- `fuzz`
- `cmake-configuration`
- `embedded-footprint`
- `unit`
- `native`
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
```

Inspect both archive listings and confirm they contain tracked source material.
Version 2.0 ships these source archives and `SHA256SUMS` as its complete release
asset set. Issue #111 defines future binary and package publishing.

## 4. Publish the GitHub release

Use the matching changelog section as the release notes, state that version 2.0
ships source archives and checksums, and attach exactly the verified artifacts:

```sh
gh release create "v$version" \
  "dist/v$version/dfc-core-$version.tar.gz" \
  "dist/v$version/dfc-core-$version.zip" \
  "dist/v$version/SHA256SUMS" \
  --verify-tag --title "dfc-core $version" --notes-file release-notes.md
gh release view "v$version"
```

Download and verify the three published assets before announcing the release:

```sh
mkdir -p "dist/verify-v$version"
gh release download "v$version" --dir "dist/verify-v$version"
python3 scripts/checksums.py check "dist/verify-v$version/SHA256SUMS"
```
