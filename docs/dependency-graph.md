# Dependency graph

`dependency-inventory.json` maps every maintained build surface to the input
GitHub uses for the repository dependency graph. Add a surface there whenever a
new package manifest, lockfile, binding, or build system is introduced.

Cargo lockfiles, NuGet project files, and GitHub Actions workflows are parsed by
GitHub directly. The Android build uses GitHub's Gradle dependency-submission
action because Gradle has no static manifest format that contains the resolved
graph. It submits runtime classpaths, which describe dependencies carried by the
Android library and sample without treating the Android build toolchain as an
application dependency. The native submission records the exact tiny-crypto-c
revision pinned by CMake. A system mbedTLS installation is selected and resolved
by the consuming build, so the repository does not submit a made-up global
mbedTLS version.

The Python wheel has no Python runtime dependencies. Its build and test tools
remain development inputs in `bindings/python/pyproject.toml`; they are not
reported as dependencies of applications installing the wheel. The standalone
Java/JNI API has no external Java dependency, while Android dependencies are
reported through Gradle.

Run the local integrity checks without submitting anything:

```sh
python3 tests/test_dependency_graph.py
python3 scripts/native-dependency-snapshot.py --output /tmp/dfc-native-dependencies.json
```

The submission workflow runs only for the default branch or by explicit manual
dispatch. It uses the repository-scoped token with only `contents: write`, the
permission required by GitHub's dependency submission API. Pull requests run
the integrity test but do not publish snapshots.

After the workflow completes, verify the repository's **Insights > Dependency
graph** page lists the Cargo, NuGet, Gradle, Actions, and pinned native
dependencies. That hosted view is the final publication check; local tests
prove only the inputs and generated snapshot.

GitHub documents the [supported package ecosystems][ecosystems] and the
[dependency submission API][submission] used by this setup.

[ecosystems]: https://docs.github.com/code-security/supply-chain-security/understanding-your-software-supply-chain/about-the-dependency-graph#supported-package-ecosystems
[submission]: https://docs.github.com/code-security/supply-chain-security/understanding-your-software-supply-chain/using-the-dependency-submission-api
