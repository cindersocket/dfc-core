# DFC for Android

The Android binding packages the Java API, `IsoDepTransport`, and the native
DFC engine in one AAR. It supports API 26 and later on `arm64-v8a`,
`armeabi-v7a`, `x86_64`, and `x86`. Its consumer rules retain the exact
`DfcException` class and constructor that native error reporting resolves, so
applications may safely enable R8 shrinking and obfuscation.

The AAR includes the Java typed response decoders, key diversification, SDM
verification, and Transaction MAC verifier. SDM verification authenticates one
message; the backend must persist the last accepted read counter for its card
and application context and reject duplicate or older counters. The binding
does not store replay state.
The Transaction MAC verifier follows the
[native transaction-input contract](../../src/dfc_transaction_mac.h) for its
supported commands, fields, padding, and card-order rules. Receipt history
remains application policy.

Install the published AAR from Maven Central:

```kotlin
dependencies {
    implementation("com.cindersocket:dfc-core-android:2.0.0")
}
```

## Read a physical card

Connect an `IsoDep` tag before constructing the transport. Keep the work off
the UI thread because both Android and `DfcReader` use blocking transceives:

```java
IsoDep isoDep = IsoDep.get(tag);
isoDep.connect();
try (DfcReader reader = new DfcReader(new IsoDepTransport(isoDep))) {
  DfcResponse version = reader.exchange(
      DfcCommand.getVersion(),
      DfcReader.Framing.ISO_7816,
      DfcReader.Communication.PLAIN);
} finally {
  isoDep.close();
}
```

`DfcReader` owns native session state and must be closed. The caller still owns
the Android `IsoDep` connection and must close it separately.

The runnable [NFC example](https://github.com/cindersocket/dfc-core/tree/master/examples/android) includes reader
mode, lifecycle handling, background execution, and a real `GetVersion`
transceive. The [Java host example](https://github.com/cindersocket/dfc-core/tree/master/examples/java) verifies the
same public reader flow without NFC hardware.

## Build

The checked-in Gradle wrapper builds the AAR, example APK, and Android lint:

```sh
cd bindings/android
./gradlew --no-daemon :dfc:assembleRelease :sample:assembleRelease \
  :dfc:lintRelease :dfc:testDebugUnitTest
./gradlew --no-daemon :dfc:androidJavadocs
```

`androidJavadocs` runs doclint with warnings treated as errors and produces the
documentation used by the Javadoc artifact.

The artifacts are `dfc/build/outputs/aar/dfc-release.aar` and
`../../examples/android/build/outputs/apk/release/sample-release.apk`. The
release sample is minified. Its release instrumentation test deliberately
rejects a credential in native code and verifies that the resulting
`DfcException` remains constructible.

## Secret lifetime

Card snapshots exclude session keys. The JNI layer clears native temporary
buffers on every exit. Android runtime or application copies of Java arrays
cannot be recalled, so callers should close `DfcCredential` promptly and clear
mutable key arrays they own. A cleaner clears owned credential and diagnostic
buffers if explicit close is missed, with runtime-dependent timing.

## Security

Report suspected vulnerabilities through the project's
[private reporting process](https://github.com/cindersocket/dfc-core/security/policy).
