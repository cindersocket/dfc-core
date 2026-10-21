# DFC for Android

The Android binding packages the Java API, `IsoDepTransport`, and the native
DFC engine in one AAR. It supports API 26 and later on `arm64-v8a`,
`armeabi-v7a`, `x86_64`, and `x86`.

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

The runnable [NFC example](../../examples/android/README.md) includes reader
mode, lifecycle handling, background execution, and a real `GetVersion`
transceive. The [Java host example](../../examples/java/README.md) verifies the
same public reader flow without NFC hardware.

## Build

The checked-in Gradle wrapper builds the AAR, example APK, and Android lint:

```sh
cd bindings/android
./gradlew --no-daemon :dfc:assembleRelease :sample:assembleDebug :dfc:lintRelease
```

The artifacts are `dfc/build/outputs/aar/dfc-release.aar` and
`../../examples/android/build/outputs/apk/debug/sample-debug.apk`.
