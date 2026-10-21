# DFC for Java and Android

The Java 17 API is a thin binding over the native DFC core. Credential parsing,
validation and canonical encoding, virtual-card behavior, and reader secure
messaging all run through the same flat native interface as the other bindings.

Build and run the host smoke test with mbedTLS:

```sh
cmake -S . -B build-jni -DDFC_BUILD_SHARED=OFF -DDFC_BUILD_TESTS=OFF \
  -DDFC_BUILD_JNI=ON -DDFC_CRYPTO=mbedtls
cmake --build build-jni
javac --release 17 -d build-jni/java \
  bindings/java/src/main/java/com/cindersocket/dfc/*.java \
  tests/java/DfcJniSmokeTest.java
java -Djava.library.path=build-jni -cp build-jni/java DfcJniSmokeTest \
  examples/credentials/v6-minimal.dfc examples/credentials/v6-maximal.dfc
```

`DfcReader` is blocking by design. Supply a `DfcTransport` for a physical card,
or use `DfcVirtualPicc` directly. Both own native resources and should be used
in try-with-resources blocks.

The Android project in `bindings/android` builds an AAR containing one
self-contained `libdfc_jni.so` for arm64-v8a, armeabi-v7a, x86_64, and x86.
It targets Android API 26 and includes `IsoDepTransport` plus a small NFC sample.

```sh
cd bindings/android
./gradlew :dfc:assembleRelease :sample:assembleDebug :dfc:lintRelease
```
