# DFC for Java

The Java 17 binding exposes credential codecs, an in-process virtual card, and
a blocking reader over any `DfcTransport`. Parsing, validation, card behavior,
and secure messaging run in the native DFC core through JNI.

## Load and transceive

`DfcCredentialCodec.load` accepts either `.dfc` text or `.dfcb` octets. A
virtual card implements `DfcTransport`, so the reader path is the same shape as
a serial, NFC, or smart-card transport:

```java
DfcCredential credential = DfcCredentialCodec.load(Files.readAllBytes(path));
credential.validate();

try (DfcVirtualPicc picc = DfcVirtualPicc.create(credential);
     DfcReader reader = new DfcReader(picc)) {
  DfcActivation activation = picc.activate();
  DfcResponse version = reader.exchange(
      DfcCommand.getVersion(),
      DfcReader.Framing.ISO_7816,
      DfcReader.Communication.PLAIN);
}
```

Both classes own native resources and should be used in try-with-resources.
`DfcReader` is blocking and serializes its methods. Hardware transports should
throw `IOException` when their link fails; the reader then clears its session.

The runnable [Java example](../../examples/java/README.md) loads a credential,
activates it, and executes the multi-frame `GetVersion` exchange. Android
consumers should use the separate [Android binding](../android/README.md).

## Build and verify

From the repository root, build the JNI library and run the binding smoke test:

```sh
cmake -S . -B build-jni -DCMAKE_BUILD_TYPE=Release \
  -DDFC_BUILD_SHARED=OFF -DDFC_BUILD_TESTS=OFF -DDFC_BUILD_JNI=ON \
  -DDFC_ROLE=simulator -DDFC_PROFILE=full_ev3 -DDFC_CRYPTO=mbedtls
cmake --build build-jni --parallel
mkdir -p build-jni/java
javac --release 17 -d build-jni/java \
  bindings/java/src/main/java/com/cindersocket/dfc/*.java \
  tests/java/DfcJniSmokeTest.java tests/java/DfcJniReplayRandomTest.java \
  examples/java/DfcTransceiveExample.java
java -Djava.library.path=build-jni -cp build-jni/java DfcJniSmokeTest \
  examples/credentials/v6-minimal.dfc examples/credentials/v6-maximal.dfc
java -Djava.library.path=build-jni -cp build-jni/java DfcJniReplayRandomTest \
  examples/credentials/v6-minimal.dfc
java -Djava.library.path=build-jni -cp build-jni/java DfcTransceiveExample \
  examples/credentials/v6-minimal.dfc
```

The native library must be discoverable through `java.library.path` or the
platform loader. JNI rejects an incompatible DFC ABI before using its layouts.
