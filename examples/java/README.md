# Java transceive example

This command-line example loads a `.dfc` or `.dfcb` credential, activates an
in-process card, and sends `GetVersion` through `DfcReader`. The exchange uses
the public transport interface and exercises additional-frame handling rather
than calling the emulator directly.

From the repository root, build the JNI library and run it with Java 17:

```sh
cmake -S . -B build-jni -DCMAKE_BUILD_TYPE=Release \
  -DDFC_BUILD_SHARED=OFF -DDFC_BUILD_TESTS=OFF -DDFC_BUILD_JNI=ON \
  -DDFC_ROLE=simulator -DDFC_PROFILE=full_ev3 -DDFC_CRYPTO=mbedtls
cmake --build build-jni --parallel
mkdir -p build-jni/java
javac --release 17 -d build-jni/java \
  bindings/java/src/main/java/com/cindersocket/dfc/*.java \
  examples/java/DfcTransceiveExample.java
java -Djava.library.path=build-jni -cp build-jni/java DfcTransceiveExample \
  examples/credentials/v6-minimal.dfc
```

Use a physical transport by implementing `DfcTransport` and passing it to
`DfcReader` in place of `DfcVirtualPicc`.
