# DFC for Java

The Java 17 binding exposes credential codecs, an in-process virtual card, and
a blocking reader over any `DfcTransport`. Parsing, validation, card behavior,
and secure messaging run in the native DFC core through JNI.

Add the Java artifact and the native classifier for the deployment target:

```xml
<dependency>
  <groupId>com.cindersocket</groupId>
  <artifactId>dfc-core</artifactId>
  <version>2.0.0</version>
</dependency>
<dependency>
  <groupId>com.cindersocket</groupId>
  <artifactId>dfc-core</artifactId>
  <version>2.0.0</version>
  <classifier>linux-x86_64</classifier>
</dependency>
```

Available classifiers are listed in the repository's
[package contract](../../release-artifacts.json). The binding loads the native
library from that classifier jar when it is not installed system-wide.

## API map

| Type | Purpose |
|---|---|
| `DfcCredentialCodec`, `DfcCredential` | Read, validate, and write credential files |
| `DfcVirtualPicc`, `DfcReader`, `DfcCommand` | Emulate or drive a card while retaining raw responses |
| `DfcResponses` | Decode version, directory, file-settings, and key responses into typed records |
| `DfcKeyDiversification` | Derive AES and two- or three-key TDEA application keys |
| `DfcSdm` | Authenticate ASCII SDM input and return verified mirrored fields |
| `DfcTransactionMacVerifier` | Reconstruct transaction input and verify its returned receipt |

`DfcSdm.verify` authenticates one message. The backend must persist the last
accepted read counter for the relevant card and application context, then reject
duplicate or older counters before acting on the result. The binding does not
store replay state.

`DfcTransactionMacVerifier` follows the
[native transaction-input contract](../../src/dfc_transaction_mac.h) for its
supported commands, fields, padding, and card-order rules. Receipt counter
history and duplicate detection remain application policy.

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
`DfcReader.exchange(..., int encryptedHeaderLength)` passes the clear-header length
to the native core unchanged (-1 derives it from the instruction). The core owns the
valid range; a refused value throws `DfcException` with status `-1`
(`DFC_FFI_INVALID_ARGUMENT`) and leaves the reader usable. The JNI layer likewise refuses
instruction, communication, cipher, key and algorithm values outside 0..255 with the same
exception instead of wrapping them.

Elapsed milliseconds outside the native unsigned 32-bit range are refused before
the JNI call. Public `DfcVirtualPicc.advanceTime` reports that range as an
`IllegalArgumentException`; raw JNI callers receive `DfcException` status `-1`.

`DfcReader` is blocking and serializes its methods. Hardware transports should
throw `IOException` when their link fails; the reader then clears its session.
`DfcCommand.selectApplication` accepts the same human-readable AID byte order
used by credential text and converts it to wire order.

`DfcVirtualPicc.createForReplay` consumes its random script in order. Each native
random request must fit completely in the remaining script. An undersized request
consumes no bytes, fails that operation with status `-5`, and leaves later
operations usable. `snapshot()` remains available after failure so callers can
verify that card state did not change. An empty script is valid and fails on its
first random request. Use `appendReplayRandom` immediately before the event that
needs those bytes; `replayRandomRemaining` exposes the current queue length for
test assertions. `clearReplayRandom` wipes and discards unread bytes so the next
event starts with newly appended replay data.

The runnable [Java example](https://github.com/cindersocket/dfc-core/tree/master/examples/java) loads a credential,
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
  tests/java/DfcSecretLifetimeTest.java \
  tests/java/DfcAdvancedApiTest.java \
  examples/java/DfcTransceiveExample.java
java -cp build-jni/java com.cindersocket.dfc.DfcSecretLifetimeTest
java -Djava.library.path=build-jni -cp build-jni/java DfcJniSmokeTest \
  examples/credentials/v6-minimal.dfc examples/credentials/v6-maximal.dfc
java -Djava.library.path=build-jni -cp build-jni/java DfcJniReplayRandomTest \
  examples/credentials/v6-minimal.dfc
java -Djava.library.path=build-jni -cp build-jni/java DfcAdvancedApiTest
java -Djava.library.path=build-jni -cp build-jni/java DfcTransceiveExample \
  examples/credentials/v6-minimal.dfc
javadoc -quiet -public -Xdoclint:all -Werror \
  -d build-jni/javadoc \
  bindings/java/src/main/java/com/cindersocket/dfc/*.java
```

The Javadoc command is a required build gate. It rejects malformed comments,
missing references, and warnings rather than publishing partial API docs.

The native library must be discoverable through `java.library.path` or the
platform loader. JNI compares the linked core's layout fingerprint with the
layout compiled into JNI before constructing a handle. Java and Android
initialization fails clearly if any shared field or binding-visible numeric
constant differs.


## Conformance vectors

The DESFire conformance vectors replay through this binding's virtual card: compile `tests/java/DfcReplayPlanTest.java` with the binding and run it with `-Djava.library.path=build-jni`, passing `tests/replay-plans`. It reports how many vectors it replayed and skipped. See [Replay plans](../../docs/conformance-vector-format.md#replay-plans).

## Secret lifetime

Card snapshots exclude session keys. JNI clears native snapshot, credential,
and temporary output buffers on every exit. Java arrays cannot prevent copies
made by the VM or application, so callers should close `DfcCredential` promptly
and clear arrays they own. A cleaner clears owned credential and diagnostic
buffers if explicit close is missed; its timing is intentionally unspecified.

## Security

Report suspected vulnerabilities through the project's
[private reporting process](https://github.com/cindersocket/dfc-core/security/policy).
