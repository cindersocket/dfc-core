# Android NFC transceive example

This minimal Android app opens a real `IsoDep` tag and sends `GetVersion`
through `DfcReader`. `IsoDepTransport` forwards every APDU to Android's
`IsoDep.transceive`, while the reader handles additional response frames.

Build the four-ABI AAR and debug APK from the repository root:

```sh
cd bindings/android
./gradlew --no-daemon :dfc:assembleRelease :sample:assembleDebug :dfc:lintRelease
```

Install `examples/android/build/outputs/apk/debug/sample-debug.apk` on an NFC
device, launch **DFC NFC example**, and hold a DESFire card to the antenna. The
screen reports the final status and assembled version data.

The physical NFC path requires an Android device and cannot be verified by a
host test. For a host-runnable exercise of the same Java reader API and its
transport boundary, use the [Java transceive example](../java/README.md).
