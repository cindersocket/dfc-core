package com.cindersocket.dfc;

final class DfcCompatibility {
  private DfcCompatibility() {}

  static void requireCompatible(int version, long fingerprint, long expectedFingerprint) {
    if (version != DfcLayout.DFC_FFI_ABI_VERSION)
      throw new UnsatisfiedLinkError(
          "dfc JNI ABI mismatch: expected " + DfcLayout.DFC_FFI_ABI_VERSION + ", found " + version);
    if (fingerprint != expectedFingerprint)
      throw new UnsatisfiedLinkError(
          String.format("dfc JNI layout fingerprint mismatch: native 0x%016x, JNI 0x%016x",
              fingerprint, expectedFingerprint));
  }
}
