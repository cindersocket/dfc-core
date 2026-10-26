package com.cindersocket.dfc;

import java.util.Arrays;

public final class DfcSecretLifetimeTest {
  private static void check(boolean condition, String message) {
    if (!condition)
      throw new AssertionError(message);
  }

  public static void main(String[] args) {
    byte[] credentialBytes = {0x60, 1, 2, 3};
    DfcCredential credential = new DfcCredential(credentialBytes);
    int hash = credential.hashCode();
    credential.close();
    check(Arrays.equals(credentialBytes, new byte[credentialBytes.length]),
        "credential was not wiped");
    check(credential.hashCode() == hash, "credential hash changed after close");

    byte[] diagnosticBytes = new byte[DfcJniLayout.DFC_JNI_DIAGNOSTIC_SIZE];
    Arrays.fill(diagnosticBytes, (byte) 0x5a);
    new DfcDiagnosticSnapshot(diagnosticBytes).close();
    check(Arrays.equals(diagnosticBytes, new byte[diagnosticBytes.length]),
        "diagnostic was not wiped");
    try {
      new DfcDiagnosticSnapshot(new byte[DfcJniLayout.DFC_JNI_DIAGNOSTIC_SIZE - 1]);
      throw new AssertionError("short diagnostic layout was accepted");
    } catch (IllegalArgumentException expected) {
      // The Java decoder must not silently follow a stale native packing layout.
    }

    byte[] fallbackBytes = {1, 2, 3, 4};
    DfcCleaner.Cleanable fallback =
        DfcCleaner.register(new Object(), () -> Arrays.fill(fallbackBytes, (byte) 0));
    fallback.clean();
    check(Arrays.equals(fallbackBytes, new byte[fallbackBytes.length]), "cleaner did not wipe");
  }
}
