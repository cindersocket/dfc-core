package com.cindersocket.dfc;

import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public final class DfcCompatibilityTest {
  @Test
  public void mismatchedNativeLayoutIsRejectedBeforeHandles() {
    UnsatisfiedLinkError error = assertThrows(UnsatisfiedLinkError.class,
        () -> DfcCompatibility.requireCompatible((int) DfcLayout.DFC_FFI_ABI_VERSION, 1, 2));
    assertTrue(error.getMessage().contains("layout fingerprint mismatch"));
  }
}
