package com.cindersocket.dfc;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.util.Arrays;
import org.junit.Test;

public final class DfcSecretLifetimeTest {
  @Test
  public void ownedSecretBuffersAreCleared() {
    byte[] credentialBytes = {0x60, 1, 2, 3};
    DfcCredential credential = new DfcCredential(credentialBytes);
    int hash = credential.hashCode();
    credential.close();
    assertArrayEquals(new byte[credentialBytes.length], credentialBytes);
    assertEquals(hash, credential.hashCode());

    byte[] diagnosticBytes = new byte[36];
    Arrays.fill(diagnosticBytes, (byte) 0x5a);
    new DfcDiagnosticSnapshot(diagnosticBytes).close();
    assertArrayEquals(new byte[diagnosticBytes.length], diagnosticBytes);

    byte[] fallbackBytes = {1, 2, 3, 4};
    DfcCleaner.Cleanable fallback =
        DfcCleaner.register(new Object(), () -> Arrays.fill(fallbackBytes, (byte) 0));
    fallback.clean();
    assertArrayEquals(new byte[fallbackBytes.length], fallbackBytes);
  }
}
