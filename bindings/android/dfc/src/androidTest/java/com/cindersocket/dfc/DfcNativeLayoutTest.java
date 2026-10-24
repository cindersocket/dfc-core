package com.cindersocket.dfc;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public final class DfcNativeLayoutTest {
  @Test
  public void mismatchedNativeLibraryFailsBeforeHandleCreation() throws Exception {
    try {
      DfcCredentialCodec.load(new byte[0]);
    } catch (UnsatisfiedLinkError expected) {
      assertTrue(expected.getMessage().contains("layout fingerprint mismatch"));
      return;
    } catch (ExceptionInInitializerError expected) {
      Throwable cause = expected.getCause();
      assertTrue(cause instanceof UnsatisfiedLinkError);
      assertTrue(cause.getMessage().contains("layout fingerprint mismatch"));
      return;
    }
    fail("mismatched native library initialized");
  }
}
