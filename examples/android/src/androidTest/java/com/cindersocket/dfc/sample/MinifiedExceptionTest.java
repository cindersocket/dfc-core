package com.cindersocket.dfc.sample;

import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.fail;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import com.cindersocket.dfc.DfcCredentialCodec;
import com.cindersocket.dfc.DfcException;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public final class MinifiedExceptionTest {
  @Test
  public void nativeExceptionKeepsItsClassAndConstructor() {
    try {
      DfcCredentialCodec.parse("not a credential");
      fail("invalid credentials must fail in native code");
    } catch (DfcException expected) {
      assertNotEquals(0, expected.status());
    }
  }
}
