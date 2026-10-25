package com.cindersocket.dfc.sample;

import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.fail;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import com.cindersocket.dfc.DfcCommand;
import com.cindersocket.dfc.DfcException;
import com.cindersocket.dfc.DfcReader;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public final class MinifiedExceptionTest {
  @Test
  public void nativeExceptionKeepsItsClassAndConstructor() throws Exception {
    try (DfcReader reader = new DfcReader(command -> {
      fail("invalid arguments must fail before transport");
      return new byte[0];
    })) {
      reader.exchange(DfcCommand.getVersion(), DfcReader.Framing.ISO_7816,
          DfcReader.Communication.PLAIN, Integer.MAX_VALUE);
      fail("invalid clear-header length must fail in native code");
    } catch (DfcException expected) {
      assertNotEquals(0, expected.status());
    }
  }
}
