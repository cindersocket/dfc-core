package com.cindersocket.dfc.sample;

import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;

import com.cindersocket.dfc.DfcCommand;
import com.cindersocket.dfc.DfcException;
import com.cindersocket.dfc.DfcReader;

/** Runs the JNI exception probe inside the minified target APK. */
public final class MinifiedExceptionProbeActivity extends Activity {
  @Override
  protected void onCreate(Bundle state) {
    super.onCreate(state);

    TextView result = new TextView(this);
    result.setId(android.R.id.text1);
    result.setText(runProbe());
    setContentView(result);
  }

  private static String runProbe() {
    try (DfcReader reader = new DfcReader(
             command -> { throw new AssertionError("invalid arguments reached the transport"); })) {
      reader.exchange(DfcCommand.getVersion(), DfcReader.Framing.ISO_7816,
          DfcReader.Communication.PLAIN, Integer.MAX_VALUE);
      return "FAIL:no exception";
    } catch (DfcException expected) {
      return expected.status() == 0 ? "FAIL:zero status" : "PASS:" + expected.status();
    } catch (Throwable error) {
      return "FAIL:" + error.getClass().getName() + ":" + error.getMessage();
    }
  }
}
