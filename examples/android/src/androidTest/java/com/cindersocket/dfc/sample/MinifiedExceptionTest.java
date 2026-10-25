package com.cindersocket.dfc.sample;

import static org.junit.Assert.assertTrue;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Intent;
import android.widget.TextView;
import androidx.test.core.app.ApplicationProvider;
import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public final class MinifiedExceptionTest {
  @Test
  public void nativeExceptionKeepsItsClassAndConstructor() {
    Intent intent = new Intent();
    intent.setComponent(new ComponentName(ApplicationProvider.getApplicationContext(),
        "com.cindersocket.dfc.sample.MinifiedExceptionProbeActivity"));
    intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);

    Activity activity = InstrumentationRegistry.getInstrumentation().startActivitySync(intent);
    try {
      TextView result = activity.findViewById(android.R.id.text1);
      assertTrue(result.getText().toString(), result.getText().toString().startsWith("PASS:"));
    } finally {
      activity.finish();
    }
  }
}
