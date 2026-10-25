package com.cindersocket.dfc.sample;

import android.app.Activity;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.Bundle;
import android.widget.TextView;

import com.cindersocket.dfc.DfcCommand;
import com.cindersocket.dfc.DfcReader;
import com.cindersocket.dfc.DfcResponse;
import com.cindersocket.dfc.android.IsoDepTransport;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Reads a real ISO-DEP card through the public DFC reader and Android transport APIs. */
public final class MainActivity extends Activity implements NfcAdapter.ReaderCallback {
  private final ExecutorService worker = Executors.newSingleThreadExecutor();
  private TextView status;

  @Override
  protected void onCreate(Bundle state) {
    super.onCreate(state);
    status = new TextView(this);
    status.setPadding(48, 48, 48, 48);
    status.setText("Tap a DESFire card to read GetVersion.");
    setContentView(status);
  }

  @Override
  protected void onResume() {
    super.onResume();
    NfcAdapter adapter = NfcAdapter.getDefaultAdapter(this);
    if (adapter == null) {
      status.setText("This device has no NFC adapter.");
      return;
    }

    // Reader mode avoids the NDEF dispatcher taking ownership before this app can transceive.
    adapter.enableReaderMode(
        this, this, NfcAdapter.FLAG_READER_NFC_A | NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK, null);
  }

  @Override
  protected void onPause() {
    NfcAdapter adapter = NfcAdapter.getDefaultAdapter(this);
    if (adapter != null) {
      adapter.disableReaderMode(this);
    }
    super.onPause();
  }

  @Override
  public void onTagDiscovered(Tag tag) {
    // NFC callbacks must not block while GetVersion follows its additional frames.
    worker.execute(() -> readVersion(tag));
  }

  private void readVersion(Tag tag) {
    IsoDep isoDep = IsoDep.get(tag);
    if (isoDep == null) {
      show("Tag does not support ISO-DEP.");
      return;
    }

    try {
      isoDep.connect();
      try (DfcReader reader = new DfcReader(new IsoDepTransport(isoDep))) {
        DfcResponse response = reader.exchange(
            DfcCommand.getVersion(), DfcReader.Framing.ISO_7816, DfcReader.Communication.PLAIN, -1);
        show("GetVersion: status=" + String.format("%02X", response.status())
            + ", data=" + hex(response.data()));
      }
    } catch (Exception error) {
      show("Read failed: " + error.getMessage());
    } finally {
      try {
        isoDep.close();
      } catch (Exception ignored) {
        // The tag may already have left the field; there is no connection left to recover.
      }
    }
  }

  private void show(String text) {
    runOnUiThread(() -> status.setText(text));
  }

  private static String hex(byte[] value) {
    StringBuilder result = new StringBuilder(value.length * 2);
    for (byte item : value) {
      result.append(String.format("%02X", item & 0xff));
    }
    return result.toString();
  }

  @Override
  protected void onDestroy() {
    worker.shutdownNow();
    super.onDestroy();
  }
}
