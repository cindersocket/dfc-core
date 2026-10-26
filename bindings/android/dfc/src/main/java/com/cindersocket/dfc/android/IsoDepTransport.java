package com.cindersocket.dfc.android;

import android.nfc.tech.IsoDep;

import com.cindersocket.dfc.DfcTransport;

import java.io.IOException;
import java.util.Objects;

/** A blocking DFC transport over an already-connected Android IsoDep tag. */
public final class IsoDepTransport implements DfcTransport {
  private final IsoDep isoDep;

  /**
   * Wraps an Android ISO-DEP connection without taking ownership of it.
   *
   * @param isoDep connected tag transport; the caller remains responsible for closing it
   * @throws NullPointerException if {@code isoDep} is {@code null}
   */
  public IsoDepTransport(IsoDep isoDep) {
    this.isoDep = Objects.requireNonNull(isoDep, "isoDep");
  }

  @Override
  public byte[] transceive(byte[] command) throws IOException {
    if (!isoDep.isConnected())
      throw new IOException("IsoDep is not connected");
    return isoDep.transceive(Objects.requireNonNull(command, "command"));
  }
}
