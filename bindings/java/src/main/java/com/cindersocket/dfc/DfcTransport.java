package com.cindersocket.dfc;

import java.io.IOException;

/** Carries one complete reader frame to a card and returns its response. */
@FunctionalInterface
public interface DfcTransport {
  /**
   * Exchanges one complete frame using the framing selected for the reader operation. The frame is
   * either a native command ({@code INS || data}) or an ISO 7816 command APDU; the response uses
   * the corresponding native ({@code status || data}) or ISO ({@code data || 91 || status}) form.
   *
   * @param frame command frame; implementations must not retain or modify it
   * @return complete response frame including its status bytes
   * @throws IOException if the transport cannot complete the exchange
   */
  byte[] transceive(byte[] frame) throws IOException;
}
