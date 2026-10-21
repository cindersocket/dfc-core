package com.cindersocket.dfc;

import java.io.IOException;

/** Carries one ISO 7816 frame to a card and returns its response. */
@FunctionalInterface
public interface DfcTransport {
  byte[] transceive(byte[] frame) throws IOException;
}
