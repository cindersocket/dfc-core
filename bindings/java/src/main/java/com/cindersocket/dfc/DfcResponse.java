package com.cindersocket.dfc;

import java.util.Objects;

/**
 * The unwrapped response data and card status from one completed exchange.
 *
 * @param data response payload without the status byte
 * @param status unsigned one-byte native card status
 */
public record DfcResponse(byte[] data, int status) {
  /**
   * Validates the status and defensively copies the payload.
   * @param data response payload without the status byte
   * @param status unsigned one-byte native card status
   * @throws IllegalArgumentException if {@code status} is outside the unsigned byte range
   * @throws NullPointerException if {@code data} is null
   */
  public DfcResponse {
    data = Objects.requireNonNull(data, "data").clone();
    if ((status & ~0xff) != 0)
      throw new IllegalArgumentException("status");
  }
  /**
   * Returns response data.
   * @return a defensive copy without the status byte
   */
  @Override
  public byte[] data() {
    return data.clone();
  }
  /**
   * Tests the status.
   * @return whether the card reported success
   */
  public boolean successful() {
    return status == 0;
  }
}
