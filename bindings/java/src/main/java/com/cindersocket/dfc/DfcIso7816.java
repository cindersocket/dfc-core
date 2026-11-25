package com.cindersocket.dfc;

import java.util.Arrays;
import java.util.Objects;

/** Helpers for standard ISO/IEC 7816 APDUs used alongside native DESFire commands. */
public final class DfcIso7816 {
  private DfcIso7816() {}

  /**
   * Builds an ISO APPEND RECORD command APDU.
   *
   * @param shortFileId zero for the current file, or an SFI from 1 through 30
   * @param data record data to append
   * @return the complete command APDU
   * @throws IllegalArgumentException if the SFI or data length is invalid
   * @throws NullPointerException if {@code data} is null
   */
  public static byte[] appendRecord(int shortFileId, byte[] data) {
    Objects.requireNonNull(data, "data");
    if (shortFileId < 0 || shortFileId > 0x1e)
      throw new IllegalArgumentException("shortFileId");
    if (data.length == 0 || data.length > 0xffff)
      throw new IllegalArgumentException("data length");
    int headerLength = data.length <= 0xff ? 5 : 7;
    byte[] apdu = new byte[headerLength + data.length];
    apdu[1] = (byte) 0xe2;
    apdu[3] = (byte) (shortFileId << 3);
    if (headerLength == 5) {
      apdu[4] = (byte) data.length;
    } else {
      apdu[5] = (byte) (data.length >> 8);
      apdu[6] = (byte) data.length;
    }
    System.arraycopy(data, 0, apdu, headerLength, data.length);
    return apdu;
  }

  /**
   * Splits an ISO response APDU into its data and unsigned two-byte status word.
   *
   * @param response complete response APDU
   * @return copied response data and status word
   * @throws IllegalArgumentException if the response has no status word
   * @throws NullPointerException if {@code response} is null
   */
  public static Response parseResponse(byte[] response) {
    Objects.requireNonNull(response, "response");
    if (response.length < 2)
      throw new IllegalArgumentException("response must include SW1 and SW2");
    int status =
        ((response[response.length - 2] & 0xff) << 8) | (response[response.length - 1] & 0xff);
    return new Response(Arrays.copyOf(response, response.length - 2), status);
  }

  /**
   * A standard ISO response APDU after status-word separation.
   *
   * @param data response data without SW1 and SW2
   * @param statusWord unsigned two-byte ISO status word
   */
  public record Response(byte[] data, int statusWord) {
    /**
     * Defensively copies response data.
     *
     * @param data response data without SW1 and SW2
     * @param statusWord unsigned two-byte ISO status word
     */
    public Response {
      data = Objects.requireNonNull(data, "data").clone();
      if ((statusWord & ~0xffff) != 0)
        throw new IllegalArgumentException("statusWord");
    }

    /**
     * Returns response data.
     *
     * @return a defensive copy
     */
    @Override
    public byte[] data() {
      return data.clone();
    }
  }
}
