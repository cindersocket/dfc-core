package com.cindersocket.dfc;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

/** Native-backed parsing and encoding for .dfc text and .dfcb bytes. */
public final class DfcCredentialCodec {
  private DfcCredentialCodec() {}
  /**
   * Parses UTF-8 credential text.
   * @param text credential text
   * @return owned credential that must be closed
   * @throws DfcException if parsing or validation fails
   */
  public static DfcCredential parse(String text) throws DfcException {
    byte[] encoded = Objects.requireNonNull(text, "text").getBytes(StandardCharsets.UTF_8);
    try {
      return new DfcCredential(DfcNative.credentialParse(encoded));
    } finally {
      java.util.Arrays.fill(encoded, (byte) 0);
    }
  }
  /**
   * Decodes canonical binary credential data.
   * @param binary binary input; the returned credential owns its own copy
   * @return owned credential that must be closed
   * @throws DfcException if decoding or validation fails
   */
  public static DfcCredential decode(byte[] binary) throws DfcException {
    Objects.requireNonNull(binary, "binary");
    if (binary.length == 0 || binary[0] != 0x60)
      throw new DfcException("not a binary DFC credential", -1, 0, 0);
    return new DfcCredential(DfcNative.credentialLoad(binary));
  }
  /**
   * Loads text or binary credential content after format detection.
   * @param content encoded content; the returned credential owns its own copy
   * @return owned credential that must be closed
   * @throws DfcException if parsing, decoding, or validation fails
   */
  public static DfcCredential load(byte[] content) throws DfcException {
    return new DfcCredential(DfcNative.credentialLoad(Objects.requireNonNull(content, "content")));
  }
  /**
   * Loads credential text.
   * @param text credential text
   * @return owned credential that must be closed
   * @throws DfcException if parsing or validation fails
   */
  public static DfcCredential load(String text) throws DfcException {
    byte[] encoded = Objects.requireNonNull(text, "text").getBytes(StandardCharsets.UTF_8);
    try {
      return load(encoded);
    } finally {
      java.util.Arrays.fill(encoded, (byte) 0);
    }
  }
}
