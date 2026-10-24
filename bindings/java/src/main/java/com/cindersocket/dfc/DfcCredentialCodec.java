package com.cindersocket.dfc;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

/** Native-backed parsing and encoding for .dfc text and .dfcb bytes. */
public final class DfcCredentialCodec {
  private DfcCredentialCodec() {}
  public static DfcCredential parse(String text) throws DfcException {
    byte[] encoded = Objects.requireNonNull(text, "text").getBytes(StandardCharsets.UTF_8);
    try {
      return new DfcCredential(DfcNative.credentialParse(encoded));
    } finally {
      java.util.Arrays.fill(encoded, (byte) 0);
    }
  }
  public static DfcCredential decode(byte[] binary) throws DfcException {
    Objects.requireNonNull(binary, "binary");
    if (binary.length == 0 || binary[0] != 0x60)
      throw new DfcException("not a binary DFC credential", -1, 0, 0);
    return new DfcCredential(DfcNative.credentialLoad(binary));
  }
  public static DfcCredential load(byte[] content) throws DfcException {
    return new DfcCredential(DfcNative.credentialLoad(Objects.requireNonNull(content, "content")));
  }
  public static DfcCredential load(String text) throws DfcException {
    byte[] encoded = Objects.requireNonNull(text, "text").getBytes(StandardCharsets.UTF_8);
    try {
      return load(encoded);
    } finally {
      java.util.Arrays.fill(encoded, (byte) 0);
    }
  }
}
