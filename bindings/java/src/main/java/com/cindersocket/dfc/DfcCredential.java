package com.cindersocket.dfc;

import java.util.Arrays;

/** An immutable, validated DFC credential in canonical binary form. */
public final class DfcCredential {
  private final byte[] binary;
  DfcCredential(byte[] binary) {
    this.binary = binary.clone();
  }
  public byte[] encode() {
    return binary.clone();
  }
  public String writeText() throws DfcException {
    return DfcNative.credentialText(binary);
  }
  public void validate() throws DfcException {
    DfcNative.credentialValidate(binary);
  }
  @Override
  public boolean equals(Object other) {
    return other instanceof DfcCredential credential && Arrays.equals(binary, credential.binary);
  }
  @Override
  public int hashCode() {
    return Arrays.hashCode(binary);
  }
}
