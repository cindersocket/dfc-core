package com.cindersocket.dfc;

/** Public reader-session state. Session keys remain inside the native core. */
public record DfcReaderSession(int authenticationMode, int keyNumber, int ev2CommandCounter,
    byte[] ev2TransactionIdentifier, byte[] ev2CardCapabilities, byte[] ev2ReaderCapabilities) {
  public DfcReaderSession {
    ev2TransactionIdentifier = ev2TransactionIdentifier.clone();
    ev2CardCapabilities = ev2CardCapabilities.clone();
    ev2ReaderCapabilities = ev2ReaderCapabilities.clone();
  }
  @Override
  public byte[] ev2TransactionIdentifier() {
    return ev2TransactionIdentifier.clone();
  }
  @Override
  public byte[] ev2CardCapabilities() {
    return ev2CardCapabilities.clone();
  }
  @Override
  public byte[] ev2ReaderCapabilities() {
    return ev2ReaderCapabilities.clone();
  }
}
