package com.cindersocket.dfc;

/**
 * Public reader-session state. Session keys remain inside the native core.
 *
 * @param authenticationMode active authentication family
 * @param keyNumber active key number, or null while unauthenticated
 * @param ev2CommandCounter current EV2 command counter, or null outside EV2
 * @param ev2TransactionIdentifier defensive copy of the four-byte transaction identifier, or an
 *     empty array outside EV2
 * @param ev2CardCapabilities defensive copy of the six-byte card capabilities, or an empty array
 *     outside EV2
 * @param ev2ReaderCapabilities defensive copy of the six-byte reader capabilities, or an empty
 *     array outside EV2
 */
public record DfcReaderSession(AuthenticationMode authenticationMode, Integer keyNumber,
    Integer ev2CommandCounter, byte[] ev2TransactionIdentifier, byte[] ev2CardCapabilities,
    byte[] ev2ReaderCapabilities) {
  /** Authentication family active in a reader session. */
  public enum AuthenticationMode {
    /** The reader is unauthenticated. */ NONE,
    /** Legacy D40 authentication. */ LEGACY,
    /** ISO authentication. */ ISO,
    /** AES authentication with EV1 secure messaging. */ AES,
    /** EV2 secure messaging. */ EV2
  }
  /**
   * Defensively copies the exported session values.
   * @param authenticationMode active authentication family
   * @param keyNumber active key number, or null while unauthenticated
   * @param ev2CommandCounter current EV2 command counter, or null outside EV2
   * @param ev2TransactionIdentifier four-byte transaction identifier, or empty outside EV2
   * @param ev2CardCapabilities six-byte card capabilities, or empty outside EV2
   * @param ev2ReaderCapabilities six-byte reader capabilities, or empty outside EV2
   */
  public DfcReaderSession {
    ev2TransactionIdentifier = ev2TransactionIdentifier.clone();
    ev2CardCapabilities = ev2CardCapabilities.clone();
    ev2ReaderCapabilities = ev2ReaderCapabilities.clone();
  }
  /**
   * Returns the transaction identifier.
   * @return a defensive four-byte copy
   */
  @Override
  public byte[] ev2TransactionIdentifier() {
    return ev2TransactionIdentifier.clone();
  }
  /**
   * Returns card capabilities.
   * @return a defensive six-byte copy
   */
  @Override
  public byte[] ev2CardCapabilities() {
    return ev2CardCapabilities.clone();
  }
  /**
   * Returns reader capabilities.
   * @return a defensive six-byte copy
   */
  @Override
  public byte[] ev2ReaderCapabilities() {
    return ev2ReaderCapabilities.clone();
  }
}
