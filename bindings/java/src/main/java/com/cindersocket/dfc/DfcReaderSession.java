package com.cindersocket.dfc;

/**
 * Public reader-session state. Session keys remain inside the native core.
 *
 * @param authenticationMode active authentication instruction: 0 for none, 0x0A for legacy, 0x1A
 *     for ISO, 0xAA for AES, or 0x71 for EV2
 * @param keyNumber active key number; meaningful only when {@code authenticationMode != 0}, and
 *     zero otherwise
 * @param ev2CommandCounter current EV2 command counter; meaningful only when {@code
 *     authenticationMode == 0x71}
 * @param ev2TransactionIdentifier defensive copy of the four-byte transaction identifier; valid
 *     only for authentication mode 0x71
 * @param ev2CardCapabilities defensive copy of the six-byte card capabilities; valid only for
 *     authentication mode 0x71
 * @param ev2ReaderCapabilities defensive copy of the six-byte reader capabilities; valid only for
 *     authentication mode 0x71
 */
public record DfcReaderSession(int authenticationMode, int keyNumber, int ev2CommandCounter,
    byte[] ev2TransactionIdentifier, byte[] ev2CardCapabilities, byte[] ev2ReaderCapabilities) {
  /**
   * Defensively copies the exported session values.
   * @param authenticationMode active authentication instruction: 0 for none, 0x0A for legacy, 0x1A
   *     for ISO, 0xAA for AES, or 0x71 for EV2
   * @param keyNumber active key number; meaningful only when {@code authenticationMode != 0}, and
   *     zero otherwise
   * @param ev2CommandCounter current EV2 command counter, active only for mode 0x71
   * @param ev2TransactionIdentifier four-byte transaction identifier, active only for mode 0x71
   * @param ev2CardCapabilities six-byte card capabilities, active only for mode 0x71
   * @param ev2ReaderCapabilities six-byte reader capabilities, active only for mode 0x71
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
