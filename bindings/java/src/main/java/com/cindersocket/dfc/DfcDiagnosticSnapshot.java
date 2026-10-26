package com.cindersocket.dfc;

import java.util.Arrays;

/** Secret-bearing state for diagnostics and conformance tests. */
public final class DfcDiagnosticSnapshot implements AutoCloseable {
  private static final class State implements Runnable {
    private final byte[] bytes;
    State(byte[] bytes) {
      this.bytes = bytes;
    }
    @Override
    public synchronized void run() {
      Arrays.fill(bytes, (byte) 0);
    }
    synchronized boolean equalsRange(byte[] expected, int offset, int length) {
      if (expected.length != length)
        return false;
      int difference = 0;
      for (int i = 0; i < length; i++) difference |= bytes[offset + i] ^ expected[i];
      return difference == 0;
    }
  }
  private final State state;
  private final DfcCleaner.Cleanable cleanable;
  DfcDiagnosticSnapshot(byte[] bytes) {
    if (bytes.length != DfcJniLayout.DFC_JNI_DIAGNOSTIC_SIZE)
      throw new IllegalArgumentException("invalid diagnostic snapshot length");
    state = new State(bytes);
    cleanable = DfcCleaner.register(this, state);
  }
  /**
   * Compares the transaction identifier without returning another secret copy.
   * @param expected expected four-byte identifier
   * @return whether it matches in constant time
   */
  public boolean transactionIdentifierEquals(byte[] expected) {
    return equalsRange(expected, DfcJniLayout.DFC_JNI_DIAGNOSTIC_TRANSACTION_ID_OFFSET, 4);
  }
  /**
   * Compares the encryption key without returning another secret copy.
   * @param expected expected 16-byte key
   * @return whether it matches in constant time
   */
  public boolean encryptionKeyEquals(byte[] expected) {
    return equalsRange(expected, DfcJniLayout.DFC_JNI_DIAGNOSTIC_ENCRYPTION_KEY_OFFSET, 16);
  }
  /**
   * Compares the authentication key without returning another secret copy.
   * @param expected expected 16-byte key
   * @return whether it matches in constant time
   */
  public boolean macKeyEquals(byte[] expected) {
    return equalsRange(expected, DfcJniLayout.DFC_JNI_DIAGNOSTIC_MAC_KEY_OFFSET, 16);
  }
  private boolean equalsRange(byte[] expected, int offset, int length) {
    return state.equalsRange(expected, offset, length);
  }
  /** Clears the managed secret buffer. */
  @Override
  public void close() {
    cleanable.clean();
  }
}
