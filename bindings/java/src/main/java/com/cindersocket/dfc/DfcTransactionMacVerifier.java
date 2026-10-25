package com.cindersocket.dfc;

import java.util.Objects;
import java.util.concurrent.atomic.AtomicLong;

/** Collects plain transaction inputs and verifies one returned receipt. */
public final class DfcTransactionMacVerifier implements AutoCloseable {
  private static final class State implements Runnable {
    private final AtomicLong handle;
    State(long handle) {
      this.handle = new AtomicLong(handle);
    }
    long require() {
      long value = handle.get();
      if (value == 0)
        throw new IllegalStateException("transaction verifier is closed");
      return value;
    }
    @Override
    public void run() {
      long value = handle.getAndSet(0);
      if (value != 0)
        DfcNative.transactionMacFree(value);
    }
  }

  private final State state;
  private final DfcCleaner.Cleanable cleanable;

  /**
   * Creates a bounded transaction transcript verifier.
   * @param key 16-byte transaction-MAC key; the caller retains ownership
   * @param uid four- or seven-byte card UID
   * @param counter unsigned transaction counter carried in a Java {@code long}
   * @param capacity maximum transcript size in bytes
   * @throws DfcException if native allocation or initialization fails
   * @throws IllegalArgumentException if the key or UID length is invalid, or capacity is not
   *     positive
   * @throws NullPointerException if {@code key} or {@code uid} is null
   */
  public DfcTransactionMacVerifier(byte[] key, byte[] uid, long counter, int capacity)
      throws DfcException {
    Objects.requireNonNull(key, "key");
    Objects.requireNonNull(uid, "uid");
    if (key.length != 16 || (uid.length != 4 && uid.length != 7) || capacity <= 0)
      throw new IllegalArgumentException("expected 16-byte key, 4- or 7-byte UID and capacity");
    state = new State(DfcNative.transactionMacCreate(capacity, key, uid, counter));
    cleanable = DfcCleaner.register(this, state);
  }

  /**
   * Adds a data-file operation in its clear semantic form.
   * @param command unsigned one-byte instruction
   * @param fileNumber unsigned one-byte file number
   * @param offset unsigned 32-bit byte offset
   * @param length unsigned 32-bit transferred length
   * @param data clear operation data
   * @throws DfcException if the transcript rejects the operation or exceeds capacity
   */
  public synchronized void addData(
      int command, int fileNumber, long offset, long length, byte[] data) throws DfcException {
    Objects.requireNonNull(data, "data");
    DfcNative.transactionMacAddData(state.require(), command, fileNumber, offset, length, data);
  }

  /**
   * Adds a record update in its clear semantic form.
   * @param command unsigned one-byte instruction
   * @param fileNumber unsigned one-byte file number
   * @param recordNumber unsigned 32-bit record number
   * @param offset unsigned 32-bit byte offset
   * @param length unsigned 32-bit transferred length
   * @param data clear operation data
   * @throws DfcException if the transcript rejects the operation or exceeds capacity
   */
  public synchronized void addRecordUpdate(int command, int fileNumber, long recordNumber,
      long offset, long length, byte[] data) throws DfcException {
    Objects.requireNonNull(data, "data");
    DfcNative.transactionMacAddRecord(
        state.require(), command, fileNumber, recordNumber, offset, length, data);
  }

  /**
   * Adds a value-file operation.
   * @param command unsigned one-byte instruction
   * @param fileNumber unsigned one-byte file number
   * @param value signed 32-bit value encoded in a Java {@code long}
   * @throws DfcException if the transcript rejects the operation or exceeds capacity
   */
  public synchronized void addValue(int command, int fileNumber, long value) throws DfcException {
    DfcNative.transactionMacAddValue(state.require(), command, fileNumber, value);
  }

  /**
   * Adds a ClearRecordFile operation.
   * @param fileNumber unsigned one-byte file number
   * @throws DfcException if the transcript rejects the operation or exceeds capacity
   */
  public synchronized void addClearRecord(int fileNumber) throws DfcException {
    DfcNative.transactionMacAddClearRecord(state.require(), fileNumber);
  }

  /**
   * Adds reader-identifier state to the transcript.
   * @param current current reader identifier
   * @param encryptedPrevious encrypted previous reader identifier
   * @throws DfcException if the transcript rejects the operation or exceeds capacity
   */
  public synchronized void addReaderId(byte[] current, byte[] encryptedPrevious)
      throws DfcException {
    Objects.requireNonNull(current, "current");
    Objects.requireNonNull(encryptedPrevious, "encryptedPrevious");
    DfcNative.transactionMacAddReaderId(state.require(), current, encryptedPrevious);
  }

  /**
   * Verifies a returned transaction receipt in constant time.
   * @param mac transmitted receipt bytes
   * @return whether the receipt matches the accumulated transcript
   * @throws DfcException if the receipt shape or native state is invalid
   */
  public synchronized boolean verify(byte[] mac) throws DfcException {
    Objects.requireNonNull(mac, "mac");
    return DfcNative.transactionMacVerify(state.require(), mac);
  }

  /** Releases and wipes native transcript state. */
  @Override
  public synchronized void close() {
    cleanable.clean();
  }
}
