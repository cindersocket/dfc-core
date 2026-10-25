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

  public DfcTransactionMacVerifier(byte[] key, byte[] uid, long counter, int capacity)
      throws DfcException {
    Objects.requireNonNull(key, "key");
    Objects.requireNonNull(uid, "uid");
    if (key.length != 16 || (uid.length != 4 && uid.length != 7) || capacity <= 0)
      throw new IllegalArgumentException("expected 16-byte key, 4- or 7-byte UID and capacity");
    state = new State(DfcNative.transactionMacCreate(capacity, key, uid, counter));
    cleanable = DfcCleaner.register(this, state);
  }

  public synchronized void addData(
      int command, int fileNumber, long offset, long length, byte[] data) throws DfcException {
    Objects.requireNonNull(data, "data");
    DfcNative.transactionMacAddData(state.require(), command, fileNumber, offset, length, data);
  }

  public synchronized void addRecordUpdate(int command, int fileNumber, long recordNumber,
      long offset, long length, byte[] data) throws DfcException {
    Objects.requireNonNull(data, "data");
    DfcNative.transactionMacAddRecord(
        state.require(), command, fileNumber, recordNumber, offset, length, data);
  }

  public synchronized void addValue(int command, int fileNumber, long value) throws DfcException {
    DfcNative.transactionMacAddValue(state.require(), command, fileNumber, value);
  }

  public synchronized void addClearRecord(int fileNumber) throws DfcException {
    DfcNative.transactionMacAddClearRecord(state.require(), fileNumber);
  }

  public synchronized void addReaderId(byte[] current, byte[] encryptedPrevious)
      throws DfcException {
    Objects.requireNonNull(current, "current");
    Objects.requireNonNull(encryptedPrevious, "encryptedPrevious");
    DfcNative.transactionMacAddReaderId(state.require(), current, encryptedPrevious);
  }

  public synchronized boolean verify(byte[] mac) throws DfcException {
    Objects.requireNonNull(mac, "mac");
    return DfcNative.transactionMacVerify(state.require(), mac);
  }

  @Override
  public synchronized void close() {
    cleanable.clean();
  }
}
