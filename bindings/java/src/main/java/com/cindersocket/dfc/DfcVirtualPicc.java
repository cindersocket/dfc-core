package com.cindersocket.dfc;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicLong;

/** A native DESFire-compatible virtual card. Methods are serialized. */
public final class DfcVirtualPicc implements DfcTransport, AutoCloseable {
  private final State state;
  private final DfcCleaner.Cleanable cleanable;
  private static final class State implements Runnable {
    private final AtomicLong handle;
    State(long handle) {
      this.handle = new AtomicLong(handle);
    }
    long require() {
      long value = handle.get();
      if (value == 0)
        throw new IllegalStateException("virtual PICC is closed");
      return value;
    }
    @Override
    public void run() {
      long value = handle.getAndSet(0);
      if (value != 0)
        DfcNative.piccFree(value);
    }
  }
  private DfcVirtualPicc(long handle) {
    state = new State(handle);
    cleanable = DfcCleaner.register(this, state);
  }
  public static DfcVirtualPicc create(DfcCredential credential) throws DfcException {
    Objects.requireNonNull(credential, "credential");
    return new DfcVirtualPicc(DfcNative.piccCreate(credential.encode(), null));
  }
  /**
   * Creates a card whose random requests consume the supplied script in order.
   *
   * <p>If a request cannot be satisfied in full, it consumes no script bytes and that operation
   * fails with status {@code -5}. Later operations may continue, including a smaller random draw.
   */
  public static DfcVirtualPicc createForReplay(DfcCredential credential, byte[] randomScript)
      throws DfcException {
    Objects.requireNonNull(credential, "credential");
    Objects.requireNonNull(randomScript, "randomScript");
    return new DfcVirtualPicc(DfcNative.piccCreate(credential.encode(), randomScript));
  }
  public synchronized DfcActivation activate() throws DfcException {
    ByteBuffer data = ByteBuffer.wrap(DfcNative.piccActivate(state.require()));
    byte[] uid = new byte[data.get() & 0xff];
    data.get(uid);
    byte[] atqa = new byte[data.get() & 0xff];
    data.get(atqa);
    int sak = data.get() & 0xff;
    byte[] ats = new byte[data.get() & 0xff];
    data.get(ats);
    return new DfcActivation(uid, atqa, sak, ats);
  }
  /** Appends bytes to this replay card's random queue without exposing future events early. */
  public synchronized void appendReplayRandom(byte[] bytes) throws DfcException {
    DfcNative.piccAppendReplayRandom(state.require(), Objects.requireNonNull(bytes, "bytes"));
  }
  /** Returns the number of bytes currently available in this replay card's random queue. */
  public synchronized int replayRandomRemaining() throws DfcException {
    return DfcNative.piccReplayRandomRemaining(state.require());
  }
  public synchronized byte[] exchange(byte[] command) throws DfcException {
    return DfcNative.piccExchange(
        state.require(), Objects.requireNonNull(command, "command"), false);
  }
  public synchronized byte[] exchangeFrame(byte[] frame) throws DfcException {
    return DfcNative.piccExchange(state.require(), Objects.requireNonNull(frame, "frame"), true);
  }
  public synchronized DfcPiccSnapshot snapshot() throws DfcException {
    ByteBuffer data = ByteBuffer.wrap(DfcNative.piccSnapshot(state.require()));
    int selected = data.get() & 0xff;
    int applicationIndex = data.getInt();
    byte[] aid = new byte[3];
    data.get(aid);
    boolean dirty = data.get() != 0;
    int authenticationMode = data.get() & 0xff;
    int authenticationKeyNumber = data.get() & 0xff;
    int ev2Counter = data.getInt();
    boolean ev2Active = data.get() != 0;
    boolean virtualCardSelected = data.get() != 0;
    boolean proximityVerified = data.get() != 0;
    return new DfcPiccSnapshot(selected, applicationIndex, aid, dirty, authenticationMode,
        authenticationKeyNumber, ev2Counter, ev2Active, virtualCardSelected, proximityVerified);
  }
  @Override
  public byte[] transceive(byte[] frame) throws IOException {
    try {
      return exchange(frame);
    } catch (DfcException error) {
      throw new IOException(error);
    }
  }
  public synchronized void fieldOff() throws DfcException {
    DfcNative.piccFieldOff(state.require());
  }
  public synchronized void resetProtocol() throws DfcException {
    DfcNative.piccResetProtocol(state.require());
  }
  public synchronized void advanceTime(long milliseconds) throws DfcException {
    if (milliseconds < 0 || milliseconds > 0xffff_ffffL)
      throw new IllegalArgumentException("milliseconds");
    DfcNative.piccAdvanceTime(state.require(), milliseconds);
  }
  public synchronized DfcCredential exportCredential() throws DfcException {
    return new DfcCredential(DfcNative.piccExport(state.require()));
  }
  public synchronized void markPersisted() throws DfcException {
    DfcNative.piccMarkPersisted(state.require());
  }
  @Override
  public synchronized void close() {
    cleanable.clean();
  }
}
