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
  /**
   * Creates a virtual card from a credential snapshot.
   * @param credential source credential; it remains owned by the caller
   * @return independent virtual card that must be closed
   * @throws DfcException if import, validation, or native allocation fails
   */
  public static DfcVirtualPicc create(DfcCredential credential) throws DfcException {
    Objects.requireNonNull(credential, "credential");
    byte[] encoded = credential.encode();
    try {
      return new DfcVirtualPicc(DfcNative.piccCreate(encoded, null));
    } finally {
      java.util.Arrays.fill(encoded, (byte) 0);
    }
  }
  /**
   * Creates a card whose random requests consume the supplied script in order.
   *
   * <p>If a request cannot be satisfied in full, it consumes no script bytes and that operation
   * fails with status {@code -5}. Later operations may continue, including a smaller random draw.
   *
   * @param credential source credential; it remains owned by the caller
   * @param randomScript bytes consumed by random requests in order
   * @return independent replay card that must be closed
   * @throws DfcException if import, validation, or native allocation fails
   */
  public static DfcVirtualPicc createForReplay(DfcCredential credential, byte[] randomScript)
      throws DfcException {
    Objects.requireNonNull(credential, "credential");
    Objects.requireNonNull(randomScript, "randomScript");
    byte[] encoded = credential.encode();
    try {
      return new DfcVirtualPicc(DfcNative.piccCreate(encoded, randomScript));
    } finally {
      java.util.Arrays.fill(encoded, (byte) 0);
    }
  }
  /**
   * Starts a new RF activation and returns its public parameters.
   * @return activation values with defensive byte-array copies
   * @throws DfcException if native activation fails
   */
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
  /**
   * Appends bytes to this replay card's random queue without exposing future events early.
   * @param bytes random bytes to append; copied by the native core
   * @throws DfcException if the card is not replay-backed or append fails
   */
  public synchronized void appendReplayRandom(byte[] bytes) throws DfcException {
    DfcNative.piccAppendReplayRandom(state.require(), Objects.requireNonNull(bytes, "bytes"));
  }
  /**
   * Discards and wipes every unread byte in this replay card's random queue.
   * @throws DfcException if the card is not replay-backed or clearing fails
   */
  public synchronized void clearReplayRandom() throws DfcException {
    DfcNative.piccClearReplayRandom(state.require());
  }
  /**
   * Returns the available replay randomness.
   * @return unread byte count
   * @throws DfcException if the card is not replay-backed or inspection fails
   */
  public synchronized int replayRandomRemaining() throws DfcException {
    return DfcNative.piccReplayRandomRemaining(state.require());
  }
  /**
   * Exchanges one complete native or ISO command.
   * @param command command bytes in wire order
   * @return response bytes in wire order
   * @throws DfcException if protocol processing fails
   */
  public synchronized byte[] exchange(byte[] command) throws DfcException {
    return DfcNative.piccExchange(
        state.require(), Objects.requireNonNull(command, "command"), false);
  }
  /**
   * Exchanges one ISO-DEP block, including chaining and retransmission state.
   * @param frame complete ISO-DEP frame
   * @return response ISO-DEP frame
   * @throws DfcException if framing or protocol processing fails
   */
  public synchronized byte[] exchangeFrame(byte[] frame) throws DfcException {
    return DfcNative.piccExchange(state.require(), Objects.requireNonNull(frame, "frame"), true);
  }
  /**
   * Returns non-secret observable card state.
   * @return immutable snapshot with defensive byte-array copies
   * @throws DfcException if native state export fails
   */
  public synchronized DfcPiccSnapshot snapshot() throws DfcException {
    ByteBuffer data = ByteBuffer.wrap(DfcNative.piccSnapshot(state.require()));
    DfcPiccSnapshot.Selection selected = switch (data.get() & 0xff) {
      case 0 -> DfcPiccSnapshot.Selection.NONE;
      case 1 -> DfcPiccSnapshot.Selection.PICC;
      case 2 -> DfcPiccSnapshot.Selection.APPLICATION;
      default -> throw new AssertionError("native PICC returned an invalid selection state");
    };
    int applicationIndex = data.getInt();
    byte[] aid = new byte[3];
    data.get(aid);
    boolean dirty = data.get() != 0;
    int rawAuthenticationMode = data.get() & 0xff;
    DfcPiccSnapshot.AuthenticationMode authenticationMode = switch (rawAuthenticationMode) {
      case 0 -> null;
      case (int) DfcLayout.DFC_FFI_AUTH_LEGACY -> DfcPiccSnapshot.AuthenticationMode.LEGACY;
      case (int) DfcLayout.DFC_FFI_AUTH_ISO -> DfcPiccSnapshot.AuthenticationMode.ISO;
      case (int) DfcLayout.DFC_FFI_AUTH_AES -> DfcPiccSnapshot.AuthenticationMode.AES;
      default -> throw new AssertionError("native PICC returned an invalid authentication mode");
    };
    int authenticationKeyNumber = data.get() & 0xff;
    int ev2Counter = data.getInt();
    boolean ev2Active = data.get() != 0;
    boolean virtualCardSelected = data.get() != 0;
    boolean proximityVerified = data.get() != 0;
    boolean applicationSelected = selected == DfcPiccSnapshot.Selection.APPLICATION;
    return new DfcPiccSnapshot(selected, applicationSelected ? applicationIndex : null,
        applicationSelected ? aid : new byte[0], dirty, authenticationMode,
        authenticationMode == null ? null : authenticationKeyNumber, ev2Active ? ev2Counter : null,
        virtualCardSelected, proximityVerified);
  }
  /**
   * Copies secret session state for diagnostics. Close the result promptly.
   * @return owned secret snapshot that must be closed
   * @throws DfcException if native state export fails
   */
  public synchronized DfcDiagnosticSnapshot diagnosticSnapshot() throws DfcException {
    return new DfcDiagnosticSnapshot(DfcNative.piccDiagnosticSnapshot(state.require()));
  }
  @Override
  public byte[] transceive(byte[] frame) throws IOException {
    try {
      return exchange(frame);
    } catch (DfcException error) {
      throw new IOException(error);
    }
  }
  /**
   * Ends the current RF field and clears volatile protocol state.
   * @throws DfcException if native cleanup fails
   */
  public synchronized void fieldOff() throws DfcException {
    DfcNative.piccFieldOff(state.require());
  }
  /**
   * Resets protocol state without ending the RF field.
   * @throws DfcException if native reset fails
   */
  public synchronized void resetProtocol() throws DfcException {
    DfcNative.piccResetProtocol(state.require());
  }
  /**
   * Advances the card's monotonic virtual clock.
   * @param milliseconds unsigned 32-bit elapsed time
   * @throws DfcException if native time advancement fails
   * @throws IllegalArgumentException if {@code milliseconds} is outside the unsigned 32-bit range
   */
  public synchronized void advanceTime(long milliseconds) throws DfcException {
    if (milliseconds < 0 || milliseconds > 0xffff_ffffL)
      throw new IllegalArgumentException("milliseconds");
    DfcNative.piccAdvanceTime(state.require(), milliseconds);
  }
  /**
   * Exports current persistent card data.
   * @return owned credential that must be closed
   * @throws DfcException if encoding or allocation fails
   */
  public synchronized DfcCredential exportCredential() throws DfcException {
    return new DfcCredential(DfcNative.piccExport(state.require()));
  }
  /**
   * Marks current persistent card data as saved.
   * @throws DfcException if the native state cannot be updated
   */
  public synchronized void markPersisted() throws DfcException {
    DfcNative.piccMarkPersisted(state.require());
  }
  /** Releases native card state and wipes session secrets. */
  @Override
  public synchronized void close() {
    cleanable.clean();
  }
}
