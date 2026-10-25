package com.cindersocket.dfc;

import java.util.Arrays;

/** A validated DFC credential in canonical binary form. Close it to clear its key-bearing bytes. */
public final class DfcCredential implements AutoCloseable {
  private static final class State implements Runnable {
    private final byte[] binary;
    private boolean closed;
    State(byte[] binary) {
      this.binary = binary;
    }
    @Override
    public synchronized void run() {
      Arrays.fill(binary, (byte) 0);
      closed = true;
    }
    synchronized byte[] requireOpen() {
      if (closed)
        throw new IllegalStateException("credential is closed");
      return binary;
    }
    synchronized boolean isClosed() {
      return closed;
    }
  }
  private final State state;
  private final DfcCleaner.Cleanable cleanable;
  private final int stableHashCode;
  DfcCredential(byte[] binary) {
    state = new State(binary);
    stableHashCode = Arrays.hashCode(binary);
    cleanable = DfcCleaner.register(this, state);
  }
  /**
   * Returns canonical binary form.
   * @return a new copy of the key-bearing bytes
   */
  public byte[] encode() {
    return state.requireOpen().clone();
  }
  /**
   * Renders canonical text form.
   * @return text representation
   * @throws DfcException if native encoding fails
   */
  public String writeText() throws DfcException {
    return DfcNative.credentialText(state.requireOpen());
  }
  /**
   * Validates the decoded model.
   * @throws DfcException if this credential violates a model invariant
   */
  public void validate() throws DfcException {
    DfcNative.credentialValidate(state.requireOpen());
  }
  /** Clears the canonical key-bearing bytes owned by this object. */
  @Override
  public void close() {
    cleanable.clean();
  }
  @Override
  public boolean equals(Object other) {
    if (other == this)
      return true;
    return other instanceof DfcCredential credential && !state.isClosed()
        && !credential.state.isClosed()
        && Arrays.equals(state.requireOpen(), credential.state.requireOpen());
  }
  @Override
  public int hashCode() {
    return stableHashCode;
  }
}
