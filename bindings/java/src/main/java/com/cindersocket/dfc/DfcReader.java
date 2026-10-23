package com.cindersocket.dfc;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicLong;

/** Blocking reader-side secure messaging over a caller-provided transport. */
public final class DfcReader implements AutoCloseable {
  public enum Framing { ISO_7816, NATIVE }
  public enum Communication {
    PLAIN(0x00),
    MAC(0x01),
    ENCIPHERED(0x03);
    private final int nativeValue;

    Communication(int nativeValue) {
      this.nativeValue = nativeValue;
    }
  }
  public enum Cipher {
    LEGACY(0x0a),
    ISO(0x1a),
    AES(0xaa);
    final int nativeValue;
    Cipher(int nativeValue) {
      this.nativeValue = nativeValue;
    }
  }
  public enum Iso7816Algorithm {
    TDEA2(0x02, 8),
    TDEA3(0x04, 16),
    AES(0x09, 16);
    final int nativeValue;
    final int randomLength;
    Iso7816Algorithm(int nativeValue, int randomLength) {
      this.nativeValue = nativeValue;
      this.randomLength = randomLength;
    }
  }
  private static final SecureRandom RANDOM = new SecureRandom();
  private final DfcTransport transport;
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
        throw new IllegalStateException("reader is closed");
      return value;
    }
    boolean owns(long expected) {
      return handle.get() == expected;
    }
    void require(long expected) {
      if (!owns(expected))
        throw new IllegalStateException("reader is closed");
    }
    @Override
    public void run() {
      long value = handle.getAndSet(0);
      if (value != 0)
        DfcNative.readerFree(value);
    }
  }
  public DfcReader(DfcTransport transport) throws DfcException {
    this.transport = Objects.requireNonNull(transport, "transport");
    state = new State(DfcNative.readerCreate());
    cleanable = DfcCleaner.register(this, state);
  }
  public synchronized void clearSession() {
    DfcNative.readerClear(state.require());
  }
  public synchronized DfcReaderSession session() throws DfcException {
    java.nio.ByteBuffer data = java.nio.ByteBuffer.wrap(DfcNative.readerState(state.require()));
    int mode = data.get() & 0xff, keyNumber = data.get() & 0xff, counter = data.getInt();
    byte[] transactionIdentifier = new byte[4];
    data.get(transactionIdentifier);
    byte[] cardCapabilities = new byte[6];
    data.get(cardCapabilities);
    byte[] readerCapabilities = new byte[6];
    data.get(readerCapabilities);
    return new DfcReaderSession(
        mode, keyNumber, counter, transactionIdentifier, cardCapabilities, readerCapabilities);
  }
  public synchronized DfcResponse exchange(DfcCommand command, Framing framing,
      Communication communication) throws DfcException, IOException {
    return exchange(command, framing, communication, -1);
  }
  /**
   * Runs one command. {@code encryptedHeaderLength} is the clear-header length of an encrypted
   * file write, or -1 to derive it from the instruction. The native core owns the valid range;
   * this method passes the integer through unchanged. A refused value (below -1 or above the
   * native maximum) throws {@link DfcException} with status {@code DFC_FFI_INVALID_ARGUMENT}
   * (-1), before any session state changes, so the reader stays usable.
   */
  public synchronized DfcResponse exchange(DfcCommand command, Framing framing,
      Communication communication, int encryptedHeaderLength) throws DfcException, IOException {
    Objects.requireNonNull(command, "command");
    long handle = state.require();
    DfcNative.readerBegin(handle, framing.ordinal(), command.instruction(), command.data(),
        communication.nativeValue, encryptedHeaderLength);
    return complete(handle);
  }
  public synchronized void authenticate(Cipher cipher, int keyNumber, byte[] key, Framing framing)
      throws DfcException, IOException {
    Objects.requireNonNull(cipher, "cipher");
    Objects.requireNonNull(key, "key");
    byte[] randomA = new byte[challengeLength(cipher, key.length)];
    RANDOM.nextBytes(randomA);
    try {
      authenticateForReplay(cipher, keyNumber, key, framing, randomA);
    } finally {
      Arrays.fill(randomA, (byte) 0);
    }
  }
  public synchronized void authenticateForReplay(Cipher cipher, int keyNumber, byte[] key,
      Framing framing, byte[] randomA) throws DfcException, IOException {
    Objects.requireNonNull(cipher, "cipher");
    Objects.requireNonNull(key, "key");
    Objects.requireNonNull(randomA, "randomA");
    Objects.requireNonNull(framing, "framing");
    if ((keyNumber & ~0xff) != 0 || randomA.length != challengeLength(cipher, key.length))
      throw new IllegalArgumentException("authentication parameters");
    long handle = state.require();
    DfcNative.readerAuthenticate(
        handle, framing.ordinal(), cipher.nativeValue, keyNumber, key, randomA);
    complete(handle);
  }
  private static int challengeLength(Cipher cipher, int keyLength) {
    boolean valid = switch (cipher) {
      case LEGACY -> keyLength == 8 || keyLength == 16;
      case ISO -> keyLength == 8 || keyLength == 16 || keyLength == 24;
      case AES -> keyLength == 16;
    };
    if (!valid)
      throw new IllegalArgumentException("unsupported key length for " + cipher);
    return cipher == Cipher.AES || (cipher == Cipher.ISO && keyLength == 24) ? 16 : 8;
  }

  public synchronized void authenticateIso7816(
      int keyReference, Iso7816Algorithm algorithm, byte[] key) throws DfcException, IOException {
    Objects.requireNonNull(algorithm, "algorithm");
    byte[] first = new byte[algorithm.randomLength], second = new byte[algorithm.randomLength];
    RANDOM.nextBytes(first);
    RANDOM.nextBytes(second);
    try {
      authenticateIso7816ForReplay(keyReference, algorithm, key, first, second);
    } finally {
      Arrays.fill(first, (byte) 0);
      Arrays.fill(second, (byte) 0);
    }
  }
  public synchronized void authenticateIso7816ForReplay(int keyReference,
      Iso7816Algorithm algorithm, byte[] key, byte[] randomFirst, byte[] randomSecond)
      throws DfcException, IOException {
    Objects.requireNonNull(algorithm, "algorithm");
    Objects.requireNonNull(key, "key");
    if ((keyReference & ~0xff) != 0 || randomFirst.length != algorithm.randomLength
        || randomSecond.length != algorithm.randomLength)
      throw new IllegalArgumentException("authentication parameters");
    long handle = state.require();
    DfcNative.readerAuthenticateIso7816(
        handle, keyReference, algorithm.nativeValue, key, randomFirst, randomSecond);
    complete(handle);
  }
  public synchronized void authenticateEv2First(int keyNumber, byte[] key, byte[] capabilities,
      Framing framing) throws DfcException, IOException {
    authenticateEv2(false, true, keyNumber, key, capabilities, framing, null);
  }
  public synchronized void authenticateEv2NonFirst(int keyNumber, byte[] key, Framing framing)
      throws DfcException, IOException {
    authenticateEv2(false, false, keyNumber, key, new byte[0], framing, null);
  }
  public synchronized void authenticateEv2ForReplay(boolean first, int keyNumber, byte[] key,
      byte[] capabilities, Framing framing, byte[] randomA) throws DfcException, IOException {
    authenticateEv2(true, first, keyNumber, key, capabilities, framing, randomA);
  }
  private void authenticateEv2(boolean replay, boolean first, int keyNumber, byte[] key,
      byte[] capabilities, Framing framing, byte[] suppliedRandom)
      throws DfcException, IOException {
    Objects.requireNonNull(key, "key");
    Objects.requireNonNull(capabilities, "capabilities");
    Objects.requireNonNull(framing, "framing");
    if (key.length != 16 || capabilities.length > 6 || (keyNumber & ~0xff) != 0)
      throw new IllegalArgumentException("EV2 authentication parameters");
    byte[] randomA = replay ? Objects.requireNonNull(suppliedRandom, "randomA") : new byte[16];
    if (randomA.length != 16)
      throw new IllegalArgumentException("randomA");
    if (!replay)
      RANDOM.nextBytes(randomA);
    long handle = state.require();
    try {
      DfcNative.readerAuthenticateEv2(
          handle, framing.ordinal(), first, keyNumber, key, randomA, capabilities);
      complete(handle);
    } finally {
      if (!replay)
        Arrays.fill(randomA, (byte) 0);
    }
  }
  private DfcResponse complete(long handle) throws DfcException, IOException {
    byte[] answer = null;
    for (;;) {
      byte[] command = DfcNative.readerStep(handle, answer);
      if (command == null)
        return new DfcResponse(DfcNative.readerResult(handle), DfcNative.readerStatus(handle));
      try {
        answer = Objects.requireNonNull(transport.transceive(command), "transport returned null");
        state.require(handle);
      } catch (IOException | RuntimeException error) {
        if (state.owns(handle))
          DfcNative.readerClear(handle);
        throw error;
      }
    }
  }
  @Override
  public synchronized void close() {
    cleanable.clean();
  }
}
