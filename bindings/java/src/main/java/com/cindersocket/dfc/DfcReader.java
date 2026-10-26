package com.cindersocket.dfc;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicLong;

/** Blocking reader-side secure messaging over a caller-provided transport. */
public final class DfcReader implements AutoCloseable {
  private static final int EV2_TRANSACTION_IDENTIFIER_LENGTH = 4;
  private static final int EV2_CAPABILITIES_LENGTH = 6;
  private static final int ISO_APPLICATION_KEY_REFERENCE = 0x80;
  private static final int ISO_KEY_NUMBER_MASK = 0x1f;
  private static final int ISO_KEY_NUMBER_MAX = 0x0d;

  /** Transport framing applied to native commands. */
  public enum Framing {
    /** ISO 7816 command APDU framing. */
    ISO_7816((int) DfcLayout.DFC_FFI_READER_FRAMING_ISO7816),
    /** Native command framing. */
    NATIVE((int) DfcLayout.DFC_FFI_READER_FRAMING_NATIVE);
    private final int nativeValue;
    Framing(int nativeValue) {
      this.nativeValue = nativeValue;
    }
  }
  /** Secure-messaging mode for a command. */
  public enum Communication {
    /** Plain command and response. */
    PLAIN((int) DfcLayout.DFC_FFI_COMM_PLAIN),
    /** Authenticated command and response. */
    MAC((int) DfcLayout.DFC_FFI_COMM_MAC),
    /** Authenticated and encrypted command and response. */
    ENCIPHERED((int) DfcLayout.DFC_FFI_COMM_ENCIPHERED);
    private final int nativeValue;

    Communication(int nativeValue) {
      this.nativeValue = nativeValue;
    }
  }
  /** Native authentication cipher family. */
  public enum Cipher {
    /** Legacy D40 authentication. */
    LEGACY((int) DfcLayout.DFC_FFI_AUTH_LEGACY),
    /** ISO authentication with DES or TDEA keys. */
    ISO((int) DfcLayout.DFC_FFI_AUTH_ISO),
    /** AES-128 authentication. */
    AES((int) DfcLayout.DFC_FFI_AUTH_AES);
    final int nativeValue;
    Cipher(int nativeValue) {
      this.nativeValue = nativeValue;
    }
  }
  /** Algorithm used by ISO 7816 INTERNAL/EXTERNAL AUTHENTICATE. */
  public enum Iso7816Algorithm {
    /** Two-key TDEA with an eight-byte challenge. */
    TDEA2((int) DfcLayout.DFC_FFI_ISO_AUTH_TDEA2, 8),
    /** Three-key TDEA with a 16-byte challenge. */
    TDEA3((int) DfcLayout.DFC_FFI_ISO_AUTH_TDEA3, 16),
    /** AES-128 with a 16-byte challenge. */
    AES((int) DfcLayout.DFC_FFI_ISO_AUTH_AES, 16);
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
  /**
   * Creates a reader over a caller-owned transport.
   * @param transport blocking frame transport; not closed by this reader
   * @throws DfcException if native reader allocation fails
   */
  public DfcReader(DfcTransport transport) throws DfcException {
    this.transport = Objects.requireNonNull(transport, "transport");
    state = new State(DfcNative.readerCreate());
    cleanable = DfcCleaner.register(this, state);
  }
  /** Clears authentication and secure-messaging state while leaving the reader open. */
  public synchronized void clearSession() {
    DfcNative.readerClear(state.require());
  }
  /**
   * Returns observable session state without exposing session keys.
   * @return immutable session snapshot
   * @throws DfcException if native state export fails
   */
  public synchronized DfcReaderSession session() throws DfcException {
    byte[] packed = DfcNative.readerState(state.require());
    if (packed.length != DfcJniLayout.DFC_JNI_READER_STATE_SIZE)
      throw new AssertionError("native reader returned an invalid state length");
    java.nio.ByteBuffer data = java.nio.ByteBuffer.wrap(packed);
    int rawMode = data.get(DfcJniLayout.DFC_JNI_READER_STATE_AUTH_MODE_OFFSET) & 0xff;
    DfcReaderSession.AuthenticationMode mode = switch (rawMode) {
      case 0 -> DfcReaderSession.AuthenticationMode.NONE;
      case (int) DfcLayout.DFC_FFI_AUTH_LEGACY -> DfcReaderSession.AuthenticationMode.LEGACY;
      case (int) DfcLayout.DFC_FFI_AUTH_ISO -> DfcReaderSession.AuthenticationMode.ISO;
      case (int) DfcLayout.DFC_FFI_AUTH_AES -> DfcReaderSession.AuthenticationMode.AES;
      case (int) DfcLayout.DFC_FFI_AUTH_EV2 -> DfcReaderSession.AuthenticationMode.EV2;
      default -> throw new AssertionError("native reader returned an invalid authentication mode");
    };
    int keyNumber = data.get(DfcJniLayout.DFC_JNI_READER_STATE_KEY_OFFSET) & 0xff;
    int counter = data.getInt(DfcJniLayout.DFC_JNI_READER_STATE_COMMAND_COUNTER_OFFSET);
    byte[] transactionIdentifier = new byte[EV2_TRANSACTION_IDENTIFIER_LENGTH];
    data.position(DfcJniLayout.DFC_JNI_READER_STATE_TRANSACTION_ID_OFFSET);
    data.get(transactionIdentifier);
    byte[] cardCapabilities = new byte[EV2_CAPABILITIES_LENGTH];
    data.position(DfcJniLayout.DFC_JNI_READER_STATE_CARD_CAPABILITIES_OFFSET);
    data.get(cardCapabilities);
    byte[] readerCapabilities = new byte[EV2_CAPABILITIES_LENGTH];
    data.position(DfcJniLayout.DFC_JNI_READER_STATE_READER_CAPABILITIES_OFFSET);
    data.get(readerCapabilities);
    boolean authenticated = mode != DfcReaderSession.AuthenticationMode.NONE;
    boolean ev2 = mode == DfcReaderSession.AuthenticationMode.EV2;
    return new DfcReaderSession(mode, authenticated ? keyNumber : null, ev2 ? counter : null,
        ev2 ? transactionIdentifier : new byte[0], ev2 ? cardCapabilities : new byte[0],
        ev2 ? readerCapabilities : new byte[0]);
  }
  /**
   * Runs one command with its instruction-specific encrypted clear-header length.
   * @param command native command and payload
   * @param framing transport framing
   * @param communication secure-messaging mode
   * @return unwrapped response data and card status
   * @throws DfcException if command processing or response verification fails
   * @throws IOException if the transport exchange fails
   */
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
   *
   * @param command native command and payload
   * @param framing transport framing
   * @param communication secure-messaging mode
   * @param encryptedHeaderLength clear prefix length, or -1 for instruction-specific behavior
   * @return unwrapped response data and card status
   * @throws DfcException if command processing or response verification fails
   * @throws IOException if the transport exchange fails
   */
  public synchronized DfcResponse exchange(DfcCommand command, Framing framing,
      Communication communication, int encryptedHeaderLength) throws DfcException, IOException {
    Objects.requireNonNull(command, "command");
    long handle = state.require();
    DfcNative.readerBegin(handle, framing.nativeValue, command.instruction(), command.data(),
        communication.nativeValue, encryptedHeaderLength);
    return complete(handle);
  }
  /**
   * Authenticates with fresh reader randomness.
   * @param cipher authentication cipher family
   * @param keyNumber unsigned one-byte key number
   * @param key authentication key; the caller retains ownership
   * @param framing transport framing
   * @throws DfcException if authentication fails
   * @throws IllegalArgumentException if the key number or cipher-specific key length is invalid
   * @throws IOException if the transport exchange fails
   */
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
  /**
   * Authenticates with caller-supplied randomness for deterministic replay.
   * @param cipher authentication cipher family
   * @param keyNumber unsigned one-byte key number
   * @param key authentication key; the caller retains ownership
   * @param framing transport framing
   * @param randomA reader challenge of the algorithm-specific length
   * @throws DfcException if authentication fails
   * @throws IllegalArgumentException if the key number, key length, or challenge length is invalid
   * @throws IOException if the transport exchange fails
   */
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
        handle, framing.nativeValue, cipher.nativeValue, keyNumber, key, randomA);
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

  /**
   * Performs ISO 7816 authentication with fresh challenges.
   * @param keyReference key number 0 through 13, optionally ORed with 0x80 to select application
   *     key scope
   * @param algorithm authentication algorithm
   * @param key authentication key; the caller retains ownership
   * @throws DfcException if authentication fails
   * @throws IllegalArgumentException if the key reference or algorithm-specific key length is
   *     invalid
   * @throws IOException if the transport exchange fails
   */
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
  /**
   * Performs ISO 7816 authentication with caller-supplied challenges.
   * @param keyReference key number 0 through 13, optionally ORed with 0x80 to select application
   *     key scope
   * @param algorithm authentication algorithm
   * @param key authentication key; the caller retains ownership
   * @param randomFirst first algorithm-sized challenge
   * @param randomSecond second algorithm-sized challenge
   * @throws DfcException if authentication fails
   * @throws IllegalArgumentException if the key reference, key length, or challenge length is
   *     invalid
   * @throws IOException if the transport exchange fails
   */
  public synchronized void authenticateIso7816ForReplay(int keyReference,
      Iso7816Algorithm algorithm, byte[] key, byte[] randomFirst, byte[] randomSecond)
      throws DfcException, IOException {
    Objects.requireNonNull(algorithm, "algorithm");
    Objects.requireNonNull(key, "key");
    Objects.requireNonNull(randomFirst, "randomFirst");
    Objects.requireNonNull(randomSecond, "randomSecond");
    if (!validIsoKeyReference(keyReference) || key.length != isoKeyLength(algorithm)
        || randomFirst.length != algorithm.randomLength
        || randomSecond.length != algorithm.randomLength)
      throw new IllegalArgumentException("authentication parameters");
    long handle = state.require();
    DfcNative.readerAuthenticateIso7816(
        handle, keyReference, algorithm.nativeValue, key, randomFirst, randomSecond);
    complete(handle);
  }
  private static boolean validIsoKeyReference(int keyReference) {
    return (keyReference & ~(ISO_APPLICATION_KEY_REFERENCE | ISO_KEY_NUMBER_MASK)) == 0
        && (keyReference & ISO_KEY_NUMBER_MASK) <= ISO_KEY_NUMBER_MAX;
  }
  private static int isoKeyLength(Iso7816Algorithm algorithm) {
    return algorithm == Iso7816Algorithm.TDEA3 ? 24 : 16;
  }
  /**
   * Starts an EV2 first authentication with fresh reader randomness.
   * @param keyNumber unsigned one-byte key number
   * @param key 16-byte AES key; the caller retains ownership
   * @param capabilities either empty or six reader-capability bytes
   * @param framing transport framing
   * @throws DfcException if authentication fails
   * @throws IllegalArgumentException if the key number, key length, or capability length is invalid
   * @throws IOException if the transport exchange fails
   */
  public synchronized void authenticateEv2First(int keyNumber, byte[] key, byte[] capabilities,
      Framing framing) throws DfcException, IOException {
    authenticateEv2(false, true, keyNumber, key, capabilities, framing, null);
  }
  /**
   * Starts an EV2 non-first authentication with fresh reader randomness.
   * @param keyNumber unsigned one-byte key number
   * @param key 16-byte AES key; the caller retains ownership
   * @param framing transport framing
   * @throws DfcException if authentication fails
   * @throws IllegalArgumentException if the key number or key length is invalid
   * @throws IOException if the transport exchange fails
   */
  public synchronized void authenticateEv2NonFirst(int keyNumber, byte[] key, Framing framing)
      throws DfcException, IOException {
    authenticateEv2(false, false, keyNumber, key, new byte[0], framing, null);
  }
  /**
   * Performs deterministic EV2 authentication for replay and conformance tools.
   * @param first whether to start a first authentication
   * @param keyNumber unsigned one-byte key number
   * @param key 16-byte AES key; the caller retains ownership
   * @param capabilities either empty or six reader-capability bytes for a first authentication;
   *     must be empty for a non-first authentication
   * @param framing transport framing
   * @param randomA 16-byte reader challenge
   * @throws DfcException if authentication fails
   * @throws IllegalArgumentException if the key number, key length, capability length, or challenge
   *     length is invalid
   * @throws IOException if the transport exchange fails
   */
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
    boolean invalidCapabilities =
        capabilities.length != 0 && (capabilities.length != EV2_CAPABILITIES_LENGTH || !first);
    if (key.length != 16 || invalidCapabilities || (keyNumber & ~0xff) != 0)
      throw new IllegalArgumentException("EV2 authentication parameters");
    byte[] randomA = replay ? Objects.requireNonNull(suppliedRandom, "randomA") : new byte[16];
    if (randomA.length != 16)
      throw new IllegalArgumentException("randomA");
    if (!replay)
      RANDOM.nextBytes(randomA);
    long handle = state.require();
    try {
      DfcNative.readerAuthenticateEv2(
          handle, framing.nativeValue, first, keyNumber, key, randomA, capabilities);
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
  /** Releases native reader state and clears its session secrets. */
  @Override
  public synchronized void close() {
    cleanable.clean();
  }
}
