package com.cindersocket.dfc;

import java.util.Objects;

/** AN10922 key diversification backed by the native core. */
public final class DfcKeyDiversification {
  /** Supported output key families. */
  public enum Algorithm {
    /** AES-128 diversification with a 16-byte master key and output. */
    AES128(0),
    /** Two-key TDEA diversification with a 16-byte master key and output. */
    TDEA2(1),
    /** Three-key TDEA diversification with a 24-byte master key and output. */
    TDEA3(2);

    private final int nativeId;
    Algorithm(int nativeId) {
      this.nativeId = nativeId;
    }
  }

  private DfcKeyDiversification() {}

  /**
   * Derives one application key from a master key and diversification input.
   *
   * @param algorithm output key family
   * @param masterKey master key; its required length follows {@code algorithm}
   * @param input non-empty diversification input
   * @return newly allocated diversified key
   * @throws NullPointerException if any argument is {@code null}
   * @throws DfcException if a length is invalid or native derivation fails
   */
  public static byte[] diversify(Algorithm algorithm, byte[] masterKey, byte[] input)
      throws DfcException {
    Objects.requireNonNull(algorithm, "algorithm");
    Objects.requireNonNull(masterKey, "masterKey");
    Objects.requireNonNull(input, "input");
    return DfcNative.an10922Diversify(algorithm.nativeId, masterKey, input);
  }
}
