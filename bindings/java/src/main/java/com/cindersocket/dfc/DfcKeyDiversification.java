package com.cindersocket.dfc;

import java.util.Objects;

/** AN10922 key diversification backed by the native core. */
public final class DfcKeyDiversification {
  /** Supported output key families. */
  public enum Algorithm {
    AES128(0),
    TDEA2(1),
    TDEA3(2);

    private final int nativeId;
    Algorithm(int nativeId) {
      this.nativeId = nativeId;
    }
  }

  private DfcKeyDiversification() {}

  public static byte[] diversify(Algorithm algorithm, byte[] masterKey, byte[] input)
      throws DfcException {
    Objects.requireNonNull(algorithm, "algorithm");
    Objects.requireNonNull(masterKey, "masterKey");
    Objects.requireNonNull(input, "input");
    return DfcNative.an10922Diversify(algorithm.nativeId, masterKey, input);
  }
}
