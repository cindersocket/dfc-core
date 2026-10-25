package com.cindersocket.dfc;

/**
 * Observable virtual-card state, excluding secret session keys.
 *
 * @param selection selected card level
 * @param selectedApplicationIndex zero-based credential-model application index, or null outside
 *     application selection
 * @param selectedAid selected application's three-byte identifier in credential-model order, or
 *     an empty array outside application selection
 * @param dirty whether persistent card data has unexported changes
 * @param authenticationMode active authentication family, or null while unauthenticated
 * @param authenticationKeyNumber active key number, or null while unauthenticated
 * @param ev2CommandCounter current EV2 command counter, or null outside EV2
 * @param virtualCardSelected whether virtual-card selection completed
 * @param proximityVerified whether proximity verification completed
 */
public record
    DfcPiccSnapshot(Selection selection, Integer selectedApplicationIndex, byte[] selectedAid,
        boolean dirty, AuthenticationMode authenticationMode, Integer authenticationKeyNumber,
        Integer ev2CommandCounter, boolean virtualCardSelected, boolean proximityVerified) {
  /** Selected card level. */
  public enum Selection {
    /** Nothing is selected. */ NONE,
    /** The PICC master application is selected. */ PICC,
    /** A credential-model application is selected. */ APPLICATION
  }
  /** Native authentication cipher family. */
  public enum AuthenticationMode {
    /** Legacy D40 authentication. */ LEGACY,
    /** ISO authentication. */ ISO,
    /** AES authentication; a non-null EV2 command counter identifies an EV2 session. */ AES
  }
  /**
   * Defensively copies the selected application identifier.
   * @param selection selected card level
   * @param selectedApplicationIndex zero-based credential-model application index, or null outside
   *     application selection
   * @param selectedAid selected application's three-byte identifier in credential-model order, or
   *     an empty array outside application selection
   * @param dirty whether persistent card data has unexported changes
   * @param authenticationMode active authentication family, or null while unauthenticated
   * @param authenticationKeyNumber active key number, or null while unauthenticated
   * @param ev2CommandCounter current EV2 command counter, or null outside EV2
   * @param virtualCardSelected whether virtual-card selection completed
   * @param proximityVerified whether proximity verification completed
   */
  public DfcPiccSnapshot {
    selectedAid = selectedAid.clone();
  }
  /**
   * Returns the selected identifier.
   * @return a defensive copy in credential-model order
   */
  @Override
  public byte[] selectedAid() {
    return selectedAid.clone();
  }
}
