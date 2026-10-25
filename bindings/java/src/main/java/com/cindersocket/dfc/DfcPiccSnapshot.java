package com.cindersocket.dfc;

/**
 * Observable virtual-card state, excluding secret session keys.
 *
 * @param selected selection state: 0 for none, 1 for the PICC master application, or 2 for an
 *     application
 * @param selectedApplicationIndex zero-based credential-model application index; meaningful only
 *     when {@code selected == 2}, and zero otherwise
 * @param selectedAid selected application's three-byte identifier in credential-model order; valid
 *     only when {@code selected == 2}, and all zero otherwise
 * @param dirty whether persistent card data has unexported changes
 * @param authenticationMode active native authentication instruction: 0 for none, 0x0A for legacy,
 *     0x1A for ISO, or 0xAA for AES
 * @param authenticationKeyNumber active key number; meaningful only when {@code authenticationMode
 *     != 0}, and zero otherwise
 * @param ev2CommandCounter current EV2 command counter when {@code ev2Active}, and zero otherwise
 * @param ev2Active whether an EV2 session is active
 * @param virtualCardSelected whether virtual-card selection completed
 * @param proximityVerified whether proximity verification completed
 */
public record DfcPiccSnapshot(int selected, int selectedApplicationIndex, byte[] selectedAid,
    boolean dirty, int authenticationMode, int authenticationKeyNumber, int ev2CommandCounter,
    boolean ev2Active, boolean virtualCardSelected, boolean proximityVerified) {
  /**
   * Defensively copies the selected application identifier.
   * @param selected selection state: 0 for none, 1 for the PICC master application, or 2 for an
   *     application
   * @param selectedApplicationIndex zero-based credential-model application index; meaningful only
   *     when {@code selected == 2}, and zero otherwise
   * @param selectedAid selected application's three-byte identifier in credential-model order;
   *     valid only when {@code selected == 2}, and all zero otherwise
   * @param dirty whether persistent card data has unexported changes
   * @param authenticationMode active native authentication instruction: 0 for none, 0x0A for
   *     legacy, 0x1A for ISO, or 0xAA for AES
   * @param authenticationKeyNumber active key number; meaningful only when {@code
   *     authenticationMode
   *     != 0}, and zero otherwise
   * @param ev2CommandCounter current EV2 command counter when {@code ev2Active}, and zero otherwise
   * @param ev2Active whether an EV2 session is active
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
