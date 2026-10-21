package com.cindersocket.dfc;

/** Observable virtual-card state, excluding secret session keys. */
public record DfcPiccSnapshot(int selected, int selectedApplicationIndex, byte[] selectedAid,
    boolean dirty, int authenticationMode, int authenticationKeyNumber, int ev2CommandCounter,
    boolean ev2Active, boolean virtualCardSelected, boolean proximityVerified) {
  public DfcPiccSnapshot {
    selectedAid = selectedAid.clone();
  }
  @Override
  public byte[] selectedAid() {
    return selectedAid.clone();
  }
}
