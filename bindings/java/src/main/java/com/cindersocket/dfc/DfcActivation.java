package com.cindersocket.dfc;

/** ISO 14443-A activation values presented by a virtual card. */
public final class DfcActivation {
  private final byte[] uid;
  private final byte[] atqa;
  private final int sak;
  private final byte[] ats;
  DfcActivation(byte[] uid, byte[] atqa, int sak, byte[] ats) {
    this.uid = uid.clone();
    this.atqa = atqa.clone();
    this.sak = sak;
    this.ats = ats.clone();
  }
  /**
   * Returns the card identifier.
   * @return a defensive copy of the 4-, 7-, or 10-byte UID
   */
  public byte[] uid() {
    return uid.clone();
  }
  /**
   * Returns the ATQA.
   * @return a defensive copy of the two bytes in wire order
   */
  public byte[] atqa() {
    return atqa.clone();
  }
  /**
   * Returns the SAK.
   * @return the unsigned one-byte value
   */
  public int sak() {
    return sak;
  }
  /**
   * Returns the ATS.
   * @return a defensive copy excluding its length byte
   */
  public byte[] ats() {
    return ats.clone();
  }
}
