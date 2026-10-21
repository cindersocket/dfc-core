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
  public byte[] uid() {
    return uid.clone();
  }
  public byte[] atqa() {
    return atqa.clone();
  }
  public int sak() {
    return sak;
  }
  public byte[] ats() {
    return ats.clone();
  }
}
