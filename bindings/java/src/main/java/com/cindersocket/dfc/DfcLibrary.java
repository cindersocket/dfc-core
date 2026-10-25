package com.cindersocket.dfc;

/** Build information exposed by the loaded native library. */
public final class DfcLibrary {
  private DfcLibrary() {}
  public static int abiVersion() {
    return DfcNative.abiVersion();
  }

  /** Returns the generated native ABI version required by this binding. */
  public static int requiredAbiVersion() {
    return (int) DfcLayout.DFC_FFI_ABI_VERSION;
  }
  public static long capabilities() {
    return DfcNative.capabilities();
  }
}
