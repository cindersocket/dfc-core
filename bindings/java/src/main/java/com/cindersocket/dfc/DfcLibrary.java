package com.cindersocket.dfc;

/** Build information exposed by the loaded native library. */
public final class DfcLibrary {
  private DfcLibrary() {}
  /**
   * Returns the loaded ABI.
   * @return version exported by the native library
   */
  public static int abiVersion() {
    return DfcNative.abiVersion();
  }

  /**
   * Returns the required ABI.
   * @return version compiled into this binding
   */
  public static int requiredAbiVersion() {
    return (int) DfcLayout.DFC_FFI_ABI_VERSION;
  }
  /**
   * Returns native capabilities.
   * @return feature bit mask
   */
  public static long capabilities() {
    return DfcNative.capabilities();
  }
}
