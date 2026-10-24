package com.cindersocket.dfc;

public final class DfcLayoutCompatibilityTest {
  private DfcLayoutCompatibilityTest() {}

  public static void main(String[] arguments) throws Exception {
    if (arguments.length == 1 && arguments[0].equals("native")) {
      try {
        DfcCredentialCodec.load(new byte[0]);
      } catch (UnsatisfiedLinkError expected) {
        requireLayoutMismatch(expected);
        return;
      } catch (ExceptionInInitializerError expected) {
        if (!(expected.getCause() instanceof UnsatisfiedLinkError cause))
          throw new AssertionError("unclear native layout mismatch", expected);
        requireLayoutMismatch(cause);
        return;
      }
      throw new AssertionError("mismatched native library initialized");
    }
    try {
      DfcCompatibility.requireCompatible((int) DfcLayout.DFC_FFI_ABI_VERSION, 1, 2);
      throw new AssertionError("mismatched native layout accepted");
    } catch (UnsatisfiedLinkError expected) {
      if (!expected.getMessage().contains("layout fingerprint mismatch"))
        throw new AssertionError("unclear layout mismatch error", expected);
    }
  }

  private static void requireLayoutMismatch(UnsatisfiedLinkError error) {
    if (!error.getMessage().contains("layout fingerprint mismatch"))
      throw new AssertionError("unclear native layout mismatch", error);
  }
}
