package com.cindersocket.dfc;

/** Checks the platform names used by published JNI classifier jars. */
public final class DfcNativeLoaderTest {
  private DfcNativeLoaderTest() {}

  public static void main(String[] args) {
    String originalOs = System.getProperty("os.name");
    String originalArch = System.getProperty("os.arch");
    try {
      check("Linux", "amd64", "linux-x86_64");
      check("Linux", "aarch64", "linux-aarch64");
      check("Mac OS X", "x86_64", "osx-x86_64");
      check("Mac OS X", "arm64", "osx-aarch64");
      check("Windows 11", "amd64", "windows-x86_64");
      check("Windows 11", "aarch64", "windows-aarch64");
    } finally {
      restore("os.name", originalOs);
      restore("os.arch", originalArch);
    }
  }

  private static void check(String os, String arch, String expected) {
    System.setProperty("os.name", os);
    System.setProperty("os.arch", arch);
    String actual = DfcNativeLoader.classifier();
    if (!expected.equals(actual)) {
      throw new AssertionError(expected + " != " + actual);
    }
  }

  private static void restore(String name, String value) {
    if (value == null) {
      System.clearProperty(name);
    } else {
      System.setProperty(name, value);
    }
  }
}
