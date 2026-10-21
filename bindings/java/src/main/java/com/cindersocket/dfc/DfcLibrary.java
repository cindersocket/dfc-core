package com.cindersocket.dfc;

/** Build information exposed by the loaded native library. */
public final class DfcLibrary {
    private DfcLibrary() {}
    public static int abiVersion() { return DfcNative.abiVersion(); }
    public static long capabilities() { return DfcNative.capabilities(); }
}
