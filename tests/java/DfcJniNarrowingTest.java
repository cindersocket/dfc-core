package com.cindersocket.dfc;

import java.nio.file.Files;
import java.nio.file.Path;

/** Verifies that raw JNI integer arguments are rejected before byte narrowing. */
public final class DfcJniNarrowingTest {
    private static final int INVALID_ARGUMENT = -1;
    private static final int ISO = 0;

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    private static void refused(String label, ThrowingCall call) {
        try {
            call.run();
        } catch (DfcException expected) {
            check(expected.status() == INVALID_ARGUMENT, label + ": status " + expected.status());
            return;
        } catch (Throwable other) {
            throw new AssertionError(label + ": wrong exception " + other, other);
        }
        throw new AssertionError(label + ": accepted");
    }

    private interface ThrowingCall {
        void run() throws Exception;
    }

    public static void main(String[] arguments) throws Exception {
        check(arguments.length == 1, "credential path required");
        DfcCredential credential = DfcCredentialCodec.load(Files.readAllBytes(Path.of(arguments[0])));
        long picc = DfcNative.piccCreate(credential.encode(), new byte[64]);
        try {
            DfcNative.piccActivate(picc);
            for (long bad : new long[] {-1, 1L << 32, Long.MAX_VALUE}) {
                refused("milliseconds " + bad, () -> DfcNative.piccAdvanceTime(picc, bad));
            }
            DfcNative.piccAdvanceTime(picc, 0);
            check(DfcNative.piccSnapshot(picc) != null, "PICC usable after refusals");
        } finally {
            DfcNative.piccFree(picc);
        }

        long handle = DfcNative.readerCreate();
        try {
            byte[] none = new byte[0];
            for (int bad : new int[] {256, -1, 0x160}) {
                refused("instruction " + bad,
                    () -> DfcNative.readerBegin(handle, ISO, bad, none, 0, -1));
                refused("communication " + bad,
                    () -> DfcNative.readerBegin(handle, ISO, 0x60, none, bad, -1));
            }
            DfcNative.readerBegin(handle, ISO, 0x60, none, 0, -1);
            check(DfcNative.readerStep(handle, null) != null, "reader usable after refusals");

            byte[] key = new byte[16];
            byte[] random8 = new byte[8];
            byte[] random16 = new byte[16];
            for (int bad : new int[] {-1, 256, Integer.MAX_VALUE}) {
                refused("cipher " + bad,
                    () -> DfcNative.readerAuthenticate(handle, ISO, bad, 0, key, random8));
                refused("key number " + bad,
                    () -> DfcNative.readerAuthenticate(handle, ISO, 0x1A, bad, key, random8));
                refused("key reference " + bad, () -> DfcNative.readerAuthenticateIso7816(
                    handle, bad, 0x02, key, random8, random8));
                refused("algorithm " + bad, () -> DfcNative.readerAuthenticateIso7816(
                    handle, 0, bad, key, random8, random8));
                refused("EV2 key number " + bad, () -> DfcNative.readerAuthenticateEv2(
                    handle, ISO, true, bad, key, random16, none));
            }
            DfcNative.readerBegin(handle, ISO, 0x60, none, 0, -1);
            check(DfcNative.readerStep(handle, null) != null,
                "reader usable after authentication refusals");
        } finally {
            DfcNative.readerFree(handle);
        }
    }
}
