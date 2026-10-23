package com.cindersocket.dfc;

import java.nio.file.Files;
import java.nio.file.Path;

/** Verifies that Java passes clear-header lengths to the native bound without narrowing. */
public final class DfcReaderHeaderBoundsTest {
    private static final int NATIVE_MAX_CLEAR_HEADER = 10;
    private static final int INVALID_ARGUMENT = -1;

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
        try (DfcVirtualPicc picc = DfcVirtualPicc.createForReplay(credential, new byte[64]);
             DfcReader reader = new DfcReader(picc)) {
            picc.activate();
            DfcCommand command = DfcCommand.getVersion();
            DfcReader.Communication plain = DfcReader.Communication.PLAIN;
            for (int accepted : new int[] {-1, 0, NATIVE_MAX_CLEAR_HEADER}) {
                check(reader.exchange(command, DfcReader.Framing.ISO_7816, plain, accepted)
                          .successful(), "header " + accepted + " accepted");
            }
            for (int bad : new int[] {NATIVE_MAX_CLEAR_HEADER + 1, 255, 256, -2,
                     Integer.MAX_VALUE, Integer.MIN_VALUE}) {
                refused("header " + bad, () -> reader.exchange(
                    command, DfcReader.Framing.ISO_7816, plain, bad));
            }
            check(reader.exchange(command, DfcReader.Framing.ISO_7816, plain).successful(),
                "reader usable after refusals");
        }
    }
}
