import com.cindersocket.dfc.DfcCredential;
import com.cindersocket.dfc.DfcCredentialCodec;
import com.cindersocket.dfc.DfcException;
import com.cindersocket.dfc.DfcPiccSnapshot;
import com.cindersocket.dfc.DfcVirtualPicc;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

public final class DfcJniReplayRandomTest {
    private static final byte[] ISO_AUTHENTICATE = {
        (byte) 0x90, 0x1a, 0x00, 0x00, 0x01, 0x00, 0x00
    };

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    private static void expectFailure(ThrowingAction action, String message) throws Exception {
        try {
            action.run();
            throw new AssertionError(message);
        } catch (DfcException expected) {
            check(expected.getMessage().contains("random script"), "specific replay failure");
        }
    }

    private static void checkSameState(DfcPiccSnapshot before, DfcPiccSnapshot after) {
        check(before.selected() == after.selected(), "selection must not change");
        check(Arrays.equals(before.selectedAid(), after.selectedAid()), "AID must not change");
        check(before.authenticationMode() == after.authenticationMode(),
            "authentication must not change");
        check(before.ev2Active() == after.ev2Active(), "EV2 state must not change");
        check(before.proximityVerified() == after.proximityVerified(),
            "proximity state must not change");
    }

    public static void main(String[] arguments) throws Exception {
        check(arguments.length == 1, "credential path required");
        DfcCredential credential =
            DfcCredentialCodec.load(Files.readAllBytes(Path.of(arguments[0])));

        expectFailure(() -> DfcVirtualPicc.createForReplay(credential, new byte[0]),
            "empty replay script must be rejected");

        try (DfcVirtualPicc picc = DfcVirtualPicc.createForReplay(credential, new byte[7])) {
            picc.activate();
            DfcPiccSnapshot before = picc.snapshot();
            expectFailure(() -> picc.exchange(ISO_AUTHENTICATE),
                "short replay script must fail instead of padding");
            checkSameState(before, picc.snapshot());
            expectFailure(() -> picc.exchange(new byte[] {(byte) 0x90, 0x60, 0, 0, 0}),
                "replay exhaustion must remain sticky");
            expectFailure(picc::resetProtocol, "protocol reset must not hide replay exhaustion");
        }

        byte[] exact = new byte[8];
        Arrays.fill(exact, (byte) 0xa5);
        try (DfcVirtualPicc picc = DfcVirtualPicc.createForReplay(credential, exact)) {
            picc.activate();
            check(picc.exchange(ISO_AUTHENTICATE).length > 2,
                "an exact replay script must satisfy one request");
            picc.resetProtocol();
            expectFailure(() -> picc.exchange(ISO_AUTHENTICATE),
                "the next random request must report exhaustion");
            expectFailure(() -> picc.exchange(ISO_AUTHENTICATE),
                "exhaustion must remain sticky after repeated calls");
        }

        byte[] twoRequests = new byte[16];
        Arrays.fill(twoRequests, (byte) 0x3c);
        try (DfcVirtualPicc picc = DfcVirtualPicc.createForReplay(credential, twoRequests)) {
            picc.activate();
            check(picc.exchange(ISO_AUTHENTICATE).length > 2, "first scripted request");
            picc.resetProtocol();
            check(picc.exchange(ISO_AUTHENTICATE).length > 2, "second scripted request");
        }
    }

    @FunctionalInterface
    private interface ThrowingAction {
        void run() throws Exception;
    }
}
