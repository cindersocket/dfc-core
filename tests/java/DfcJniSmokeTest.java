import com.cindersocket.dfc.DfcCommand;
import com.cindersocket.dfc.DfcCredential;
import com.cindersocket.dfc.DfcCredentialCodec;
import com.cindersocket.dfc.DfcLibrary;
import com.cindersocket.dfc.DfcReader;
import com.cindersocket.dfc.DfcResponse;
import com.cindersocket.dfc.DfcVirtualPicc;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

public final class DfcJniSmokeTest {
    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    public static void main(String[] arguments) throws Exception {
        check(arguments.length == 2, "minimal and EV2 credential paths required");
        byte[] source = Files.readAllBytes(Path.of(arguments[0]));
        DfcCredential credential = DfcCredentialCodec.load(source);
        credential.validate();
        DfcCredential reparsed = DfcCredentialCodec.parse(credential.writeText());
        check(credential.equals(reparsed), "credential text round-trip");
        check(DfcLibrary.abiVersion() == 4, "ABI version");
        check(DfcLibrary.capabilities() != 0, "capabilities");
        check(Arrays.equals(DfcCommand.selectApplication(
            new byte[] {(byte) 0xd3, 0x49, 0x4f}).data(),
            new byte[] {0x4f, 0x49, (byte) 0xd3}),
            "SelectApplication converts model AID to wire order");

        try (DfcVirtualPicc picc = DfcVirtualPicc.createForReplay(credential, new byte[64]);
             DfcReader reader = new DfcReader(picc)) {
            check(picc.activate().uid().length > 0, "activation UID");
            check(picc.snapshot().selected() == 1, "activated PICC snapshot");
            DfcResponse version = reader.exchange(DfcCommand.getVersion(),
                DfcReader.Framing.ISO_7816, DfcReader.Communication.PLAIN);
            check(version.successful(), "GetVersion status");
            check(version.data().length == 28, "GetVersion response length");

            byte[] key = new byte[16];
            byte[] randomA = new byte[8];
            Arrays.fill(randomA, (byte) 0x5a);
            reader.authenticateForReplay(DfcReader.Cipher.ISO, 0, key,
                DfcReader.Framing.ISO_7816, randomA);
            check(reader.session().authenticationMode() == 0x1a, "ISO reader session");
            check(DfcReader.Communication.ENCIPHERED.ordinal() == 2,
                "test must distinguish native values from enum ordinals");
            for (DfcReader.Communication communication : DfcReader.Communication.values()) {
                check(reader.exchange(DfcCommand.getApplicationIds(), DfcReader.Framing.ISO_7816,
                    communication).successful(), communication + " authenticated exchange");
            }
        }

        DfcCredential ev2Credential = DfcCredentialCodec.load(Files.readAllBytes(Path.of(arguments[1])));
        byte[] ev2Key = new byte[16];
        for (int index = 0; index < ev2Key.length; index++) ev2Key[index] = (byte) index;
        try (DfcVirtualPicc picc = DfcVirtualPicc.createForReplay(ev2Credential, new byte[64]);
             DfcReader reader = new DfcReader(picc)) {
            picc.activate();
            reader.authenticateEv2ForReplay(true, 0, ev2Key, new byte[0],
                DfcReader.Framing.ISO_7816, new byte[16]);
            check(reader.session().authenticationMode() == 0x71, "EV2 reader session");
            check(picc.snapshot().ev2Active(), "EV2 PICC session");
        }
    }
}
