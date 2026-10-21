import com.cindersocket.dfc.DfcActivation;
import com.cindersocket.dfc.DfcCommand;
import com.cindersocket.dfc.DfcCredential;
import com.cindersocket.dfc.DfcCredentialCodec;
import com.cindersocket.dfc.DfcReader;
import com.cindersocket.dfc.DfcResponse;
import com.cindersocket.dfc.DfcVirtualPicc;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;

/** Loads a credential, activates its virtual card, and drives it through the reader API. */
public final class DfcTransceiveExample {
  private DfcTransceiveExample() {}

  public static void main(String[] arguments) throws Exception {
    if (arguments.length != 1) {
      throw new IllegalArgumentException("usage: DfcTransceiveExample <credential.dfc|dfcb>");
    }

    // load() accepts either encoding, so callers do not need a file-extension heuristic.
    DfcCredential credential = DfcCredentialCodec.load(Files.readAllBytes(Path.of(arguments[0])));
    credential.validate();

    // The virtual PICC owns an independent copy. Closing both native-backed objects is required.
    try (DfcVirtualPicc picc = DfcVirtualPicc.create(credential);
         DfcReader reader = new DfcReader(picc)) {
      DfcActivation activation = picc.activate();

      // The reader follows GetVersion's additional frames and returns one assembled payload.
      DfcResponse version = reader.exchange(
          DfcCommand.getVersion(), DfcReader.Framing.ISO_7816, DfcReader.Communication.PLAIN);
      if (!version.successful() || version.data().length != 28) {
        throw new IllegalStateException(
            "GetVersion failed: status=" + String.format("%02X", version.status()));
      }

      System.out.println("UID: " + HexFormat.ofDelimiter(":").formatHex(activation.uid()));
      System.out.println("GetVersion: " + HexFormat.of().formatHex(version.data()));
    }
  }
}
