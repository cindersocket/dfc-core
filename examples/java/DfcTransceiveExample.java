import com.cindersocket.dfc.DfcActivation;
import com.cindersocket.dfc.DfcCommand;
import com.cindersocket.dfc.DfcCredential;
import com.cindersocket.dfc.DfcCredentialCodec;
import com.cindersocket.dfc.DfcReader;
import com.cindersocket.dfc.DfcResponse;
import com.cindersocket.dfc.DfcResponses;
import com.cindersocket.dfc.DfcSdm;
import com.cindersocket.dfc.DfcTransactionMacVerifier;
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
      DfcResponses.Version decodedVersion = DfcResponses.decodeVersion(version.data());
      System.out.println("GetVersion UID: " + HexFormat.of().formatHex(decodedVersion.uid()));

      DfcResponse applications = reader.exchange(DfcCommand.getApplicationIds(),
          DfcReader.Framing.ISO_7816, DfcReader.Communication.PLAIN);
      var aids = DfcResponses.decodeApplicationIds(applications.data());
      if (!aids.isEmpty()) {
        reader.exchange(DfcCommand.selectApplication(aids.get(0)), DfcReader.Framing.ISO_7816,
            DfcReader.Communication.PLAIN);
        var files = DfcResponses.decodeFileIds(reader
                .exchange(DfcCommand.getFileIds(), DfcReader.Framing.ISO_7816,
                    DfcReader.Communication.PLAIN)
                .data());
        if (!files.isEmpty()) {
          var settings = DfcResponses.decodeFileSettings(reader
                  .exchange(DfcCommand.getFileSettings(files.get(0)), DfcReader.Framing.ISO_7816,
                      DfcReader.Communication.PLAIN)
                  .data());
          System.out.printf("File %d: type=%d communication=%d%n", files.get(0), settings.type(),
              settings.communicationMode());
        }
      }
    }

    verifyCapturedBackendData();
  }

  private static void verifyCapturedBackendData() throws Exception {
    byte[] message =
        "0483B4F2CF1890000001163F0AC4319102F37F4B61FE6BFDE1469CF53E287D682A2E".getBytes(
            java.nio.charset.StandardCharsets.US_ASCII);
    var config =
        new DfcSdm.Config(20, 52, new DfcSdm.Field(0, 7), 14, null, new DfcSdm.Field(20, 32));
    var verified = DfcSdm.verify(message, config, new byte[16], null);
    System.out.printf("Verified SDM UID: %s, counter=%d%n",
        HexFormat.of().formatHex(verified.uid()), verified.readCounter());

    // Mirror the plain Credit operation, then authenticate the CommitTransaction receipt.
    try (var receipt = new DfcTransactionMacVerifier(
             new byte[16], HexFormat.of().parseHex("0483B4F2CF1890"), 1, 128)) {
      receipt.addValue(0x0C, 5, 1);
      if (!receipt.verify(HexFormat.of().parseHex("352E57ADDA911EDC"))) {
        throw new IllegalStateException("transaction receipt did not match");
      }
    }
    System.out.println("Transaction receipt verified");
  }
}
