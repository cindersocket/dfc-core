import com.cindersocket.dfc.DfcKeyDiversification;
import com.cindersocket.dfc.DfcCommand;
import com.cindersocket.dfc.DfcException;
import com.cindersocket.dfc.DfcIso7816;
import com.cindersocket.dfc.DfcReader;
import com.cindersocket.dfc.DfcResponses;
import com.cindersocket.dfc.DfcSdm;
import com.cindersocket.dfc.DfcTransactionMacVerifier;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HexFormat;

/** Binding-level vectors and marshalling boundaries for the standalone Java APIs. */
public final class DfcAdvancedApiTest {
  @FunctionalInterface
  private interface CheckedOperation {
    void run() throws Exception;
  }

  private static final HexFormat HEX = HexFormat.of();
  private static final byte[] UID = hex("0483B4F2CF1890");

  private DfcAdvancedApiTest() {}

  private static byte[] hex(String value) {
    return HEX.parseHex(value);
  }

  private static void require(boolean condition, String message) {
    if (!condition)
      throw new AssertionError(message);
  }

  private static void requireHex(byte[] actual, String expected, String message) {
    require(Arrays.equals(actual, hex(expected)), message);
  }

  private static void requireFailure(CheckedOperation operation, String message) {
    try {
      operation.run();
    } catch (Exception expected) {
      return;
    }
    throw new AssertionError(message);
  }

  private static void testIsoChainedConstructorsAndAppendRecord() throws Exception {
    require(DfcCommand.readData(1, 2, 3, true).instruction() == 0xAD, "wrong ReadData opcode");
    require(DfcCommand.writeData(1, 2, hex("A5"), true).instruction() == 0x8D,
        "wrong WriteData opcode");
    require(
        DfcCommand.readRecords(1, 2, 3, true).instruction() == 0xAB, "wrong ReadRecords opcode");
    require(DfcCommand.writeRecord(1, 2, hex("A5"), true).instruction() == 0x8B,
        "wrong WriteRecord opcode");
    require(DfcCommand.updateRecord(1, 2, 3, hex("A5"), true).instruction() == 0xBA,
        "wrong UpdateRecord opcode");
    for (String line : Files.readAllLines(Path.of("tests", "iso7816-helper-vectors.txt"))) {
      if (line.isEmpty() || line.startsWith("#"))
        continue;
      String[] fields = line.split("\\|", -1);
      if (fields[0].equals("append-record")) {
        requireHex(DfcIso7816.appendRecord(Integer.parseInt(fields[2]), hex(fields[1])), fields[3],
            "wrong APPEND RECORD APDU");
      } else {
        require(fields[0].equals("parse-response"), "unknown ISO helper vector");
        var response = DfcIso7816.parseResponse(hex(fields[1]));
        requireHex(response.data(), fields[2], "wrong ISO response data");
        require(response.statusWord() == Integer.parseInt(fields[3], 16), "wrong ISO status word");
      }
    }
  }

  private static void requireIllegalArgument(CheckedOperation operation, String message) {
    try {
      operation.run();
    } catch (IllegalArgumentException expected) {
      return;
    } catch (Exception other) {
      throw new AssertionError(message + ": wrong exception", other);
    }
    throw new AssertionError(message);
  }

  private static void requireConfigurationAccepted(CheckedOperation operation, String message) {
    try {
      operation.run();
    } catch (IllegalArgumentException invalid) {
      throw new AssertionError(message, invalid);
    } catch (DfcException expectedAuthenticationFailure) {
      // The synthetic input has no valid MAC; reaching native verification is the assertion.
    } catch (Exception other) {
      throw new AssertionError(message + ": wrong exception", other);
    }
  }

  private static void testReaderAuthenticationValidation() throws Exception {
    try (var reader = new DfcReader(frame -> {
      throw new AssertionError("invalid authentication reached the transport");
    })) {
      requireIllegalArgument(()
                                 -> reader.authenticate(DfcReader.Cipher.AES, 0, new byte[15],
                                     DfcReader.Framing.NATIVE),
          "short native-authentication key accepted");
      requireIllegalArgument(()
                                 -> reader.authenticateForReplay(DfcReader.Cipher.AES, 256,
                                     new byte[16], DfcReader.Framing.NATIVE, new byte[16]),
          "wide native-authentication key number accepted");
      requireIllegalArgument(
          ()
              -> reader.authenticateIso7816(0x20, DfcReader.Iso7816Algorithm.TDEA2, new byte[16]),
          "reserved ISO key-reference bits accepted");
      requireIllegalArgument(
          ()
              -> reader.authenticateIso7816(0x0e, DfcReader.Iso7816Algorithm.TDEA2, new byte[16]),
          "out-of-range ISO key number accepted");
      requireIllegalArgument(
          ()
              -> reader.authenticateIso7816(0, DfcReader.Iso7816Algorithm.TDEA3, new byte[16]),
          "short ISO three-key TDEA key accepted");
      requireIllegalArgument(
          ()
              -> reader.authenticateIso7816ForReplay(
                  0, DfcReader.Iso7816Algorithm.AES, new byte[16], new byte[8], new byte[16]),
          "short ISO replay challenge accepted");
      requireIllegalArgument(()
                                 -> reader.authenticateEv2First(
                                     0, new byte[16], new byte[1], DfcReader.Framing.NATIVE),
          "partial EV2 capabilities accepted");
      requireIllegalArgument(()
                                 -> reader.authenticateEv2ForReplay(false, 0, new byte[16],
                                     new byte[6], DfcReader.Framing.NATIVE, new byte[16]),
          "non-first EV2 capabilities accepted");
      requireIllegalArgument(()
                                 -> reader.authenticateEv2ForReplay(true, 0, new byte[16],
                                     new byte[0], DfcReader.Framing.NATIVE, new byte[15]),
          "short EV2 replay challenge accepted");
    }
  }

  private static void testDiversification() throws Exception {
    byte[] aesMaster = hex("00112233445566778899AABBCCDDEEFF");
    requireHex(DfcKeyDiversification.diversify(DfcKeyDiversification.Algorithm.AES128, aesMaster,
                   hex("04782E21801D803042F54E585020416275")),
        "A8DD63A3B89D54B37CA802473FDA9175", "AES AN10922 vector mismatch");
    requireHex(DfcKeyDiversification.diversify(DfcKeyDiversification.Algorithm.TDEA2, aesMaster,
                   hex("04782E21801D803042F54E58502041")),
        "16F9587D9E8910C96B9648D006107DD7", "two-key TDEA AN10922 vector mismatch");
    requireHex(DfcKeyDiversification.diversify(DfcKeyDiversification.Algorithm.TDEA3,
                   hex("00112233445566778899AABBCCDDEEFF0102030405060708"),
                   hex("04782E21801D803042F54E5850")),
        "2E0DD03774D3FA9B5705AB0BDA91CA0B55B8E07FCDBF10EC",
        "three-key TDEA AN10922 vector mismatch");
    requireFailure(()
                       -> DfcKeyDiversification.diversify(
                           DfcKeyDiversification.Algorithm.AES128, new byte[15], new byte[] {1}),
        "short AN10922 key accepted");
    requireFailure(()
                       -> DfcKeyDiversification.diversify(
                           DfcKeyDiversification.Algorithm.AES128, new byte[16], new byte[32]),
        "oversized AN10922 input accepted");
  }

  private static void testResponseDecoders() throws Exception {
    var version =
        DfcResponses.decodeVersion(hex("04010101001A0504010101041A05045704EA916F80B90C2145901921"));
    require(version.hardware().vendorId() == 4 && version.software().minorVersion() == 4,
        "version fields mismatch");
    requireHex(version.uid(), "045704EA916F80", "version UID mismatch");
    requireFailure(() -> DfcResponses.decodeVersion(new byte[27]), "short version accepted");

    var aids = DfcResponses.decodeApplicationIds(hex("3141F5030201"));
    require(aids.size() == 2, "application count mismatch");
    requireHex(aids.get(0), "F54131", "first AID byte order mismatch");
    requireHex(aids.get(1), "010203", "second AID byte order mismatch");
    requireFailure(
        () -> DfcResponses.decodeApplicationIds(new byte[] {1, 2}), "partial AID accepted");
    require(DfcResponses.decodeFileIds(new byte[] {1, 7, 31}).equals(java.util.List.of(1, 7, 31)),
        "file IDs mismatch");

    var standard = DfcResponses.decodeFileSettings(hex("00013012360000"));
    require(standard.type() == DfcResponses.FileType.STANDARD_DATA
            && standard.communicationMode() == DfcReader.Communication.MAC && standard.size() == 54
            && standard.access().read().keyNumber() == 1,
        "standard file settings mismatch");
    var value = DfcResponses.decodeFileSettings(hex("0200EEEE9CFFFFFF640000000B00000001"));
    require(value.type() == DfcResponses.FileType.VALUE
            && value.communicationMode() == DfcReader.Communication.PLAIN
            && value.lowerLimit() == -100 && value.upperLimit() == 100
            && value.limitedCreditEnabled(),
        "value file settings mismatch");
    var records = DfcResponses.decodeFileSettings(hex("0301EF12200000100000070000"));
    require(records.type() == DfcResponses.FileType.LINEAR_RECORD
            && records.communicationMode() == DfcReader.Communication.MAC
            && records.recordSize() == 32 && records.maxRecords() == 16
            && records.currentRecords() == 7,
        "record file settings mismatch");
    requireFailure(
        () -> DfcResponses.decodeFileSettings(hex("7F000000")), "unknown file type accepted");
    requireFailure(
        () -> DfcResponses.decodeFileSettings(new byte[] {0}), "truncated file settings accepted");

    var simpleKeys = DfcResponses.decodeKeySettings(hex("0F01"));
    require(simpleKeys.keyCount() == 1 && simpleKeys.activeKeySetVersion() == null,
        "simple key settings mismatch");
    var extendedKeys = DfcResponses.decodeKeySettings(hex("0F8321041002"));
    require(extendedKeys.activeKeySetVersion() == 0x21 && extendedKeys.keySetCount() == 4
            && extendedKeys.maxKeySize() == 16,
        "extended key settings mismatch");
    requireFailure(
        () -> DfcResponses.decodeKeySettings(hex("0F0F")), "unsupported key count accepted");
    requireFailure(
        () -> DfcResponses.decodeKeySettings(new byte[] {0}), "truncated key settings accepted");
    require(
        DfcResponses.decodeKeyVersion(new byte[] {(byte) 0xA5}) == 0xA5, "key version mismatch");
    requireFailure(() -> DfcResponses.decodeKeyVersion(new byte[0]), "empty key version accepted");
    requireFailure(() -> DfcResponses.decodeKeyVersion(new byte[2]), "long key version accepted");
  }

  private static byte[] sdmMessage() {
    return "0483B4F2CF1890000001163F0AC4319102F37F4B61FE6BFDE1469CF53E287D682A2E".getBytes(
        StandardCharsets.US_ASCII);
  }

  private static DfcSdm.Config sdmConfig() {
    return new DfcSdm.Config(20, 52, new DfcSdm.Field(0, 7), 14, null, new DfcSdm.Field(20, 32));
  }

  private static void testSdm() throws Exception {
    byte[] message = sdmMessage();
    var verified = DfcSdm.verify(message, sdmConfig(), new byte[16], null);
    requireHex(verified.uid(), "0483B4F2CF1890", "SDM UID mismatch");
    require(verified.readCounter() == 1, "SDM counter mismatch");
    requireHex(
        verified.decryptedFileData(), "00112233445566778899AABBCCDDEEFF", "SDM file data mismatch");

    byte[] wrongKey = new byte[16];
    wrongKey[0] = 1;
    requireFailure(
        () -> DfcSdm.verify(message, sdmConfig(), wrongKey, null), "wrong SDM key accepted");
    byte[] modified = message.clone();
    modified[30] ^= 1;
    requireFailure(()
                       -> DfcSdm.verify(modified, sdmConfig(), new byte[16], null),
        "modified SDM input accepted");
    requireFailure(
        () -> DfcSdm.verify(message, sdmConfig(), new byte[15], null), "short SDM key accepted");
    requireFailure(()
                       -> DfcSdm.verify(message, sdmConfig(), new byte[16], new byte[15]),
        "short SDM metadata key accepted");
    requireFailure(() -> new DfcSdm.Field(-1, 1), "negative SDM offset accepted");
    requireFailure(
        ()
            -> DfcSdm.verify(message,
                new DfcSdm.Config(20, 52, null, null, null, new DfcSdm.Field(0, Integer.MAX_VALUE)),
                new byte[16], null),
        "oversized SDM field accepted");

    byte[] synthetic = new byte[128];
    Arrays.fill(synthetic, (byte) '0');
    for (int length : new int[] {7, 10})
      requireConfigurationAccepted(
          ()
              -> DfcSdm.verify(synthetic,
                  new DfcSdm.Config(80, 96, new DfcSdm.Field(0, length), null, null, null),
                  new byte[16], null),
          "valid plain UID length rejected");
    requireIllegalArgument(
        ()
            -> DfcSdm.verify(synthetic,
                new DfcSdm.Config(80, 96, new DfcSdm.Field(0, 14), null, null, null), new byte[16],
                null),
        "plain UID ASCII span was accepted as decoded length");
    requireConfigurationAccepted(
        ()
            -> DfcSdm.verify(synthetic,
                new DfcSdm.Config(80, 96, new DfcSdm.Field(108, 10), null, null, null),
                new byte[16], null),
        "scaled plain UID range rejected");
    requireIllegalArgument(
        ()
            -> DfcSdm.verify(synthetic,
                new DfcSdm.Config(80, 96, new DfcSdm.Field(109, 10), null, null, null),
                new byte[16], null),
        "out-of-bounds scaled plain UID range accepted");
    for (int length : new int[] {32, 64}) {
      requireConfigurationAccepted(
          ()
              -> DfcSdm.verify(synthetic,
                  new DfcSdm.Config(80, 96, null, null, new DfcSdm.Field(0, length), null),
                  new byte[16], new byte[16]),
          "valid encrypted PICC-data length rejected");
      requireConfigurationAccepted(
          ()
              -> DfcSdm.verify(synthetic,
                  new DfcSdm.Config(0, 96, null, null, null, new DfcSdm.Field(0, length)),
                  new byte[16], null),
          "valid encrypted file-data length rejected");
    }
    requireIllegalArgument(
        ()
            -> DfcSdm.verify(synthetic,
                new DfcSdm.Config(80, 96, null, null, new DfcSdm.Field(0, 16), null), new byte[16],
                new byte[16]),
        "short encrypted PICC-data field accepted");
    requireIllegalArgument(
        ()
            -> DfcSdm.verify(synthetic,
                new DfcSdm.Config(0, 96, null, null, null, new DfcSdm.Field(0, 16)), new byte[16],
                null),
        "short encrypted file-data field accepted");
  }

  private static DfcTransactionMacVerifier verifier(int capacity) throws Exception {
    return new DfcTransactionMacVerifier(new byte[16], UID, 1, capacity);
  }

  private static void testTransactionMac() throws Exception {
    requireFailure(()
                       -> new DfcTransactionMacVerifier(new byte[15], UID, 1, 64),
        "short transaction key accepted");
    requireFailure(()
                       -> new DfcTransactionMacVerifier(new byte[16], new byte[6], 1, 64),
        "invalid transaction UID accepted");
    requireFailure(()
                       -> new DfcTransactionMacVerifier(new byte[16], UID, 1, 0),
        "zero transaction capacity accepted");
    byte[] captured = hex("352E57ADDA911EDC");
    try (var receipt = verifier(64)) {
      receipt.addValue(0x0C, 5, 1);
      require(receipt.verify(captured), "captured transaction receipt rejected");
      captured[7] ^= 1;
      require(!receipt.verify(captured), "modified transaction receipt accepted");
      requireFailure(() -> receipt.verify(new byte[7]), "short transaction MAC accepted");
    }
    try (var allInputs = verifier(192)) {
      allInputs.addData(0x3D, 2, 0x030201, 3, hex("A1B2C3"));
      allInputs.addRecordUpdate(0xDB, 3, 4, 5, 2, hex("4455"));
      allInputs.addValue(0x0C, 5, 1);
      allInputs.addClearRecord(4);
      allInputs.addReaderId(new byte[16], new byte[16]);
      require(!allInputs.verify(new byte[8]), "unrelated receipt accepted");
    }
    try (var bounded = verifier(192)) {
      requireFailure(
          () -> bounded.addData(256, 2, 0, 1, new byte[] {1}), "wrapped command accepted");
      requireFailure(
          () -> bounded.addData(0x3D, 2, 0, 2, new byte[] {1}), "mismatched data length accepted");
      requireFailure(
          () -> bounded.addReaderId(new byte[15], new byte[16]), "short reader ID accepted");
      bounded.addValue(0x0C, 5, 1);
      require(bounded.verify(hex("352E57ADDA911EDC")), "failed input changed verifier state");
    }
    try (var tooSmall = verifier(16)) {
      requireFailure(()
                         -> tooSmall.addData(0x3D, 2, 0, 3, hex("A1B2C3")),
          "transaction input exceeded capacity");
    }

    byte[] wrongKey = new byte[16];
    wrongKey[0] = 1;
    try (var receipt = new DfcTransactionMacVerifier(wrongKey, UID, 1, 64)) {
      receipt.addValue(0x0C, 5, 1);
      require(!receipt.verify(hex("352E57ADDA911EDC")), "wrong transaction key accepted");
    }
    try (var receipt = new DfcTransactionMacVerifier(new byte[16], UID, 2, 64)) {
      receipt.addValue(0x0C, 5, 1);
      require(!receipt.verify(hex("352E57ADDA911EDC")), "wrong counter accepted");
    }
    try (var reordered = verifier(64)) {
      reordered.addValue(0xDC, 5, 2);
      reordered.addValue(0x0C, 5, 1);
      require(!reordered.verify(hex("7BEE577D5D8D0C69")), "reordered transaction accepted");
    }
  }

  public static void main(String[] arguments) throws Exception {
    testDiversification();
    testResponseDecoders();
    testSdm();
    testTransactionMac();
    testReaderAuthenticationValidation();
    testIsoChainedConstructorsAndAppendRecord();
  }
}
