package com.cindersocket.dfc;

import java.util.Arrays;
import java.nio.file.Files;
import java.nio.file.Path;

/** Verifies range-command opcodes and little-endian offset/length encoding. */
public final class DfcCommandRangeTest {
  private static void checkCommand(
      DfcCommand command, int instruction, byte[] expectedData, String label) {
    if (command.instruction() != instruction)
      throw new AssertionError(label + ": instruction");
    if (!Arrays.equals(command.data(), expectedData))
      throw new AssertionError(label + ": data");
  }

  private static byte[] hex(String value) {
    return java.util.HexFormat.of().parseHex(value);
  }

  private static DfcCommand construct(String name, String arguments) {
    java.util.function.IntSupplier number = () -> Integer.parseInt(arguments);
    return switch (name) {
      case "get-version" -> DfcCommand.getVersion();
      case "get-free-memory" -> DfcCommand.getFreeMemory();
      case "format-picc" -> DfcCommand.formatPicc();
      case "get-key-settings" -> DfcCommand.getKeySettings();
      case "get-application-ids" -> DfcCommand.getApplicationIds();
      case "get-df-names" -> DfcCommand.getDfNames();
      case "get-file-ids" -> DfcCommand.getFileIds();
      case "get-iso-file-ids" -> DfcCommand.getIsoFileIds();
      case "get-card-uid" -> DfcCommand.getCardUid();
      case "read-signature" -> DfcCommand.readSignature(number.getAsInt());
      case "get-key-version" -> DfcCommand.getKeyVersion(number.getAsInt());
      case "select-application" -> DfcCommand.selectApplication(hex(arguments));
      case "get-file-settings" -> DfcCommand.getFileSettings(number.getAsInt());
      case "get-file-counters" -> DfcCommand.getFileCounters(number.getAsInt());
      case "delete-file" -> DfcCommand.deleteFile(number.getAsInt());
      case "clear-record-file" -> DfcCommand.clearRecordFile(number.getAsInt());
      case "get-value" -> DfcCommand.getValue(number.getAsInt());
      case "read-data", "read-data-iso-chaining" -> {
        String[] fields = arguments.split(",");
        yield DfcCommand.readData(Integer.parseInt(fields[0]), Integer.parseInt(fields[1]),
            Integer.parseInt(fields[2]), name.equals("read-data-iso-chaining"));
      }
      case "write-data", "write-data-iso-chaining", "write-record", "write-record-iso-chaining" -> {
        String[] fields = arguments.split(",");
        int file = Integer.parseInt(fields[0]);
        int offset = Integer.parseInt(fields[1]);
        boolean isoChaining = name.endsWith("-iso-chaining");
        yield name.startsWith("write-data")
            ? DfcCommand.writeData(file, offset, hex(fields[2]), isoChaining)
            : DfcCommand.writeRecord(file, offset, hex(fields[2]), isoChaining);
      }
      case "read-records", "read-records-iso-chaining" -> {
        String[] fields = arguments.split(",");
        yield DfcCommand.readRecords(Integer.parseInt(fields[0]), Integer.parseInt(fields[1]),
            Integer.parseInt(fields[2]), name.equals("read-records-iso-chaining"));
      }
      case "update-record", "update-record-iso-chaining" -> {
        String[] fields = arguments.split(",");
        yield DfcCommand.updateRecord(Integer.parseInt(fields[0]), Integer.parseInt(fields[1]),
            Integer.parseInt(fields[2]), hex(fields[3]), name.equals("update-record-iso-chaining"));
      }
      case "credit", "debit", "limited-credit" -> {
        String[] fields = arguments.split(",");
        int file = Integer.parseInt(fields[0]);
        int amount = Integer.parseInt(fields[1]);
        yield switch (name) {
          case "credit" -> DfcCommand.credit(file, amount);
          case "debit" -> DfcCommand.debit(file, amount);
          default -> DfcCommand.limitedCredit(file, amount);
        };
      }
      case "commit-transaction" ->
        arguments.isEmpty() ? DfcCommand.commitTransaction()
                            : DfcCommand.commitTransaction(number.getAsInt());
      case "abort-transaction" -> DfcCommand.abortTransaction();
      default -> throw new IllegalArgumentException("unknown constructor " + name);
    };
  }

  private static void checkSharedVectors() throws Exception {
    for (String line : Files.readAllLines(Path.of("tests", "command-constructor-vectors.txt"))) {
      if (line.isEmpty() || line.startsWith("#"))
        continue;
      String[] fields = line.split("\\|", -1);
      DfcCommand command = construct(fields[0], fields[1]);
      byte[] actual = new byte[command.data().length + 1];
      actual[0] = (byte) command.instruction();
      System.arraycopy(command.data(), 0, actual, 1, command.data().length);
      if (!Arrays.equals(actual, hex(fields[2])))
        throw new AssertionError(fields[0] + ": shared vector");
    }
  }

  private static void checkFileBounds() {
    for (int fileNumber : new int[] {-1, 32, 256}) {
      for (java.util.function.IntFunction<DfcCommand> constructor :
          java.util.List.<java.util.function.IntFunction<DfcCommand>>of(DfcCommand::getFileSettings,
              DfcCommand::getFileCounters, DfcCommand::deleteFile, DfcCommand::clearRecordFile,
              DfcCommand::getValue)) {
        try {
          constructor.apply(fileNumber);
          throw new AssertionError("accepted file number " + fileNumber);
        } catch (IllegalArgumentException expected) {
          // Expected.
        }
      }
      try {
        DfcCommand.readData(fileNumber, 0, 1);
        throw new AssertionError("ReadData accepted file number " + fileNumber);
      } catch (IllegalArgumentException expected) {
        // Expected.
      }
      try {
        DfcCommand.credit(fileNumber, 1);
        throw new AssertionError("Credit accepted file number " + fileNumber);
      } catch (IllegalArgumentException expected) {
        // Expected.
      }
    }
  }

  private static void checkPayloadBoundaries() throws Exception {
    for (String line : Files.readAllLines(Path.of("tests", "command-constructor-boundaries.txt"))) {
      if (line.isEmpty() || line.startsWith("#"))
        continue;
      String[] fields = line.split("\\|", -1);
      int length = Integer.parseInt(fields[1]);
      byte[] value = new byte[length];
      boolean accepted;
      try {
        switch (fields[0]) {
          case "write-data" -> DfcCommand.writeData(1, 0, value);
          case "write-record" -> DfcCommand.writeRecord(1, 0, value);
          case "update-record" -> DfcCommand.updateRecord(1, 0, 0, value);
          default -> throw new IllegalArgumentException("unknown constructor " + fields[0]);
        }
        accepted = true;
      } catch (IllegalArgumentException error) {
        accepted = false;
      }
      if (accepted != fields[2].equals("accept"))
        throw new AssertionError(fields[0] + " " + length + ": payload boundary");
    }
  }

  public static void main(String[] arguments) throws Exception {
    byte[] value = {(byte) 0xa5, 0x5a};
    byte[] expected = {0x07, 0x03, 0x02, 0x01, 0x02, 0x00, 0x00, (byte) 0xa5, 0x5a};
    byte[] expectedUpdate = {
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x02, 0x00, 0x00, (byte) 0xa5, 0x5a};

    checkCommand(DfcCommand.writeData(7, 0x010203, value), 0x3d, expected, "WriteData");
    checkCommand(DfcCommand.writeRecord(7, 0x010203, value), 0x3b, expected, "WriteRecord");
    checkCommand(DfcCommand.updateRecord(7, 0x040506, 0x010203, value), 0xdb, expectedUpdate,
        "UpdateRecord");
    checkSharedVectors();
    checkFileBounds();
    checkPayloadBoundaries();
  }
}
