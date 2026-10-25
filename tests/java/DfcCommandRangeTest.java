package com.cindersocket.dfc;

import java.util.Arrays;

/** Verifies range-command opcodes and little-endian offset/length encoding. */
public final class DfcCommandRangeTest {
  private static void checkCommand(
      DfcCommand command, int instruction, byte[] expectedData, String label) {
    if (command.instruction() != instruction)
      throw new AssertionError(label + ": instruction");
    if (!Arrays.equals(command.data(), expectedData))
      throw new AssertionError(label + ": data");
  }

  public static void main(String[] arguments) {
    byte[] value = {(byte) 0xa5, 0x5a};
    byte[] expected = {0x07, 0x03, 0x02, 0x01, 0x02, 0x00, 0x00, (byte) 0xa5, 0x5a};
    byte[] expectedUpdate = {
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x02, 0x00, 0x00, (byte) 0xa5, 0x5a};

    checkCommand(DfcCommand.writeData(7, 0x010203, value), 0x3d, expected, "WriteData");
    checkCommand(DfcCommand.writeRecord(7, 0x010203, value), 0x3b, expected, "WriteRecord");
    checkCommand(DfcCommand.updateRecord(7, 0x040506, 0x010203, value), 0xdb, expectedUpdate,
        "UpdateRecord");
  }
}
