package com.cindersocket.dfc;

import java.util.Objects;

/** One native DESFire command before transport framing or secure messaging. */
public record DfcCommand(int instruction, byte[] data) {
  public DfcCommand {
    if ((instruction & ~0xff) != 0)
      throw new IllegalArgumentException("instruction");
    data = Objects.requireNonNull(data, "data").clone();
  }
  @Override
  public byte[] data() {
    return data.clone();
  }
  public static DfcCommand getVersion() {
    return new DfcCommand(0x60, new byte[0]);
  }
  public static DfcCommand getFreeMemory() {
    return new DfcCommand(0x6e, new byte[0]);
  }
  public static DfcCommand formatPicc() {
    return new DfcCommand(0xfc, new byte[0]);
  }
  public static DfcCommand getKeySettings() {
    return new DfcCommand(0x45, new byte[0]);
  }
  public static DfcCommand getApplicationIds() {
    return new DfcCommand(0x6a, new byte[0]);
  }
  public static DfcCommand getDfNames() {
    return new DfcCommand(0x6d, new byte[0]);
  }
  public static DfcCommand getFileIds() {
    return new DfcCommand(0x6f, new byte[0]);
  }
  public static DfcCommand getIsoFileIds() {
    return new DfcCommand(0x61, new byte[0]);
  }
  public static DfcCommand getCardUid() {
    return new DfcCommand(0x51, new byte[0]);
  }
  public static DfcCommand commitTransaction() {
    return new DfcCommand(0xc7, new byte[0]);
  }
  public static DfcCommand abortTransaction() {
    return new DfcCommand(0xa7, new byte[0]);
  }
  public static DfcCommand readSignature(int signatureId) {
    return oneByte(0x3c, signatureId);
  }
  public static DfcCommand getKeyVersion(int keyNumber) {
    return oneByte(0x64, keyNumber);
  }
  public static DfcCommand getFileSettings(int fileNumber) {
    return oneByte(0xf5, fileNumber);
  }
  public static DfcCommand getFileCounters(int fileNumber) {
    return oneByte(0xf6, fileNumber);
  }
  public static DfcCommand deleteFile(int fileNumber) {
    return oneByte(0xdf, fileNumber);
  }
  public static DfcCommand clearRecordFile(int fileNumber) {
    return oneByte(0xeb, fileNumber);
  }
  public static DfcCommand getValue(int fileNumber) {
    return oneByte(0x6c, fileNumber);
  }
  public static DfcCommand selectApplication(byte[] aid) {
    if (Objects.requireNonNull(aid, "aid").length != 3)
      throw new IllegalArgumentException("AID must be 3 bytes");
    return new DfcCommand(0x5a, aid);
  }
  public static DfcCommand readData(int fileNumber, int offset, int length) {
    return new DfcCommand(0xbd, fileRange(fileNumber, offset, length));
  }
  public static DfcCommand writeData(int fileNumber, int offset, byte[] value) {
    Objects.requireNonNull(value, "value");
    byte[] header = fileRange(fileNumber, offset, value.length);
    byte[] data = new byte[header.length + value.length];
    System.arraycopy(header, 0, data, 0, header.length);
    System.arraycopy(value, 0, data, header.length, value.length);
    return new DfcCommand(0x3d, data);
  }
  public static DfcCommand readRecords(int fileNumber, int firstRecord, int count) {
    return new DfcCommand(0xbb, fileRange(fileNumber, firstRecord, count));
  }
  public static DfcCommand writeRecord(int fileNumber, int offset, byte[] value) {
    return writeRange(0x3b, fileNumber, offset, value);
  }
  public static DfcCommand updateRecord(
      int fileNumber, int recordNumber, int offset, byte[] value) {
    if ((recordNumber & ~0xffffff) != 0)
      throw new IllegalArgumentException("recordNumber");
    byte[] tail = writeRange(0xdb, fileNumber, offset, value).data();
    byte[] data = new byte[tail.length + 3];
    data[0] = tail[0];
    put24(data, 1, recordNumber);
    System.arraycopy(tail, 1, data, 4, tail.length - 1);
    return new DfcCommand(0xdb, data);
  }
  public static DfcCommand credit(int fileNumber, int amount) {
    return valueOperation(0x0c, fileNumber, amount);
  }
  public static DfcCommand debit(int fileNumber, int amount) {
    return valueOperation(0xdc, fileNumber, amount);
  }
  public static DfcCommand limitedCredit(int fileNumber, int amount) {
    return valueOperation(0x1c, fileNumber, amount);
  }
  private static DfcCommand oneByte(int instruction, int value) {
    if ((value & ~0xff) != 0)
      throw new IllegalArgumentException("byte value");
    return new DfcCommand(instruction, new byte[] {(byte) value});
  }
  private static DfcCommand writeRange(int instruction, int fileNumber, int offset, byte[] value) {
    Objects.requireNonNull(value, "value");
    byte[] header = fileRange(fileNumber, offset, value.length);
    byte[] data = new byte[header.length + value.length];
    System.arraycopy(header, 0, data, 0, header.length);
    System.arraycopy(value, 0, data, header.length, value.length);
    return new DfcCommand(instruction, data);
  }
  private static DfcCommand valueOperation(int instruction, int fileNumber, int amount) {
    if ((fileNumber & ~0xff) != 0)
      throw new IllegalArgumentException("fileNumber");
    return new DfcCommand(instruction,
        new byte[] {(byte) fileNumber, (byte) amount, (byte) (amount >>> 8), (byte) (amount >>> 16),
            (byte) (amount >>> 24)});
  }
  private static byte[] fileRange(int fileNumber, int offset, int length) {
    if ((fileNumber & ~0xff) != 0 || offset < 0 || offset > 0xffffff || length < 0
        || length > 0xffffff)
      throw new IllegalArgumentException("file range");
    return new byte[] {(byte) fileNumber, (byte) offset, (byte) (offset >>> 8),
        (byte) (offset >>> 16), (byte) length, (byte) (length >>> 8), (byte) (length >>> 16)};
  }
  private static void put24(byte[] output, int offset, int value) {
    output[offset] = (byte) value;
    output[offset + 1] = (byte) (value >>> 8);
    output[offset + 2] = (byte) (value >>> 16);
  }
}
