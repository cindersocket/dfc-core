package com.cindersocket.dfc;

import java.util.Objects;

/**
 * One native command before transport framing or secure messaging.
 *
 * @param instruction unsigned one-byte instruction
 * @param data command payload in wire order
 */
public record DfcCommand(int instruction, byte[] data) {
  private static final int GET_VERSION = 0x60;
  private static final int GET_FREE_MEMORY = 0x6e;
  private static final int FORMAT_PICC = 0xfc;
  private static final int GET_KEY_SETTINGS = 0x45;
  private static final int GET_APPLICATION_IDS = 0x6a;
  private static final int GET_DF_NAMES = 0x6d;
  private static final int GET_FILE_IDS = 0x6f;
  private static final int GET_ISO_FILE_IDS = 0x61;
  private static final int GET_CARD_UID = 0x51;
  private static final int COMMIT_TRANSACTION = 0xc7;
  private static final int ABORT_TRANSACTION = 0xa7;
  private static final int READ_SIGNATURE = 0x3c;
  private static final int GET_KEY_VERSION = 0x64;
  private static final int GET_FILE_SETTINGS = 0xf5;
  private static final int GET_FILE_COUNTERS = 0xf6;
  private static final int DELETE_FILE = 0xdf;
  private static final int CLEAR_RECORD_FILE = 0xeb;
  private static final int GET_VALUE = 0x6c;
  private static final int SELECT_APPLICATION = 0x5a;
  private static final int READ_DATA = 0xbd;
  private static final int WRITE_DATA = 0x3d;
  private static final int READ_RECORDS = 0xbb;
  private static final int WRITE_RECORD = 0x3b;
  private static final int UPDATE_RECORD = 0xdb;
  private static final int CREDIT = 0x0c;
  private static final int DEBIT = 0xdc;
  private static final int LIMITED_CREDIT = 0x1c;

  /**
   * Validates and defensively copies the command payload.
   * @param instruction unsigned one-byte instruction
   * @param data command payload in wire order
   * @throws IllegalArgumentException if {@code instruction} is outside the unsigned byte range
   * @throws NullPointerException if {@code data} is null
   */
  public DfcCommand {
    if ((instruction & ~0xff) != 0)
      throw new IllegalArgumentException("instruction");
    data = Objects.requireNonNull(data, "data").clone();
  }
  /**
   * Returns the payload.
   * @return a defensive copy in wire order
   */
  @Override
  public byte[] data() {
    return data.clone();
  }
  /**
   * Creates GetVersion.
   * @return the command
   */
  public static DfcCommand getVersion() {
    return new DfcCommand(GET_VERSION, new byte[0]);
  }
  /**
   * Creates GetFreeMemory.
   * @return the command
   */
  public static DfcCommand getFreeMemory() {
    return new DfcCommand(GET_FREE_MEMORY, new byte[0]);
  }
  /**
   * Creates FormatPICC.
   * @return the command
   */
  public static DfcCommand formatPicc() {
    return new DfcCommand(FORMAT_PICC, new byte[0]);
  }
  /**
   * Creates GetKeySettings.
   * @return the command for the selected application
   */
  public static DfcCommand getKeySettings() {
    return new DfcCommand(GET_KEY_SETTINGS, new byte[0]);
  }
  /**
   * Creates GetApplicationIDs.
   * @return the command
   */
  public static DfcCommand getApplicationIds() {
    return new DfcCommand(GET_APPLICATION_IDS, new byte[0]);
  }
  /**
   * Creates GetDFNames.
   * @return the command
   */
  public static DfcCommand getDfNames() {
    return new DfcCommand(GET_DF_NAMES, new byte[0]);
  }
  /**
   * Creates GetFileIDs.
   * @return the command
   */
  public static DfcCommand getFileIds() {
    return new DfcCommand(GET_FILE_IDS, new byte[0]);
  }
  /**
   * Creates GetISOFileIDs.
   * @return the command
   */
  public static DfcCommand getIsoFileIds() {
    return new DfcCommand(GET_ISO_FILE_IDS, new byte[0]);
  }
  /**
   * Creates GetCardUID.
   * @return the command
   */
  public static DfcCommand getCardUid() {
    return new DfcCommand(GET_CARD_UID, new byte[0]);
  }
  /**
   * Creates CommitTransaction.
   * @return the command
   */
  public static DfcCommand commitTransaction() {
    return new DfcCommand(COMMIT_TRANSACTION, new byte[0]);
  }
  /**
   * Creates AbortTransaction.
   * @return the command
   */
  public static DfcCommand abortTransaction() {
    return new DfcCommand(ABORT_TRANSACTION, new byte[0]);
  }
  /**
   * Creates ReadSignature.
   *
   * @param signatureId unsigned one-byte signature identifier
   * @return a ReadSignature command
   * @throws IllegalArgumentException if {@code signatureId} is outside the unsigned byte range
   */
  public static DfcCommand readSignature(int signatureId) {
    return oneByte(READ_SIGNATURE, signatureId);
  }
  /**
   * Creates GetKeyVersion.
   *
   * @param keyNumber unsigned one-byte key number
   * @return a GetKeyVersion command
   * @throws IllegalArgumentException if {@code keyNumber} is outside the unsigned byte range
   */
  public static DfcCommand getKeyVersion(int keyNumber) {
    return oneByte(GET_KEY_VERSION, keyNumber);
  }
  /**
   * Creates GetFileSettings.
   *
   * @param fileNumber unsigned one-byte file number
   * @return a GetFileSettings command
   * @throws IllegalArgumentException if {@code fileNumber} is outside the unsigned byte range
   */
  public static DfcCommand getFileSettings(int fileNumber) {
    return oneByte(GET_FILE_SETTINGS, fileNumber);
  }
  /**
   * Creates GetFileCounters.
   *
   * @param fileNumber unsigned one-byte file number
   * @return a GetFileCounters command
   * @throws IllegalArgumentException if {@code fileNumber} is outside the unsigned byte range
   */
  public static DfcCommand getFileCounters(int fileNumber) {
    return oneByte(GET_FILE_COUNTERS, fileNumber);
  }
  /**
   * Creates DeleteFile.
   *
   * @param fileNumber unsigned one-byte file number
   * @return a DeleteFile command
   * @throws IllegalArgumentException if {@code fileNumber} is outside the unsigned byte range
   */
  public static DfcCommand deleteFile(int fileNumber) {
    return oneByte(DELETE_FILE, fileNumber);
  }
  /**
   * Creates ClearRecordFile.
   *
   * @param fileNumber unsigned one-byte file number
   * @return a ClearRecordFile command
   * @throws IllegalArgumentException if {@code fileNumber} is outside the unsigned byte range
   */
  public static DfcCommand clearRecordFile(int fileNumber) {
    return oneByte(CLEAR_RECORD_FILE, fileNumber);
  }
  /**
   * Creates GetValue.
   *
   * @param fileNumber unsigned one-byte file number
   * @return a GetValue command
   * @throws IllegalArgumentException if {@code fileNumber} is outside the unsigned byte range
   */
  public static DfcCommand getValue(int fileNumber) {
    return oneByte(GET_VALUE, fileNumber);
  }
  /**
   * Creates SelectApplication.
   *
   * @param aid three-byte application identifier in human-readable order
   * @return a SelectApplication command with the identifier encoded in wire order
   * @throws IllegalArgumentException if {@code aid} is not three bytes
   * @throws NullPointerException if {@code aid} is null
   */
  public static DfcCommand selectApplication(byte[] aid) {
    if (Objects.requireNonNull(aid, "aid").length != 3)
      throw new IllegalArgumentException("AID must be 3 bytes");
    return new DfcCommand(SELECT_APPLICATION, new byte[] {aid[2], aid[1], aid[0]});
  }
  /**
   * Creates ReadData.
   *
   * @param fileNumber unsigned one-byte file number
   * @param offset unsigned 24-bit byte offset
   * @param length unsigned 24-bit byte count
   * @return a ReadData command
   * @throws IllegalArgumentException if the file number or either 24-bit value is out of range
   */
  public static DfcCommand readData(int fileNumber, int offset, int length) {
    return new DfcCommand(READ_DATA, fileRange(fileNumber, offset, length));
  }
  /**
   * Creates WriteData.
   *
   * @param fileNumber unsigned one-byte file number
   * @param offset unsigned 24-bit byte offset
   * @param value bytes to write; copied into the command
   * @return a WriteData command
   * @throws IllegalArgumentException if the file number, offset, or payload length is out of range
   * @throws NullPointerException if {@code value} is null
   */
  public static DfcCommand writeData(int fileNumber, int offset, byte[] value) {
    return writeRange(WRITE_DATA, fileNumber, offset, value);
  }
  /**
   * Creates ReadRecords.
   *
   * @param fileNumber unsigned one-byte file number
   * @param firstRecord unsigned 24-bit first record number
   * @param count unsigned 24-bit record count; zero requests all remaining records
   * @return a ReadRecords command
   * @throws IllegalArgumentException if the file number or either 24-bit value is out of range
   */
  public static DfcCommand readRecords(int fileNumber, int firstRecord, int count) {
    return new DfcCommand(READ_RECORDS, fileRange(fileNumber, firstRecord, count));
  }
  /**
   * Creates WriteRecord.
   *
   * @param fileNumber unsigned one-byte file number
   * @param offset unsigned 24-bit byte offset within the record
   * @param value bytes to write; copied into the command
   * @return a WriteRecord command
   * @throws IllegalArgumentException if the file number, offset, or payload length is out of range
   * @throws NullPointerException if {@code value} is null
   */
  public static DfcCommand writeRecord(int fileNumber, int offset, byte[] value) {
    return writeRange(WRITE_RECORD, fileNumber, offset, value);
  }
  /**
   * Creates UpdateRecord.
   *
   * @param fileNumber unsigned one-byte file number
   * @param recordNumber unsigned 24-bit record number
   * @param offset unsigned 24-bit byte offset within the record
   * @param value bytes to write; copied into the command
   * @return an UpdateRecord command
   * @throws IllegalArgumentException if the file number, record number, offset, or payload length
   *     is out of range
   * @throws NullPointerException if {@code value} is null
   */
  public static DfcCommand updateRecord(
      int fileNumber, int recordNumber, int offset, byte[] value) {
    if ((recordNumber & ~0xffffff) != 0)
      throw new IllegalArgumentException("recordNumber");
    byte[] tail = writeRange(UPDATE_RECORD, fileNumber, offset, value).data();
    byte[] data = new byte[tail.length + 3];
    data[0] = tail[0];
    put24(data, 1, recordNumber);
    System.arraycopy(tail, 1, data, 4, tail.length - 1);
    return new DfcCommand(UPDATE_RECORD, data);
  }
  /**
   * Creates Credit.
   *
   * @param fileNumber unsigned one-byte file number
   * @param amount signed 32-bit credit amount
   * @return a Credit command
   * @throws IllegalArgumentException if {@code fileNumber} is outside the unsigned byte range
   */
  public static DfcCommand credit(int fileNumber, int amount) {
    return valueOperation(CREDIT, fileNumber, amount);
  }
  /**
   * Creates Debit.
   *
   * @param fileNumber unsigned one-byte file number
   * @param amount signed 32-bit debit amount
   * @return a Debit command
   * @throws IllegalArgumentException if {@code fileNumber} is outside the unsigned byte range
   */
  public static DfcCommand debit(int fileNumber, int amount) {
    return valueOperation(DEBIT, fileNumber, amount);
  }
  /**
   * Creates LimitedCredit.
   *
   * @param fileNumber unsigned one-byte file number
   * @param amount signed 32-bit limited-credit amount
   * @return a LimitedCredit command
   * @throws IllegalArgumentException if {@code fileNumber} is outside the unsigned byte range
   */
  public static DfcCommand limitedCredit(int fileNumber, int amount) {
    return valueOperation(LIMITED_CREDIT, fileNumber, amount);
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
