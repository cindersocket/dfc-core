package com.cindersocket.dfc;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/** Typed decoders for clear DESFire response payloads. */
public final class DfcResponses {
  private static final int STANDARD_DATA_FILE = 0;
  private static final int BACKUP_DATA_FILE = 1;
  private static final int VALUE_FILE = 2;

  /** Decoded access-right form. */
  public enum AccessKind {
    /** Access requires a numbered key. */ KEY,
    /** Access requires no authentication. */ FREE,
    /** Access is denied. */ DENIED
  }
  /**
   * One decoded access-right nibble.
   * @param kind key-controlled, free, or denied
   * @param keyNumber unsigned key number when {@code kind} is {@link AccessKind#KEY}; otherwise
   *     null
   */
  public record Access(AccessKind kind, Integer keyNumber) {}
  /**
   * Decoded file access rights.
   * @param read read access
   * @param write write access
   * @param readWrite combined read/write access
   * @param change settings-change access
   */
  public record AccessRights(Access read, Access write, Access readWrite, Access change) {}
  /**
   * One seven-byte hardware or software version block.
   * @param vendorId unsigned vendor identifier
   * @param type unsigned product type
   * @param subtype unsigned product subtype
   * @param majorVersion unsigned major version
   * @param minorVersion unsigned minor version
   * @param storageSize encoded storage-size byte
   * @param protocol encoded protocol byte
   */
  public record VersionPart(int vendorId, int type, int subtype, int majorVersion, int minorVersion,
      int storageSize, int protocol) {}
  /**
   * Decoded assembled GetVersion response.
   * @param hardware hardware version block
   * @param software software version block
   * @param uid seven-byte UID
   * @param batchNumber five-byte batch number
   * @param productionWeek encoded production-week byte returned by the card
   * @param productionYear encoded production-year byte returned by the card
   */
  public record Version(VersionPart hardware, VersionPart software, byte[] uid, byte[] batchNumber,
      int productionWeek, int productionYear) {
    /**
     * Defensively copies the mutable response fields.
     * @param hardware hardware version block
     * @param software software version block
     * @param uid seven-byte UID
     * @param batchNumber five-byte batch number
     * @param productionWeek encoded production-week byte returned by the card
     * @param productionYear encoded production-year byte returned by the card
     */
    public Version {
      uid = uid.clone();
      batchNumber = batchNumber.clone();
    }
    /**
     * Returns the UID.
     * @return a defensive seven-byte copy
     */
    @Override
    public byte[] uid() {
      return uid.clone();
    }
    /**
     * Returns the batch number.
     * @return a defensive five-byte copy
     */
    @Override
    public byte[] batchNumber() {
      return batchNumber.clone();
    }
  }
  /**
   * Decoded file settings. Fields that do not apply to the file type are null.
   * @param type unsigned native file type
   * @param communicationMode unsigned communication-mode value
   * @param accessRightsRaw unsigned packed access-right word
   * @param access decoded access rights
   * @param size data-file size in bytes
   * @param lowerLimit value-file lower limit
   * @param upperLimit value-file upper limit
   * @param limitedCreditValue value-file limited-credit bound
   * @param limitedCreditEnabled whether limited credit is enabled
   * @param recordSize record size in bytes
   * @param maxRecords record capacity
   * @param currentRecords current record count
   */
  public record FileSettings(int type, int communicationMode, int accessRightsRaw,
      AccessRights access, Integer size, Integer lowerLimit, Integer upperLimit,
      Integer limitedCreditValue, Boolean limitedCreditEnabled, Integer recordSize,
      Integer maxRecords, Integer currentRecords) {}
  /**
   * Decoded application or PICC key settings.
   * @param settings1 first settings byte
   * @param settings2 second settings byte
   * @param keyType unsigned key-type value
   * @param keyCount configured key count
   * @param activeKeySetVersion active key-set version, or null when unavailable
   * @param keySetCount configured key-set count, or null when unavailable
   * @param maxKeySize maximum key size in bytes, or null when unavailable
   * @param keySetSettings key-set settings byte, or null when unavailable
   */
  public record KeySettings(int settings1, int settings2, int keyType, int keyCount,
      Integer activeKeySetVersion, Integer keySetCount, Integer maxKeySize,
      Integer keySetSettings) {}

  private DfcResponses() {}

  private static VersionPart part(byte[] value, int offset) {
    return new VersionPart(value[offset] & 0xff, value[offset + 1] & 0xff, value[offset + 2] & 0xff,
        value[offset + 3] & 0xff, value[offset + 4] & 0xff, value[offset + 5] & 0xff,
        value[offset + 6] & 0xff);
  }

  /**
   * Decodes an assembled GetVersion payload.
   * @param response clear response payload without the status byte
   * @return typed version information with defensive byte-array copies
   * @throws DfcException if the payload is malformed
   */
  public static Version decodeVersion(byte[] response) throws DfcException {
    Objects.requireNonNull(response, "response");
    byte[] value = DfcNative.responseDecodeVersion(response);
    return new Version(part(value, 0), part(value, 7), java.util.Arrays.copyOfRange(value, 14, 21),
        java.util.Arrays.copyOfRange(value, 21, 26), value[26] & 0xff, value[27] & 0xff);
  }

  /**
   * Decodes GetApplicationIDs.
   * @param response clear response payload without the status byte
   * @return immutable list of three-byte identifiers in human-readable order
   * @throws DfcException if the payload is malformed
   */
  public static List<byte[]> decodeApplicationIds(byte[] response) throws DfcException {
    Objects.requireNonNull(response, "response");
    byte[] value = DfcNative.responseDecodeApplicationIds(response);
    List<byte[]> result = new ArrayList<>(value.length / 3);
    for (int offset = 0; offset < value.length; offset += 3)
      result.add(java.util.Arrays.copyOfRange(value, offset, offset + 3));
    return List.copyOf(result);
  }

  /**
   * Decodes GetFileIDs.
   * @param response clear response payload without the status byte
   * @return immutable list of unsigned file numbers
   * @throws DfcException if the payload is malformed
   */
  public static List<Integer> decodeFileIds(byte[] response) throws DfcException {
    Objects.requireNonNull(response, "response");
    byte[] value = DfcNative.responseDecodeFileIds(response);
    List<Integer> result = new ArrayList<>(value.length);
    for (byte number : value) result.add(number & 0xff);
    return List.copyOf(result);
  }

  private static Access access(byte[] value, int offset) {
    AccessKind kind = AccessKind.values()[value[offset] & 0xff];
    return new Access(kind, kind == AccessKind.KEY ? value[offset + 1] & 0xff : null);
  }

  private static FileSettings dataFileSettings(
      int type, int communicationMode, int rawRights, AccessRights rights, int size) {
    return new FileSettings(
        type, communicationMode, rawRights, rights, size, null, null, null, null, null, null, null);
  }

  private static FileSettings valueFileSettings(int type, int communicationMode, int rawRights,
      AccessRights rights, int lowerLimit, int upperLimit, int limitedCredit,
      boolean limitedCreditEnabled) {
    return new FileSettings(type, communicationMode, rawRights, rights, null, lowerLimit,
        upperLimit, limitedCredit, limitedCreditEnabled, null, null, null);
  }

  private static FileSettings recordFileSettings(int type, int communicationMode, int rawRights,
      AccessRights rights, int recordSize, int maxRecords, int currentRecords) {
    return new FileSettings(type, communicationMode, rawRights, rights, null, null, null, null,
        null, recordSize, maxRecords, currentRecords);
  }

  /**
   * Decodes GetFileSettings.
   * @param response clear response payload without the status byte
   * @return file-type-specific settings
   * @throws DfcException if the payload is malformed
   */
  public static FileSettings decodeFileSettings(byte[] response) throws DfcException {
    Objects.requireNonNull(response, "response");
    byte[] value = DfcNative.responseDecodeFileSettings(response);
    ByteBuffer little = ByteBuffer.wrap(value).order(ByteOrder.LITTLE_ENDIAN);
    int type = value[0] & 0xff;
    int communicationMode = value[1] & 0xff;
    int rawRights = little.getShort(4) & 0xffff;
    AccessRights rights =
        new AccessRights(access(value, 6), access(value, 8), access(value, 10), access(value, 12));
    if (type == STANDARD_DATA_FILE || type == BACKUP_DATA_FILE)
      return dataFileSettings(type, communicationMode, rawRights, rights, little.getInt(14));
    if (type == VALUE_FILE)
      return valueFileSettings(type, communicationMode, rawRights, rights, little.getInt(14),
          little.getInt(18), little.getInt(22), value[26] != 0);
    return recordFileSettings(type, communicationMode, rawRights, rights, little.getInt(14),
        little.getInt(18), little.getInt(22));
  }

  /**
   * Decodes GetKeySettings.
   * @param response clear response payload without the status byte
   * @return application or PICC key settings
   * @throws DfcException if the payload is malformed
   */
  public static KeySettings decodeKeySettings(byte[] response) throws DfcException {
    Objects.requireNonNull(response, "response");
    byte[] value = DfcNative.responseDecodeKeySettings(response);
    boolean sets = value[4] != 0;
    return new KeySettings(value[0] & 0xff, value[1] & 0xff, value[2] & 0xff, value[3] & 0xff,
        sets ? value[5] & 0xff : null, sets ? value[6] & 0xff : null, sets ? value[7] & 0xff : null,
        sets ? value[8] & 0xff : null);
  }

  /**
   * Decodes GetKeyVersion.
   * @param response clear response payload without the status byte
   * @return unsigned one-byte key version
   * @throws DfcException if the payload is malformed
   */
  public static int decodeKeyVersion(byte[] response) throws DfcException {
    Objects.requireNonNull(response, "response");
    return DfcNative.responseDecodeKeyVersion(response);
  }
}
