package com.cindersocket.dfc;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/** Typed decoders for clear DESFire response payloads. */
public final class DfcResponses {
  public enum AccessKind { KEY, FREE, DENIED }
  public record Access(AccessKind kind, Integer keyNumber) {}
  public record AccessRights(Access read, Access write, Access readWrite, Access change) {}
  public record VersionPart(int vendorId, int type, int subtype, int majorVersion, int minorVersion,
      int storageSize, int protocol) {}
  public record Version(VersionPart hardware, VersionPart software, byte[] uid, byte[] batchNumber,
      int productionWeek, int productionYear) {
    public Version {
      uid = uid.clone();
      batchNumber = batchNumber.clone();
    }
    @Override
    public byte[] uid() {
      return uid.clone();
    }
    @Override
    public byte[] batchNumber() {
      return batchNumber.clone();
    }
  }
  public record FileSettings(int type, int communicationMode, int accessRightsRaw,
      AccessRights access, Integer size, Integer lowerLimit, Integer upperLimit,
      Integer limitedCreditValue, Boolean limitedCreditEnabled, Integer recordSize,
      Integer maxRecords, Integer currentRecords) {}
  public record KeySettings(int settings1, int settings2, int keyType, int keyCount,
      Integer activeKeySetVersion, Integer keySetCount, Integer maxKeySize,
      Integer keySetSettings) {}

  private DfcResponses() {}

  private static VersionPart part(byte[] value, int offset) {
    return new VersionPart(value[offset] & 0xff, value[offset + 1] & 0xff, value[offset + 2] & 0xff,
        value[offset + 3] & 0xff, value[offset + 4] & 0xff, value[offset + 5] & 0xff,
        value[offset + 6] & 0xff);
  }

  public static Version decodeVersion(byte[] response) throws DfcException {
    Objects.requireNonNull(response, "response");
    byte[] value = DfcNative.responseDecodeVersion(response);
    return new Version(part(value, 0), part(value, 7), java.util.Arrays.copyOfRange(value, 14, 21),
        java.util.Arrays.copyOfRange(value, 21, 26), value[26] & 0xff, value[27] & 0xff);
  }

  public static List<byte[]> decodeApplicationIds(byte[] response) throws DfcException {
    Objects.requireNonNull(response, "response");
    byte[] value = DfcNative.responseDecodeApplicationIds(response);
    List<byte[]> result = new ArrayList<>(value.length / 3);
    for (int offset = 0; offset < value.length; offset += 3)
      result.add(java.util.Arrays.copyOfRange(value, offset, offset + 3));
    return List.copyOf(result);
  }

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

  public static FileSettings decodeFileSettings(byte[] response) throws DfcException {
    Objects.requireNonNull(response, "response");
    byte[] value = DfcNative.responseDecodeFileSettings(response);
    ByteBuffer little = ByteBuffer.wrap(value).order(ByteOrder.LITTLE_ENDIAN);
    int type = value[0] & 0xff;
    AccessRights rights =
        new AccessRights(access(value, 6), access(value, 8), access(value, 10), access(value, 12));
    if (type == 0 || type == 1)
      return new FileSettings(type, value[1] & 0xff, little.getShort(4) & 0xffff, rights,
          little.getInt(14), null, null, null, null, null, null, null);
    if (type == 2)
      return new FileSettings(type, value[1] & 0xff, little.getShort(4) & 0xffff, rights, null,
          little.getInt(14), little.getInt(18), little.getInt(22), value[26] != 0, null, null,
          null);
    return new FileSettings(type, value[1] & 0xff, little.getShort(4) & 0xffff, rights, null, null,
        null, null, null, little.getInt(14), little.getInt(18), little.getInt(22));
  }

  public static KeySettings decodeKeySettings(byte[] response) throws DfcException {
    Objects.requireNonNull(response, "response");
    byte[] value = DfcNative.responseDecodeKeySettings(response);
    boolean sets = value[4] != 0;
    return new KeySettings(value[0] & 0xff, value[1] & 0xff, value[2] & 0xff, value[3] & 0xff,
        sets ? value[5] & 0xff : null, sets ? value[6] & 0xff : null, sets ? value[7] & 0xff : null,
        sets ? value[8] & 0xff : null);
  }

  public static int decodeKeyVersion(byte[] response) throws DfcException {
    Objects.requireNonNull(response, "response");
    return DfcNative.responseDecodeKeyVersion(response);
  }
}
