package com.cindersocket.dfc;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.Objects;

/** Verification of authenticated ASCII Secure Dynamic Messaging responses. */
public final class DfcSdm {
  public record Field(int offset, int length) {
    public Field {
      if (offset < 0 || length < 0)
        throw new IllegalArgumentException("negative field range");
    }
  }
  public record Config(int macInputOffset, int macOffset, Field plainUid,
      Integer plainReadCounterOffset, Field encryptedPiccData, Field encryptedFileData) {
    public Config {
      if (macInputOffset < 0 || macOffset < 0)
        throw new IllegalArgumentException("negative MAC offset");
    }
  }
  public record Result(byte[] uid, Integer readCounter, byte[] decryptedFileData) {
    public Result {
      uid = uid == null ? null : uid.clone();
      decryptedFileData = decryptedFileData.clone();
    }
    @Override
    public byte[] uid() {
      return uid == null ? null : uid.clone();
    }
    @Override
    public byte[] decryptedFileData() {
      return decryptedFileData.clone();
    }
  }

  private DfcSdm() {}

  public static Result verify(byte[] message, Config config, byte[] fileReadKey, byte[] metaReadKey)
      throws DfcException {
    Objects.requireNonNull(message, "message");
    Objects.requireNonNull(config, "config");
    Objects.requireNonNull(fileReadKey, "fileReadKey");
    if (fileReadKey.length != 16 || (metaReadKey != null && metaReadKey.length != 16))
      throw new IllegalArgumentException("SDM keys must be 16 bytes");
    int fields = 0;
    if (config.plainUid() != null)
      fields |= 1;
    if (config.plainReadCounterOffset() != null)
      fields |= 2;
    if (config.encryptedPiccData() != null)
      fields |= 4;
    if (config.encryptedFileData() != null)
      fields |= 8;
    Field uid = config.plainUid() == null ? new Field(0, 0) : config.plainUid();
    Field picc = config.encryptedPiccData() == null ? new Field(0, 0) : config.encryptedPiccData();
    Field file = config.encryptedFileData() == null ? new Field(0, 0) : config.encryptedFileData();
    byte[] packed = DfcNative.sdmVerify(message, fields, uid.offset(), uid.length(),
        config.plainReadCounterOffset() == null ? 0 : config.plainReadCounterOffset(),
        picc.offset(), picc.length(), file.offset(), file.length(), config.macInputOffset(),
        config.macOffset(), metaReadKey, fileReadKey);
    byte[] resultUid =
        packed[0] == 0 ? null : Arrays.copyOfRange(packed, 2, 2 + (packed[1] & 0xff));
    Integer counter = packed[12] == 0
        ? null
        : ByteBuffer.wrap(packed, 16, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
    return new Result(resultUid, counter, Arrays.copyOfRange(packed, 20, packed.length));
  }
}
