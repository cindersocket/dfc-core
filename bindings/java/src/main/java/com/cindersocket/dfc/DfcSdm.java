package com.cindersocket.dfc;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.Objects;

/** Verification of authenticated ASCII Secure Dynamic Messaging responses. */
public final class DfcSdm {
  private static final int FIELD_PLAIN_UID = 1;
  private static final int FIELD_PLAIN_READ_COUNTER = 1 << 1;
  private static final int FIELD_ENCRYPTED_PICC_DATA = 1 << 2;
  private static final int FIELD_ENCRYPTED_FILE_DATA = 1 << 3;

  /**
   * Byte range in the ASCII message.
   * @param offset zero-based byte offset
   * @param length byte length
   */
  public record Field(int offset, int length) {
    /**
     * Validates a non-negative range.
     * @param offset zero-based byte offset
     * @param length byte length
     * @throws IllegalArgumentException if either value is negative
     */
    public Field {
      if (offset < 0 || length < 0)
        throw new IllegalArgumentException("negative field range");
    }
  }
  /**
   * Locations of authenticated and mirrored fields in an ASCII message.
   * @param macInputOffset first byte covered by the MAC
   * @param macOffset first ASCII byte of the transmitted MAC
   * @param plainUid clear UID range, or null
   * @param plainReadCounterOffset clear counter offset, or null
   * @param encryptedPiccData encrypted PICC-data range, or null
   * @param encryptedFileData encrypted file-data range, or null
   */
  public record Config(int macInputOffset, int macOffset, Field plainUid,
      Integer plainReadCounterOffset, Field encryptedPiccData, Field encryptedFileData) {
    /**
     * Validates mandatory offsets.
     * @param macInputOffset first byte covered by the MAC
     * @param macOffset first ASCII byte of the transmitted MAC
     * @param plainUid clear UID range, or null
     * @param plainReadCounterOffset clear counter offset, or null
     * @param encryptedPiccData encrypted PICC-data range, or null
     * @param encryptedFileData encrypted file-data range, or null
     * @throws IllegalArgumentException if either mandatory MAC offset is negative
     */
    public Config {
      if (macInputOffset < 0 || macOffset < 0)
        throw new IllegalArgumentException("negative MAC offset");
    }
  }
  /**
   * Authenticated SDM fields.
   * @param uid verified UID, or null when not requested
   * @param readCounter verified read counter, or null when not requested
   * @param decryptedFileData decrypted file data, possibly empty
   */
  public record Result(byte[] uid, Integer readCounter, byte[] decryptedFileData) {
    /**
     * Defensively copies mutable output fields.
     * @param uid verified UID, or null when not requested
     * @param readCounter verified read counter, or null when not requested
     * @param decryptedFileData decrypted file data, possibly empty
     */
    public Result {
      uid = uid == null ? null : uid.clone();
      decryptedFileData = decryptedFileData.clone();
    }
    /**
     * Returns the verified UID.
     * @return a defensive copy, or null
     */
    @Override
    public byte[] uid() {
      return uid == null ? null : uid.clone();
    }
    /**
     * Returns decrypted file data.
     * @return a defensive copy
     */
    @Override
    public byte[] decryptedFileData() {
      return decryptedFileData.clone();
    }
  }

  private DfcSdm() {}

  /**
   * Authenticates one ASCII SDM message before publishing mirrored fields.
   * @param message complete ASCII message
   * @param config byte ranges within {@code message}
   * @param fileReadKey 16-byte file-read key
   * @param metaReadKey optional 16-byte metadata-read key
   * @return verified and decrypted fields
   * @throws DfcException if authentication, decoding, or range validation fails
   * @throws IllegalArgumentException if either supplied key has a length other than 16 bytes
   * @throws NullPointerException if {@code message}, {@code config}, or {@code fileReadKey} is null
   */
  public static Result verify(byte[] message, Config config, byte[] fileReadKey, byte[] metaReadKey)
      throws DfcException {
    Objects.requireNonNull(message, "message");
    Objects.requireNonNull(config, "config");
    Objects.requireNonNull(fileReadKey, "fileReadKey");
    if (fileReadKey.length != 16 || (metaReadKey != null && metaReadKey.length != 16))
      throw new IllegalArgumentException("SDM keys must be 16 bytes");
    int fields = 0;
    if (config.plainUid() != null)
      fields |= FIELD_PLAIN_UID;
    if (config.plainReadCounterOffset() != null)
      fields |= FIELD_PLAIN_READ_COUNTER;
    if (config.encryptedPiccData() != null)
      fields |= FIELD_ENCRYPTED_PICC_DATA;
    if (config.encryptedFileData() != null)
      fields |= FIELD_ENCRYPTED_FILE_DATA;
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
