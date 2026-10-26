namespace Dfc.Sdm;

using System;
using System.Buffers.Binary;
using System.Security.Cryptography;
using CSharpFunctionalExtensions;
using Dfc.Interop;

/// <summary>Locates one ASCII-encoded SDM field within the complete message.</summary>
/// <param name="Offset">Zero-based byte offset into the ASCII message.</param>
/// <param name="Length">Field length in the units documented by the <see cref="DfcSdmConfig"/> property that uses this value.</param>
public sealed record DfcSdmField(int Offset, int Length);

/// <summary>Describes the SDM fields and MAC range present in an ASCII message.</summary>
/// <param name="MacInputOffset">First message byte authenticated by the SDM MAC.</param>
/// <param name="MacOffset">Offset of the encoded SDM MAC and exclusive end of its input range.</param>
/// <param name="PlainUid">Location of a plain UID, or <see langword="null"/> when absent. Its length is the decoded UID size, 7 or 10 bytes; the field occupies twice that many ASCII bytes.</param>
/// <param name="PlainReadCounterOffset">Offset of a plain three-byte read counter encoded as six ASCII bytes, or <see langword="null"/> when absent.</param>
/// <param name="EncryptedPiccData">Location of encrypted PICC data, or <see langword="null"/> when absent. Its length is the encoded ASCII byte count, 32 or 64.</param>
/// <param name="EncryptedFileData">Location of encrypted file data, or <see langword="null"/> when absent. Its length is the encoded ASCII byte count and must be a nonzero multiple of 32.</param>
public sealed record DfcSdmConfig(int MacInputOffset, int MacOffset, DfcSdmField? PlainUid = null,
    int? PlainReadCounterOffset = null, DfcSdmField? EncryptedPiccData = null,
    DfcSdmField? EncryptedFileData = null);

/// <summary>Contains fields published only after successful SDM authentication.</summary>
/// <param name="Uid">Verified UID, or <see langword="null"/> when the configured message does not carry one.</param>
/// <param name="ReadCounter">Verified SDM read counter, or <see langword="null"/> when absent.</param>
/// <param name="DecryptedFileData">Decrypted file data. The array is empty when no encrypted file field was configured.</param>
/// <remarks>The result owns its arrays; callers may retain or clear them independently.</remarks>
public sealed record DfcSdmResult(byte[]? Uid, int? ReadCounter, byte[] DecryptedFileData);

/// <summary>Authenticates ASCII SDM input before publishing mirrored fields.</summary>
public static unsafe class DfcSdmVerifier
{
    private const uint PlainUidField = 1u << 0;
    private const uint PlainReadCounterField = 1u << 1;
    private const uint EncryptedPiccDataField = 1u << 2;
    private const uint EncryptedFileDataField = 1u << 3;
    private const int PackedResultLength = 20;
    private const int HasUidOffset = 0;
    private const int UidLengthOffset = 1;
    private const int UidOffset = 2;
    private const int HasReadCounterOffset = 12;
    private const int ReadCounterOffset = 16;

    /// <summary>Authenticates one ASCII SDM message and returns only fields covered by the verified MAC.</summary>
    /// <param name="message">Complete ASCII message containing the configured mirrored fields.</param>
    /// <param name="config">Offsets and lengths of the fields and MAC input range.</param>
    /// <param name="fileReadKey">Sixteen-byte file read key used for MAC verification and file-data decryption.</param>
    /// <param name="metaReadKey">Sixteen-byte metadata read key required when encrypted PICC data is configured.</param>
    /// <returns>A verified result, or a native validation, authentication, or cryptographic error.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="config"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">A key has the wrong length or encrypted file data cannot fit in the message.</exception>
    /// <exception cref="ArgumentOutOfRangeException">A configured offset or length is negative.</exception>
    public static Result<DfcSdmResult, DfcError> Verify(ReadOnlySpan<byte> message,
        DfcSdmConfig config, ReadOnlySpan<byte> fileReadKey, ReadOnlySpan<byte> metaReadKey = default)
    {
        ArgumentNullException.ThrowIfNull(config);
        if (fileReadKey.Length != 16 || (!metaReadKey.IsEmpty && metaReadKey.Length != 16))
            throw new ArgumentException("SDM keys must be 16 bytes.");
        if (config.MacInputOffset < 0 || config.MacOffset < 0)
            throw new ArgumentOutOfRangeException(nameof(config));

        uint fields = 0;
        if (config.PlainUid is not null)
            fields |= PlainUidField;
        if (config.PlainReadCounterOffset is not null)
            fields |= PlainReadCounterField;
        if (config.EncryptedPiccData is not null)
            fields |= EncryptedPiccDataField;
        if (config.EncryptedFileData is not null)
            fields |= EncryptedFileDataField;
        var uid = config.PlainUid ?? new(0, 0);
        var picc = config.EncryptedPiccData ?? new(0, 0);
        var file = config.EncryptedFileData ?? new(0, 0);
        if (uid.Offset < 0 || uid.Length < 0 || picc.Offset < 0 || picc.Length < 0 ||
            file.Offset < 0 || file.Length < 0 || config.PlainReadCounterOffset < 0)
            throw new ArgumentOutOfRangeException(nameof(config));
        if (file.Length > message.Length)
            throw new ArgumentException("Encrypted file data cannot exceed the message.", nameof(config));

        var decrypted = new byte[file.Length / 2];
        Span<byte> packed = stackalloc byte[PackedResultLength];
        nuint required = 0;
        int status;
        fixed (byte* messageBytes = message)
        fixed (byte* fileKey = fileReadKey)
        fixed (byte* metaKey = metaReadKey)
        fixed (byte* clear = decrypted)
        fixed (byte* result = packed)
        {
            status = Native.dfc_ffi_sdm_verify_ascii(messageBytes, (nuint)message.Length, fields,
                (nuint)uid.Offset, (nuint)uid.Length, (nuint)(config.PlainReadCounterOffset ?? 0),
                (nuint)picc.Offset, (nuint)picc.Length, (nuint)file.Offset, (nuint)file.Length,
                (nuint)config.MacInputOffset, (nuint)config.MacOffset,
                metaReadKey.IsEmpty ? null : metaKey, fileKey, decrypted.Length == 0 ? null : clear,
                (nuint)decrypted.Length, &required, result, (nuint)packed.Length);
        }

        if (status != 0)
        {
            CryptographicOperations.ZeroMemory(decrypted);
            return DfcError.FromStatus(status, "SDM verification failed");
        }
        byte[]? uidResult = packed[HasUidOffset] == 0
            ? null
            : packed.Slice(UidOffset, packed[UidLengthOffset]).ToArray();
        int? counter = packed[HasReadCounterOffset] == 0
            ? null
            : BinaryPrimitives.ReadInt32LittleEndian(packed[ReadCounterOffset..]);
        return new DfcSdmResult(uidResult, counter, decrypted);
    }
}
