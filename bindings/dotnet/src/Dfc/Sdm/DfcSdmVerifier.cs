namespace Dfc.Sdm;

#pragma warning disable CS1591 // Compact SDM models are described by their property names.

using System;
using System.Buffers.Binary;
using System.Security.Cryptography;
using CSharpFunctionalExtensions;
using Dfc.Interop;

public sealed record DfcSdmField(int Offset, int Length);
public sealed record DfcSdmConfig(int MacInputOffset, int MacOffset, DfcSdmField? PlainUid = null,
    int? PlainReadCounterOffset = null, DfcSdmField? EncryptedPiccData = null,
    DfcSdmField? EncryptedFileData = null);
public sealed record DfcSdmResult(byte[]? Uid, int? ReadCounter, byte[] DecryptedFileData);
#pragma warning restore CS1591

/// <summary>Authenticates ASCII SDM input before publishing mirrored fields.</summary>
public static unsafe class DfcSdmVerifier
{
    /// <summary>Authenticates one ASCII SDM message and returns verified fields.</summary>
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
            fields |= 1;
        if (config.PlainReadCounterOffset is not null)
            fields |= 2;
        if (config.EncryptedPiccData is not null)
            fields |= 4;
        if (config.EncryptedFileData is not null)
            fields |= 8;
        var uid = config.PlainUid ?? new(0, 0);
        var picc = config.EncryptedPiccData ?? new(0, 0);
        var file = config.EncryptedFileData ?? new(0, 0);
        if (uid.Offset < 0 || uid.Length < 0 || picc.Offset < 0 || picc.Length < 0 ||
            file.Offset < 0 || file.Length < 0 || config.PlainReadCounterOffset < 0)
            throw new ArgumentOutOfRangeException(nameof(config));
        if (file.Length > message.Length)
            throw new ArgumentException("Encrypted file data cannot exceed the message.", nameof(config));

        var decrypted = new byte[file.Length / 2];
        Span<byte> packed = stackalloc byte[20];
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
        byte[]? uidResult = packed[0] == 0 ? null : packed.Slice(2, packed[1]).ToArray();
        int? counter = packed[12] == 0 ? null : BinaryPrimitives.ReadInt32LittleEndian(packed[16..20]);
        return new DfcSdmResult(uidResult, counter, decrypted);
    }
}
