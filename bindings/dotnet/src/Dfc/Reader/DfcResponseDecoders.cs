namespace Dfc.Reader;

using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using CSharpFunctionalExtensions;
using Dfc.Credentials;
using Dfc.Interop;

/// <summary>Identifies how a file operation is authorized.</summary>
public enum DfcAccessKind
{
    /// <summary>The operation requires authentication with a specific key.</summary>
    Key,

    /// <summary>The operation is available without authentication.</summary>
    Free,

    /// <summary>The operation is disabled.</summary>
    Denied
}

/// <summary>Represents one decoded file access condition.</summary>
/// <param name="Kind">Authorization kind.</param>
/// <param name="KeyNumber">Required key number when <paramref name="Kind"/> is <see cref="DfcAccessKind.Key"/>; otherwise <see langword="null"/>.</param>
public sealed record DfcAccess(DfcAccessKind Kind, int? KeyNumber);

/// <summary>Contains the four decoded access conditions for a file.</summary>
/// <param name="Read">Condition for reading data or records.</param>
/// <param name="Write">Condition for writing data or records.</param>
/// <param name="ReadWrite">Combined read/write condition.</param>
/// <param name="Change">Condition for changing file settings.</param>
public sealed record DfcAccessRights(DfcAccess Read, DfcAccess Write, DfcAccess ReadWrite, DfcAccess Change);

/// <summary>Contains one seven-byte hardware or software part of a version response.</summary>
/// <param name="VendorId">Chip vendor identifier.</param>
/// <param name="Type">Product type identifier.</param>
/// <param name="Subtype">Product subtype identifier.</param>
/// <param name="MajorVersion">Major product version.</param>
/// <param name="MinorVersion">Minor product version.</param>
/// <param name="StorageSize">Encoded storage-size descriptor.</param>
/// <param name="Protocol">Supported protocol identifier.</param>
public sealed record DfcVersionPart(int VendorId, int Type, int Subtype, int MajorVersion,
    int MinorVersion, int StorageSize, int Protocol);

/// <summary>Contains a fully assembled and decoded version response.</summary>
/// <param name="Hardware">Hardware version fields.</param>
/// <param name="Software">Software version fields.</param>
/// <param name="Uid">Seven-byte card UID returned by the version command.</param>
/// <param name="BatchNumber">Five-byte manufacturing batch number.</param>
/// <param name="ProductionWeek">Encoded production week.</param>
/// <param name="ProductionYear">Encoded production year.</param>
/// <remarks>The result owns its UID and batch-number arrays.</remarks>
public sealed record DfcVersion(DfcVersionPart Hardware, DfcVersionPart Software, byte[] Uid,
    byte[] BatchNumber, int ProductionWeek, int ProductionYear);

/// <summary>Contains common and file-type-specific settings from a decoded file-settings response.</summary>
/// <param name="Type">Decoded file type.</param>
/// <param name="CommunicationMode">Decoded file communication mode.</param>
/// <param name="AccessRightsRaw">Unmodified 16-bit access-rights field.</param>
/// <param name="Access">Decoded access conditions.</param>
/// <param name="Size">Data-file size, or <see langword="null"/> for other file types.</param>
/// <param name="LowerLimit">Value-file lower limit, or <see langword="null"/> for other file types.</param>
/// <param name="UpperLimit">Value-file upper limit, or <see langword="null"/> for other file types.</param>
/// <param name="LimitedCreditValue">Value-file limited-credit amount, or <see langword="null"/> for other file types.</param>
/// <param name="LimitedCreditEnabled">Whether limited credit is enabled, or <see langword="null"/> for other file types.</param>
/// <param name="RecordSize">Record size in bytes, or <see langword="null"/> for non-record files.</param>
/// <param name="MaxRecords">Maximum record count, or <see langword="null"/> for non-record files.</param>
/// <param name="CurrentRecords">Current record count, or <see langword="null"/> for non-record files.</param>
public sealed record DfcFileSettings(DfcFileType Type, DfcCommunicationMode CommunicationMode, int AccessRightsRaw,
    DfcAccessRights Access, int? Size = null, int? LowerLimit = null, int? UpperLimit = null,
    int? LimitedCreditValue = null, bool? LimitedCreditEnabled = null, int? RecordSize = null,
    int? MaxRecords = null, int? CurrentRecords = null);

/// <summary>Contains decoded application or PICC key settings.</summary>
/// <param name="Settings1">First native key-settings byte.</param>
/// <param name="Settings2">Second native key-settings byte.</param>
/// <param name="KeyType">Decoded key-type value.</param>
/// <param name="KeyCount">Configured key count.</param>
/// <param name="ActiveKeySetVersion">Active key-set version when key sets are present.</param>
/// <param name="KeySetCount">Configured key-set count when present.</param>
/// <param name="MaxKeySize">Maximum key size when reported.</param>
/// <param name="KeySetSettings">Key-set settings byte when reported.</param>
public sealed record DfcKeySettings(int Settings1, int Settings2, int KeyType, int KeyCount,
    int? ActiveKeySetVersion = null, int? KeySetCount = null, int? MaxKeySize = null,
    int? KeySetSettings = null);

/// <summary>Typed decoding for clear command responses. Raw reader results remain available.</summary>
public static unsafe class DfcResponseDecoders
{
    private const int VersionPartLength = 7;
    private const int VersionResponseLength = 28;
    private const int HardwareVersionOffset = 0;
    private const int SoftwareVersionOffset = 7;
    private const int VersionUidOffset = 14;
    private const int VersionUidLength = 7;
    private const int BatchNumberOffset = 21;
    private const int BatchNumberLength = 5;
    private const int ProductionWeekOffset = 26;
    private const int ProductionYearOffset = 27;

    private const int FileSettingsResultLength = 32;
    private const int FileTypeOffset = 0;
    private const int CommunicationModeOffset = 1;
    private const int AccessRightsOffset = 4;
    private const int ReadAccessOffset = 6;
    private const int WriteAccessOffset = 8;
    private const int ReadWriteAccessOffset = 10;
    private const int ChangeAccessOffset = 12;
    private const int FileTypeSpecificOffset = 14;
    private const int KeySettingsResultLength = 9;
    private const int Settings1Offset = 0;
    private const int Settings2Offset = 1;
    private const int KeyTypeOffset = 2;
    private const int KeyCountOffset = 3;
    private const int HasKeySetSettingsOffset = 4;
    private const int ActiveKeySetVersionOffset = 5;
    private const int KeySetCountOffset = 6;
    private const int MaximumKeySizeOffset = 7;
    private const int KeySetSettingsOffset = 8;

    private delegate int FixedDecoder(byte* input, nuint length, byte* output, nuint capacity);

    private static Result<byte[], DfcError> Fixed(ReadOnlySpan<byte> response, int size, FixedDecoder decode)
    {
        Native.EnsureCompatible();
        var output = new byte[size];
        int status;
        fixed (byte* input = response)
        fixed (byte* result = output)
        {
            status = decode(input, (nuint)response.Length, result, (nuint)output.Length);
        }
        return status == Native.ResponseOk ? output : DfcError.FromStatus(status, "response decode failed");
    }

    private static DfcVersionPart Part(byte[] value, int offset)
    {
        var part = value.AsSpan(offset, VersionPartLength);
        return new(part[0], part[1], part[2], part[3], part[4], part[5], part[6]);
    }

    /// <summary>Decodes an assembled GetVersion response.</summary>
    /// <param name="response">Clear response data without trailing native or ISO status bytes.</param>
    /// <returns>The decoded hardware, software, UID, batch, and production fields, or a decode error.</returns>
    public static Result<DfcVersion, DfcError> DecodeVersion(ReadOnlySpan<byte> response) =>
        Fixed(response, VersionResponseLength, Native.dfc_ffi_response_decode_version).Map(value => new DfcVersion(
            Part(value, HardwareVersionOffset),
            Part(value, SoftwareVersionOffset),
            value[VersionUidOffset..(VersionUidOffset + VersionUidLength)],
            value[BatchNumberOffset..(BatchNumberOffset + BatchNumberLength)],
            value[ProductionWeekOffset],
            value[ProductionYearOffset]));

    private delegate int ListDecoder(byte* input, nuint length, byte* output, nuint capacity, nuint* outputLength);

    private static Result<byte[], DfcError> List(ReadOnlySpan<byte> response, ListDecoder decode)
    {
        Native.EnsureCompatible();
        var output = new byte[response.Length];
        nuint length = 0;
        int status;
        fixed (byte* input = response)
        fixed (byte* result = output)
        {
            status = decode(input, (nuint)response.Length, result, (nuint)output.Length, &length);
        }
        return status == Native.ResponseOk ? output[..(int)length] : DfcError.FromStatus(status, "response decode failed");
    }

    /// <summary>Decodes a GetApplicationIDs response in human-readable AID order.</summary>
    /// <param name="response">Clear response data without trailing native or ISO status bytes.</param>
    /// <returns>New three-byte application-identifier arrays in human-readable byte order, or a decode error.</returns>
    public static Result<IReadOnlyList<byte[]>, DfcError> DecodeApplicationIds(ReadOnlySpan<byte> response) =>
        List(response, Native.dfc_ffi_response_decode_application_ids).Map(value =>
        {
            var result = new List<byte[]>(value.Length / 3);
            for (var offset = 0; offset < value.Length; offset += 3)
                result.Add(value[offset..(offset + 3)]);
            return (IReadOnlyList<byte[]>)result;
        });

    /// <summary>Decodes a GetFileIDs response.</summary>
    /// <param name="response">Clear response data without trailing native or ISO status bytes.</param>
    /// <returns>A newly allocated list of file identifiers, or a decode error.</returns>
    public static Result<IReadOnlyList<byte>, DfcError> DecodeFileIds(ReadOnlySpan<byte> response) =>
        List(response, Native.dfc_ffi_response_decode_file_ids).Map(value => (IReadOnlyList<byte>)value);

    private static DfcAccess Access(byte[] value, int offset)
    {
        var kind = (DfcAccessKind)value[offset];
        return new(kind, kind == DfcAccessKind.Key ? value[offset + 1] : null);
    }

    /// <summary>Decodes file settings into their file-type-specific fields.</summary>
    /// <param name="response">Clear response data without trailing native or ISO status bytes.</param>
    /// <returns>The common settings and fields applicable to the decoded file type, or a decode error.</returns>
    public static Result<DfcFileSettings, DfcError> DecodeFileSettings(ReadOnlySpan<byte> response) =>
        Fixed(response, FileSettingsResultLength, Native.dfc_ffi_response_decode_file_settings).Map(value =>
        {
            var type = (DfcFileType)value[FileTypeOffset];
            var communicationMode = (DfcCommunicationMode)value[CommunicationModeOffset];
            var rights = new DfcAccessRights(
                Access(value, ReadAccessOffset),
                Access(value, WriteAccessOffset),
                Access(value, ReadWriteAccessOffset),
                Access(value, ChangeAccessOffset));
            var raw = BinaryPrimitives.ReadUInt16LittleEndian(value.AsSpan(AccessRightsOffset));
            if (type is DfcFileType.StandardData or DfcFileType.BackupData)
                return new DfcFileSettings(type, communicationMode, raw, rights,
                    Size: BinaryPrimitives.ReadInt32LittleEndian(value.AsSpan(FileTypeSpecificOffset)));
            if (type == DfcFileType.Value)
                return new DfcFileSettings(type, communicationMode, raw, rights,
                    LowerLimit: BinaryPrimitives.ReadInt32LittleEndian(value.AsSpan(FileTypeSpecificOffset)),
                    UpperLimit: BinaryPrimitives.ReadInt32LittleEndian(value.AsSpan(FileTypeSpecificOffset + 4)),
                    LimitedCreditValue: BinaryPrimitives.ReadInt32LittleEndian(value.AsSpan(FileTypeSpecificOffset + 8)),
                    LimitedCreditEnabled: value[FileTypeSpecificOffset + 12] != 0);
            return new DfcFileSettings(type, communicationMode, raw, rights,
                RecordSize: BinaryPrimitives.ReadInt32LittleEndian(value.AsSpan(FileTypeSpecificOffset)),
                MaxRecords: BinaryPrimitives.ReadInt32LittleEndian(value.AsSpan(FileTypeSpecificOffset + 4)),
                CurrentRecords: BinaryPrimitives.ReadInt32LittleEndian(value.AsSpan(FileTypeSpecificOffset + 8)));
        });

    /// <summary>Decodes application or PICC key settings.</summary>
    /// <param name="response">Clear response data without trailing native or ISO status bytes.</param>
    /// <returns>The base key settings and optional key-set fields, or a decode error.</returns>
    public static Result<DfcKeySettings, DfcError> DecodeKeySettings(ReadOnlySpan<byte> response) =>
        Fixed(response, KeySettingsResultLength, Native.dfc_ffi_response_decode_key_settings).Map(value =>
            value[HasKeySetSettingsOffset] == 0
                ? new DfcKeySettings(
                    value[Settings1Offset], value[Settings2Offset], value[KeyTypeOffset], value[KeyCountOffset])
                : new DfcKeySettings(
                    value[Settings1Offset],
                    value[Settings2Offset],
                    value[KeyTypeOffset],
                    value[KeyCountOffset],
                    value[ActiveKeySetVersionOffset],
                    value[KeySetCountOffset],
                    value[MaximumKeySizeOffset],
                    value[KeySetSettingsOffset]));

    /// <summary>Decodes a GetKeyVersion response.</summary>
    /// <param name="response">Clear response data without trailing native or ISO status bytes.</param>
    /// <returns>The key version byte, or a decode error.</returns>
    public static Result<byte, DfcError> DecodeKeyVersion(ReadOnlySpan<byte> response)
    {
        Native.EnsureCompatible();
        byte output = 0;
        int status;
        fixed (byte* input = response)
        {
            status = Native.dfc_ffi_response_decode_key_version(input, (nuint)response.Length, &output);
        }
        return status == Native.ResponseOk ? output : DfcError.FromStatus(status, "response decode failed");
    }
}
