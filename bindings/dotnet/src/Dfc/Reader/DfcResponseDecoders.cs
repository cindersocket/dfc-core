namespace Dfc.Reader;

#pragma warning disable CS1591 // Compact response models are described by their property names.

using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using CSharpFunctionalExtensions;
using Dfc.Interop;

public enum DfcAccessKind { Key, Free, Denied }
public sealed record DfcAccess(DfcAccessKind Kind, int? KeyNumber);
public sealed record DfcAccessRights(DfcAccess Read, DfcAccess Write, DfcAccess ReadWrite, DfcAccess Change);
public sealed record DfcVersionPart(int VendorId, int Type, int Subtype, int MajorVersion,
    int MinorVersion, int StorageSize, int Protocol);
public sealed record DfcVersion(DfcVersionPart Hardware, DfcVersionPart Software, byte[] Uid,
    byte[] BatchNumber, int ProductionWeek, int ProductionYear);
public sealed record DfcFileSettings(int Type, int CommunicationMode, int AccessRightsRaw,
    DfcAccessRights Access, int? Size = null, int? LowerLimit = null, int? UpperLimit = null,
    int? LimitedCreditValue = null, bool? LimitedCreditEnabled = null, int? RecordSize = null,
    int? MaxRecords = null, int? CurrentRecords = null);
public sealed record DfcKeySettings(int Settings1, int Settings2, int KeyType, int KeyCount,
    int? ActiveKeySetVersion = null, int? KeySetCount = null, int? MaxKeySize = null,
    int? KeySetSettings = null);
#pragma warning restore CS1591

/// <summary>Typed decoding for clear command responses. Raw reader results remain available.</summary>
public static unsafe class DfcResponseDecoders
{
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

    private static DfcVersionPart Part(byte[] value, int offset) => new(value[offset], value[offset + 1],
        value[offset + 2], value[offset + 3], value[offset + 4], value[offset + 5], value[offset + 6]);

    /// <summary>Decodes an assembled GetVersion response.</summary>
    public static Result<DfcVersion, DfcError> DecodeVersion(ReadOnlySpan<byte> response) =>
        Fixed(response, 28, Native.dfc_ffi_response_decode_version).Map(value => new DfcVersion(
            Part(value, 0), Part(value, 7), value[14..21], value[21..26], value[26], value[27]));

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
    public static Result<IReadOnlyList<byte[]>, DfcError> DecodeApplicationIds(ReadOnlySpan<byte> response) =>
        List(response, Native.dfc_ffi_response_decode_application_ids).Map(value =>
        {
            var result = new List<byte[]>(value.Length / 3);
            for (var offset = 0; offset < value.Length; offset += 3)
                result.Add(value[offset..(offset + 3)]);
            return (IReadOnlyList<byte[]>)result;
        });

    /// <summary>Decodes a GetFileIDs response.</summary>
    public static Result<IReadOnlyList<byte>, DfcError> DecodeFileIds(ReadOnlySpan<byte> response) =>
        List(response, Native.dfc_ffi_response_decode_file_ids).Map(value => (IReadOnlyList<byte>)value);

    private static DfcAccess Access(byte[] value, int offset)
    {
        var kind = (DfcAccessKind)value[offset];
        return new(kind, kind == DfcAccessKind.Key ? value[offset + 1] : null);
    }

    /// <summary>Decodes file settings into their file-type-specific fields.</summary>
    public static Result<DfcFileSettings, DfcError> DecodeFileSettings(ReadOnlySpan<byte> response) =>
        Fixed(response, 32, Native.dfc_ffi_response_decode_file_settings).Map(value =>
        {
            var type = value[0];
            var rights = new DfcAccessRights(Access(value, 6), Access(value, 8), Access(value, 10), Access(value, 12));
            var raw = BinaryPrimitives.ReadUInt16LittleEndian(value.AsSpan(4));
            if (type is 0 or 1)
                return new DfcFileSettings(type, value[1], raw, rights,
                    Size: BinaryPrimitives.ReadInt32LittleEndian(value.AsSpan(14)));
            if (type == 2)
                return new DfcFileSettings(type, value[1], raw, rights,
                    LowerLimit: BinaryPrimitives.ReadInt32LittleEndian(value.AsSpan(14)),
                    UpperLimit: BinaryPrimitives.ReadInt32LittleEndian(value.AsSpan(18)),
                    LimitedCreditValue: BinaryPrimitives.ReadInt32LittleEndian(value.AsSpan(22)),
                    LimitedCreditEnabled: value[26] != 0);
            return new DfcFileSettings(type, value[1], raw, rights,
                RecordSize: BinaryPrimitives.ReadInt32LittleEndian(value.AsSpan(14)),
                MaxRecords: BinaryPrimitives.ReadInt32LittleEndian(value.AsSpan(18)),
                CurrentRecords: BinaryPrimitives.ReadInt32LittleEndian(value.AsSpan(22)));
        });

    /// <summary>Decodes application or PICC key settings.</summary>
    public static Result<DfcKeySettings, DfcError> DecodeKeySettings(ReadOnlySpan<byte> response) =>
        Fixed(response, 9, Native.dfc_ffi_response_decode_key_settings).Map(value =>
            value[4] == 0 ? new DfcKeySettings(value[0], value[1], value[2], value[3])
                : new DfcKeySettings(value[0], value[1], value[2], value[3], value[5], value[6], value[7], value[8]));

    /// <summary>Decodes a GetKeyVersion response.</summary>
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
