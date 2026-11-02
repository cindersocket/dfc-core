namespace Dfc.Reader;

using System;
using CSharpFunctionalExtensions;
using Dfc.Interop;

/// <summary>
/// One native DESFire command frame: the instruction and the data after it. The factories encode through the
/// native command encoder, which validates every field the way the card does; secure messaging is applied later,
/// by <see cref="DfcReader" />.
/// </summary>
public sealed record DfcCommand
{
    /// <summary>Largest data field one frame carries.</summary>
    public const int MaximumData = 255;

    /// <summary>Instruction of an additional frame.</summary>
    public const byte AdditionalFrame = 0xAF;

    /// <summary>Creates one native command frame.</summary>
    /// <exception cref="InvalidOperationException">The data field exceeds <see cref="MaximumData" />.</exception>
    public DfcCommand(byte instruction, ReadOnlyMemory<byte> data)
    {
        if (data.Length > MaximumData)
        {
            throw new InvalidOperationException(TooMuchDataMessage);
        }

        Instruction = instruction;
        Data = data;
    }

    /// <summary>The instruction octet.</summary>
    public byte Instruction { get; }

    /// <summary>The data field.</summary>
    public ReadOnlyMemory<byte> Data { get; }

    /// <summary>Deconstructs the command into its instruction and data.</summary>
    public void Deconstruct(out byte instruction, out ReadOnlyMemory<byte> data) =>
        (instruction, data) = (Instruction, Data);

    /// <summary>This command as an ISO 7816 envelope: 90 INS 00 00 [Lc data] 00.</summary>
    public byte[] ToApdu()
    {
        if (Data.Length == 0)
        {
            return [0x90, Instruction, 0x00, 0x00, 0x00];
        }

        var apdu = new byte[Data.Length + 6];
        apdu[0] = 0x90;
        apdu[1] = Instruction;
        apdu[4] = (byte)Data.Length;
        Data.Span.CopyTo(apdu.AsSpan(5));
        return apdu;
    }

    /// <summary>Any instruction with any data.</summary>
    public static Result<DfcCommand, DfcProtocolError> Raw(byte instruction, ReadOnlySpan<byte> data) =>
        data.Length <= MaximumData
            ? new DfcCommand(instruction, data.ToArray())
            : Invalid(TooMuchDataMessage);

    private static string TooMuchDataMessage =>
        $"A native frame carries at most {MaximumData} octets of data.";

    // --------------------------------------------------------- discovery ---

    /// <summary>
    /// SelectApplication. AIDs use the human-readable order stored by the credential model;
    /// this factory converts them to wire order.
    /// </summary>
    public static unsafe Result<DfcCommand, DfcProtocolError> SelectApplication(
        ReadOnlySpan<byte> aid,
        ReadOnlySpan<byte> secondaryAid = default
    )
    {
        if (aid.Length != 3 || (secondaryAid.Length != 0 && secondaryAid.Length != 3))
        {
            return Invalid("An AID is three octets.");
        }

        fixed (byte* a = aid)
        fixed (byte* b = secondaryAid)
        {
            var aa = a;
            var bb = secondaryAid.Length == 0 ? null : b;
            return Encode(c => Native.dfc_command_select_application(c, aa, bb));
        }
    }

    /// <summary>GetVersion.</summary>
    public static DfcCommand GetVersion() => new(0x60, ReadOnlyMemory<byte>.Empty);

    /// <summary>GetFreeMemory.</summary>
    public static DfcCommand GetFreeMemory() => new(0x6E, ReadOnlyMemory<byte>.Empty);

    /// <summary>FormatPICC.</summary>
    public static DfcCommand FormatPicc() => new(0xFC, ReadOnlyMemory<byte>.Empty);

    /// <summary>GetKeySettings.</summary>
    public static DfcCommand GetKeySettings() => new(0x45, ReadOnlyMemory<byte>.Empty);

    /// <summary>GetApplicationIDs.</summary>
    public static DfcCommand GetApplicationIds() => new(0x6A, ReadOnlyMemory<byte>.Empty);

    /// <summary>GetDFNames.</summary>
    public static DfcCommand GetDfNames() => new(0x6D, ReadOnlyMemory<byte>.Empty);

    /// <summary>GetFileIDs.</summary>
    public static DfcCommand GetFileIds() => new(0x6F, ReadOnlyMemory<byte>.Empty);

    /// <summary>GetISOFileIDs.</summary>
    public static DfcCommand GetIsoFileIds() => new(0x61, ReadOnlyMemory<byte>.Empty);

    /// <summary>GetCardUID.</summary>
    public static DfcCommand GetCardUid() => new(0x51, ReadOnlyMemory<byte>.Empty);

    /// <summary>ReadSignature.</summary>
    public static DfcCommand ReadSignature(byte signatureId = 0x00) => new(0x3C, new[] { signatureId });

    /// <summary>GetKeyVersion.</summary>
    public static DfcCommand GetKeyVersion(byte keyNo) => new(0x64, new[] { keyNo });

    /// <summary>GetFileSettings.</summary>
    public static DfcCommand GetFileSettings(byte fileNo) => OneFile(0xF5, fileNo);

    /// <summary>GetFileCounters.</summary>
    public static DfcCommand GetFileCounters(byte fileNo) => OneFile(0xF6, fileNo);

    /// <summary>DeleteFile.</summary>
    public static DfcCommand DeleteFile(byte fileNo) => OneFile(0xDF, fileNo);

    /// <summary>ClearRecordFile.</summary>
    public static DfcCommand ClearRecordFile(byte fileNo) => OneFile(0xEB, fileNo);

    /// <summary>CommitTransaction.</summary>
    public static DfcCommand CommitTransaction() => new(0xC7, ReadOnlyMemory<byte>.Empty);

    /// <summary>CommitTransaction carrying its option octet.</summary>
    public static DfcCommand CommitTransaction(byte option) => new(0xC7, new[] { option });

    /// <summary>AbortTransaction.</summary>
    public static DfcCommand AbortTransaction() => new(0xA7, ReadOnlyMemory<byte>.Empty);

    // --------------------------------------------------------------- data ---

    /// <summary>ReadData.</summary>
    public static unsafe Result<DfcCommand, DfcProtocolError> ReadData(
        byte fileNo,
        uint offset,
        uint length,
        bool isoChaining = false
    ) => Encode(c => isoChaining
        ? Native.dfc_command_read_data_iso_chaining(c, fileNo, offset, length)
        : Native.dfc_command_read_data(c, fileNo, offset, length));

    /// <summary>WriteData.</summary>
    public static unsafe Result<DfcCommand, DfcProtocolError> WriteData(
        byte fileNo,
        uint offset,
        ReadOnlySpan<byte> data,
        bool isoChaining = false
    )
    {
        fixed (byte* d = data)
        {
            var dd = d;
            var n = (nuint)data.Length;
            return Encode(c => isoChaining
                ? Native.dfc_command_write_data_iso_chaining(c, fileNo, offset, dd, n)
                : Native.dfc_command_write_data(c, fileNo, offset, dd, n));
        }
    }

    /// <summary>ReadRecords.</summary>
    public static unsafe Result<DfcCommand, DfcProtocolError> ReadRecords(
        byte fileNo,
        uint recordNo,
        uint recordCount,
        bool isoChaining = false
    ) => Encode(c => Native.dfc_command_read_records(c, fileNo, recordNo, recordCount, isoChaining));

    /// <summary>WriteRecord.</summary>
    public static unsafe Result<DfcCommand, DfcProtocolError> WriteRecord(
        byte fileNo,
        uint offset,
        ReadOnlySpan<byte> data,
        bool isoChaining = false
    )
    {
        fixed (byte* d = data)
        {
            var dd = d;
            var n = (nuint)data.Length;
            return Encode(c => Native.dfc_command_write_record(c, fileNo, offset, dd, n, isoChaining));
        }
    }

    /// <summary>UpdateRecord.</summary>
    public static unsafe Result<DfcCommand, DfcProtocolError> UpdateRecord(
        byte fileNo,
        uint recordNo,
        uint offset,
        ReadOnlySpan<byte> data,
        bool isoChaining = false
    )
    {
        fixed (byte* d = data)
        {
            var dd = d;
            var n = (nuint)data.Length;
            return Encode(c => Native.dfc_command_update_record(c, fileNo, recordNo, offset, dd, n, isoChaining));
        }
    }

    /// <summary>GetValue.</summary>
    public static DfcCommand GetValue(byte fileNo) => OneFile(0x6C, fileNo);

    /// <summary>Credit.</summary>
    public static unsafe Result<DfcCommand, DfcProtocolError> Credit(byte fileNo, int amount) =>
        Encode(c => Native.dfc_command_credit(c, fileNo, amount));

    /// <summary>Debit.</summary>
    public static unsafe Result<DfcCommand, DfcProtocolError> Debit(byte fileNo, int amount) =>
        Encode(c => Native.dfc_command_debit(c, fileNo, amount));

    /// <summary>LimitedCredit.</summary>
    public static unsafe Result<DfcCommand, DfcProtocolError> LimitedCredit(byte fileNo, int amount) =>
        Encode(c => Native.dfc_command_limited_credit(c, fileNo, amount));

    /// <summary>ChangeFileSettings; <paramref name="additional" /> follows the access rights, e.g. SDM settings.</summary>
    public static unsafe Result<DfcCommand, DfcProtocolError> ChangeFileSettings(
        byte fileNo,
        byte communicationSettings,
        ushort accessRights,
        ReadOnlySpan<byte> additional = default
    )
    {
        fixed (byte* a = additional)
        {
            var aa = a;
            var n = (nuint)additional.Length;
            return Encode(c => Native.dfc_command_change_file_settings(c, fileNo, communicationSettings, accessRights, aa, n));
        }
    }

    // ------------------------------------------------------------ helpers ---

    private unsafe delegate int Encoder(NativeCommand* command);

    private static unsafe Result<DfcCommand, DfcProtocolError> Encode(Encoder encode)
    {
        Native.EnsureCompatible();
        NativeCommand command;
        var st = encode(&command);
        if (st != 0)
        {
            return Invalid(st == 2 ? "The command does not fit one native frame." : "A command field is out of range.");
        }

        return new DfcCommand(command.Ins, new ReadOnlySpan<byte>(command.Data, (int)command.DataLen).ToArray());
    }

    private static DfcProtocolError Invalid(string message) => new(DfcProtocolErrorKind.Invalid, message);

    private static DfcCommand OneFile(byte instruction, byte fileNo)
    {
        ArgumentOutOfRangeException.ThrowIfGreaterThan(fileNo, (byte)31);
        return new DfcCommand(instruction, new[] { fileNo });
    }
}
