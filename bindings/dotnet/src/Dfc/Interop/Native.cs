namespace Dfc.Interop;

using System;
using System.Runtime.InteropServices;

// Every call into the native library. Pointer-based so the marshaller stays
// out of the way; the public types above this layer own the safety.
internal static unsafe partial class Native
{
    internal const string Library = "libdfc";
    internal const uint AbiVersion = (uint)DFC_FFI_ABI_VERSION;

    internal const int InvalidArgument = (int)DFC_FFI_INVALID_ARGUMENT;
    internal const int BufferTooSmall = (int)DFC_FFI_BUFFER_TOO_SMALL;
    internal const int OutOfMemory = (int)DFC_FFI_OUT_OF_MEMORY;
    internal const int Unsupported = (int)DFC_FFI_UNSUPPORTED;
    internal const int RandomFailed = (int)DFC_FFI_RANDOM_FAILED;
    internal const int PiccBufferTooSmall = (int)DFC_FFI_PICC_BUFFER_TOO_SMALL;
    internal const int OwnerPicc = (int)DFC_FFI_OWNER_PICC;
    internal const int ResponseOk = (int)DFC_FFI_RESPONSE_OK;
    internal const int TransactionMacOk = (int)DFC_FFI_TRANSACTION_MAC_OK;

    private static readonly Lazy<bool> Checked = new(CheckAbi);

    // Refuse to run against a library whose layouts differ from these
    // declarations, rather than corrupt memory quietly.
    internal static void EnsureCompatible()
    {
        _ = Checked.Value;
    }

    private static bool CheckAbi()
    {
        var version = dfc_ffi_abi_version();
        var fingerprint = dfc_ffi_layout_fingerprint();
        RequireCompatible(version, fingerprint);

        NativeStructSizes sizes;
        dfc_ffi_struct_sizes(&sizes);
        Require(sizes.Capabilities, sizeof(NativeCapabilities), "capabilities");
        Require(sizes.Error, sizeof(NativeError), "error");
        Require(sizes.Card, sizeof(NativeCard), "card");
        Require(sizes.Picc, sizeof(NativePicc), "PICC settings");
        Require(sizes.Application, sizeof(NativeApplication), "application");
        Require(sizes.File, sizeof(NativeFile), "file");
        Require(sizes.Key, sizeof(NativeKey), "key");
        Require(sizes.Activation, sizeof(NativeActivation), "activation");
        Require(sizes.Snapshot, sizeof(NativeSnapshot), "snapshot");
        Require(sizes.DiagnosticSnapshot, sizeof(NativeDiagnosticSnapshot), "diagnostic snapshot");
        Require(sizes.ReaderState, sizeof(NativeReaderState), "reader state");
        return true;
    }

    internal static void RequireCompatible(uint version, ulong fingerprint)
    {
        if (version != AbiVersion)
        {
            throw new InvalidOperationException(
                $"The native DFC library speaks interface version {version}; this assembly needs {AbiVersion}."
            );
        }
        var expected = ExpectedLayoutFingerprint();
        if (fingerprint != expected)
        {
            throw new InvalidOperationException(
                $"The native DFC layout fingerprint is 0x{fingerprint:x16}; this assembly expects 0x{expected:x16}."
            );
        }
    }

    private static void Require(uint native, int managed, string name)
    {
        if (native != managed)
        {
            throw new InvalidOperationException(
                $"The native DFC library lays out the {name} struct in {native} octets; this assembly expects {managed}."
            );
        }
    }

    // ------------------------------------------ reader protocol helpers ---

    [LibraryImport(Library)]
    [return: MarshalAs(UnmanagedType.U1)]
    internal static partial bool dfc_reader_proximity_check_mac(
        byte* key,
        [MarshalAs(UnmanagedType.U1)] bool fromCard,
        byte* published,
        nuint publishedLength,
        byte* transcript,
        nuint transcriptLength,
        byte* mac);

    [LibraryImport(Library)]
    internal static partial int dfc_reader_virtual_card_open(
        byte* selectEncryptionKey,
        byte* response,
        nuint responseLength,
        byte* challenge,
        byte* clearData);

    [LibraryImport(Library)]
    internal static partial int dfc_reader_virtual_card_authenticate_apdu(
        byte* selectMacKey,
        byte* challenge,
        byte* clearData,
        byte* output,
        nuint outputCapacity,
        nuint* outputLength);

    // ----------------------------------------------------- command encoder ---

    [LibraryImport(Library)]
    internal static partial int dfc_command_encode_raw(NativeCommand* command, byte ins, byte* data, nuint length);

    [LibraryImport(Library)]
    internal static partial int dfc_command_to_apdu(NativeCommand* command, byte* output, nuint capacity, nuint* length);

    [LibraryImport(Library)]
    internal static partial int dfc_command_select_application(NativeCommand* command, byte* aid, byte* secondaryAid);

    [LibraryImport(Library)]
    internal static partial int dfc_command_read_data(NativeCommand* command, byte fileNo, uint offset, uint length);

    [LibraryImport(Library)]
    internal static partial int dfc_command_read_data_iso_chaining(NativeCommand* command, byte fileNo, uint offset, uint length);

    [LibraryImport(Library)]
    internal static partial int dfc_command_write_data(NativeCommand* command, byte fileNo, uint offset, byte* data, nuint length);

    [LibraryImport(Library)]
    internal static partial int dfc_command_write_data_iso_chaining(NativeCommand* command, byte fileNo, uint offset, byte* data, nuint length);

    [LibraryImport(Library)]
    internal static partial int dfc_command_read_records(NativeCommand* command, byte fileNo, uint recordNo, uint recordCount, [MarshalAs(UnmanagedType.U1)] bool isoChaining);

    [LibraryImport(Library)]
    internal static partial int dfc_command_write_record(NativeCommand* command, byte fileNo, uint offset, byte* data, nuint length, [MarshalAs(UnmanagedType.U1)] bool isoChaining);

    [LibraryImport(Library)]
    internal static partial int dfc_command_update_record(NativeCommand* command, byte fileNo, uint recordNo, uint offset, byte* data, nuint length, [MarshalAs(UnmanagedType.U1)] bool isoChaining);

    [LibraryImport(Library)]
    internal static partial int dfc_command_credit(NativeCommand* command, byte fileNo, int amount);

    [LibraryImport(Library)]
    internal static partial int dfc_command_debit(NativeCommand* command, byte fileNo, int amount);

    [LibraryImport(Library)]
    internal static partial int dfc_command_limited_credit(NativeCommand* command, byte fileNo, int amount);

    [LibraryImport(Library)]
    internal static partial int dfc_command_change_file_settings(NativeCommand* command, byte fileNo, byte commSettings, ushort accessRights, byte* additional, nuint additionalLength);
}
