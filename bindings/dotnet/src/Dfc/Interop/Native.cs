namespace Dfc.Interop;

using System;
using System.Runtime.InteropServices;

// Every call into the native library. Pointer-based so the marshaller stays
// out of the way; the public types above this layer own the safety.
internal static unsafe partial class Native
{
    internal const string Library = "dfc";
    internal const uint AbiVersion = 1;

    internal const int InvalidArgument = -1;
    internal const int BufferTooSmall = -2;
    internal const int OutOfMemory = -3;
    internal const int Unsupported = -4;
    internal const int OwnerPicc = -1;

    private static readonly Lazy<bool> Checked = new(CheckAbi);

    // Refuse to run against a library whose layouts differ from these
    // declarations, rather than corrupt memory quietly.
    internal static void EnsureCompatible()
    {
        _ = Checked.Value;
    }

    private static bool CheckAbi()
    {
        uint version = dfc_ffi_abi_version();
        if (version != AbiVersion)
        {
            throw new InvalidOperationException(
                $"The native DFC library speaks interface version {version}; this assembly needs {AbiVersion}."
            );
        }

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
        Require(sizes.ReaderState, sizeof(NativeReaderState), "reader state");
        return true;
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

    // ------------------------------------------------------------ library ---

    [LibraryImport(Library)]
    internal static partial uint dfc_ffi_abi_version();

    [LibraryImport(Library)]
    internal static partial void dfc_ffi_capabilities(NativeCapabilities* output);

    [LibraryImport(Library)]
    internal static partial void dfc_ffi_struct_sizes(NativeStructSizes* output);

    // --------------------------------------------------------- credential ---

    [LibraryImport(Library)]
    internal static partial int dfc_ffi_credential_parse_text(byte* text, nuint length, nint* output, NativeError* error);

    [LibraryImport(Library)]
    internal static partial int dfc_ffi_credential_decode(byte* dfcb, nuint length, nint* output, NativeError* error);

    [LibraryImport(Library)]
    internal static partial int dfc_ffi_credential_load(byte* content, nuint length, nint* output, NativeError* error);

    [LibraryImport(Library)]
    internal static partial int dfc_ffi_credential_encode(nint credential, byte* output, nuint capacity, nuint* length);

    [LibraryImport(Library)]
    internal static partial int dfc_ffi_credential_write_text(nint credential, byte* output, nuint capacity, nuint* length);

    [LibraryImport(Library)]
    internal static partial int dfc_ffi_credential_validate(nint credential);

    [LibraryImport(Library)]
    internal static partial void dfc_ffi_credential_free(nint credential);

    [LibraryImport(Library)]
    internal static partial int dfc_ffi_credential_get_card(nint credential, NativeCard* output);

    [LibraryImport(Library)]
    internal static partial int dfc_ffi_credential_get_picc(nint credential, NativePicc* output);

    [LibraryImport(Library)]
    internal static partial uint dfc_ffi_credential_application_count(nint credential);

    [LibraryImport(Library)]
    internal static partial int dfc_ffi_credential_get_application(nint credential, uint index, NativeApplication* output);

    [LibraryImport(Library)]
    internal static partial uint dfc_ffi_credential_file_count(nint credential);

    [LibraryImport(Library)]
    internal static partial int dfc_ffi_credential_get_file(nint credential, uint index, NativeFile* output);

    [LibraryImport(Library)]
    internal static partial int dfc_ffi_credential_get_file_data(nint credential, uint index, byte* output, nuint capacity, nuint* length);

    [LibraryImport(Library)]
    internal static partial int dfc_ffi_credential_get_key(nint credential, int owner, uint keySet, uint slot, NativeKey* output);

    [LibraryImport(Library)]
    internal static partial int dfc_ffi_credential_new(nint* output);

    [LibraryImport(Library)]
    internal static partial int dfc_ffi_credential_set_card(nint credential, NativeCard* card);

    [LibraryImport(Library)]
    internal static partial int dfc_ffi_credential_set_picc(nint credential, NativePicc* picc);

    [LibraryImport(Library)]
    internal static partial int dfc_ffi_credential_add_application(nint credential, NativeApplication* application, uint* index);

    [LibraryImport(Library)]
    internal static partial int dfc_ffi_credential_add_file(nint credential, NativeFile* file, uint* index);

    [LibraryImport(Library)]
    internal static partial int dfc_ffi_credential_set_file_data(nint credential, uint index, byte* data, nuint length);

    [LibraryImport(Library)]
    internal static partial int dfc_ffi_credential_set_key(nint credential, int owner, uint keySet, uint slot, NativeKey* key);

    [LibraryImport(Library)]
    internal static partial int dfc_ffi_credential_finish(nint credential, NativeError* error);

    // ------------------------------------------------------- virtual PICC ---

    [LibraryImport(Library)]
    internal static partial int dfc_ffi_picc_create(
        nint credential,
        delegate* unmanaged<nint, byte*, nuint, void> random,
        nint context,
        nint* output);

    [LibraryImport(Library)]
    internal static partial void dfc_ffi_picc_free(nint picc);

    [LibraryImport(Library)]
    internal static partial int dfc_ffi_picc_activate(nint picc, NativeActivation* output);

    [LibraryImport(Library)]
    internal static partial int dfc_ffi_picc_exchange(nint picc, byte* command, nuint commandLength, byte* response, nuint responseCapacity, nuint* responseLength);

    [LibraryImport(Library)]
    internal static partial int dfc_ffi_picc_frame_exchange(nint picc, byte* frame, nuint frameLength, byte* response, nuint responseCapacity, nuint* responseLength);

    [LibraryImport(Library)]
    internal static partial int dfc_ffi_picc_field_off(nint picc);

    [LibraryImport(Library)]
    internal static partial int dfc_ffi_picc_reset_protocol(nint picc);

    [LibraryImport(Library)]
    internal static partial int dfc_ffi_picc_advance_time(nint picc, uint elapsedMilliseconds);

    [LibraryImport(Library)]
    internal static partial int dfc_ffi_picc_snapshot(nint picc, NativeSnapshot* output);

    [LibraryImport(Library)]
    internal static partial int dfc_ffi_picc_export(nint picc, nint* output);

    [LibraryImport(Library)]
    internal static partial int dfc_ffi_picc_mark_persisted(nint picc);

    // ------------------------------------------------------------- reader ---

    [LibraryImport(Library)]
    internal static partial int dfc_ffi_reader_session_new(nint* output);

    [LibraryImport(Library)]
    internal static partial void dfc_ffi_reader_session_free(nint session);

    [LibraryImport(Library)]
    internal static partial void dfc_ffi_reader_session_clear(nint session);

    [LibraryImport(Library)]
    internal static partial int dfc_ffi_reader_session_state(nint session, NativeReaderState* output);

    [LibraryImport(Library)]
    internal static partial int dfc_ffi_reader_exchange_new(nint* output);

    [LibraryImport(Library)]
    internal static partial void dfc_ffi_reader_exchange_free(nint exchange);

    [LibraryImport(Library)]
    internal static partial int dfc_ffi_reader_authenticate_begin(
        nint exchange,
        nint session,
        uint framing,
        byte cipher,
        byte keyNo,
        byte* key,
        nuint keyLength,
        byte* randomA,
        nuint randomALength);

    [LibraryImport(Library)]
    internal static partial int dfc_ffi_reader_authenticate_ev2_begin(
        nint exchange,
        nint session,
        uint framing,
        byte first,
        byte keyNo,
        byte* key,
        byte* randomA,
        byte* capabilities,
        nuint capabilitiesLength);

    [LibraryImport(Library)]
    internal static partial int dfc_ffi_reader_exchange_begin(
        nint exchange,
        nint session,
        uint framing,
        byte ins,
        byte* data,
        nuint dataLength,
        byte commMode,
        int headerLength);

    [LibraryImport(Library)]
    internal static partial int dfc_ffi_reader_write_data_begin(
        nint exchange, nint session, uint framing, byte fileNumber, uint offset,
        byte* data, nuint dataLength, byte commMode);

    [LibraryImport(Library)]
    internal static partial int dfc_ffi_reader_write_record_begin(
        nint exchange, nint session, uint framing, byte fileNumber, uint offset,
        byte* data, nuint dataLength, byte commMode);

    [LibraryImport(Library)]
    internal static partial int dfc_ffi_reader_update_record_begin(
        nint exchange, nint session, uint framing, byte fileNumber, uint recordNumber,
        uint offset, byte* data, nuint dataLength, byte commMode);

    [LibraryImport(Library)]
    internal static partial int dfc_ffi_reader_create_delegated_application_begin(
        nint exchange,
        nint session,
        uint framing,
        byte* header,
        nuint headerLength,
        byte* damEncryptionKey,
        byte* damMacKey,
        byte* randomPrefix,
        byte* initialKey,
        nuint initialKeyLength,
        byte initialVersion);

    [LibraryImport(Library)]
    internal static partial int dfc_ffi_reader_step(
        nint exchange,
        byte* response,
        nuint responseLength,
        byte* output,
        nuint outputCapacity,
        nuint* outputLength);

    [LibraryImport(Library)]
    internal static partial byte dfc_ffi_reader_result_status(nint exchange);

    [LibraryImport(Library)]
    internal static partial int dfc_ffi_reader_result_data(nint exchange, byte* output, nuint capacity, nuint* length);

    [LibraryImport(Library)]
    internal static partial int dfc_ffi_reader_change_key_cryptogram(
        nint session,
        byte keyNo,
        byte* newKey,
        nuint keyLength,
        byte* currentKey,
        byte aesKey,
        byte newVersion,
        byte* output,
        nuint outputCapacity,
        nuint* outputLength);

    [LibraryImport(Library)]
    internal static partial int dfc_ffi_reader_change_key_ev2_data(
        nint session,
        byte keySetNo,
        byte keyNo,
        byte* newKey,
        byte* currentKey,
        byte newVersion,
        byte* output,
        nuint outputCapacity,
        nuint* outputLength);

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
    internal static partial int dfc_command_write_data(NativeCommand* command, byte fileNo, uint offset, byte* data, nuint length);

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
