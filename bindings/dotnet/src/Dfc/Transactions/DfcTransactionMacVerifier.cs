namespace Dfc.Transactions;

using System;
using System.Runtime.InteropServices;
using CSharpFunctionalExtensions;
using Dfc.Interop;

/// <summary>Collects plain transaction inputs and verifies one returned receipt.</summary>
public sealed unsafe class DfcTransactionMacVerifier : IDisposable
{
    private readonly TransactionHandle handle;

    private DfcTransactionMacVerifier(TransactionHandle handle) => this.handle = handle;

    /// <summary>Creates a verifier for one transaction and transaction counter.</summary>
    public static Result<DfcTransactionMacVerifier, DfcError> Create(ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> uid, uint counter, int capacity = 128)
    {
        if (key.Length != 16 || (uid.Length != 4 && uid.Length != 7) || capacity <= 0)
            return DfcError.FromStatus(Native.InvalidArgument,
                "expected a 16-byte key, 4- or 7-byte UID and positive capacity");
        Native.EnsureCompatible();
        nint raw = 0;
        int status;
        fixed (byte* keyBytes = key)
        fixed (byte* uidBytes = uid)
        {
            status = Native.dfc_ffi_transaction_mac_verifier_new(
                (nuint)capacity, keyBytes, uidBytes, (nuint)uid.Length, counter, &raw);
        }
        return status == Native.TransactionMacOk
            ? new DfcTransactionMacVerifier(new TransactionHandle(raw))
            : DfcError.FromStatus(status, "transaction MAC initialization failed");
    }

    private UnitResult<DfcError> Use(Func<nint, int> action)
    {
        if (handle.IsClosed || handle.IsInvalid)
            return UnitResult.Failure(DfcError.FromStatus(Native.InvalidArgument, "transaction verifier is closed"));
        bool added = false;
        try
        {
            handle.DangerousAddRef(ref added);
            int status = action(handle.DangerousGetHandle());
            return status == Native.TransactionMacOk ? UnitResult.Success<DfcError>()
                : UnitResult.Failure(DfcError.FromStatus(status, "transaction MAC operation failed"));
        }
        finally
        {
            if (added)
                handle.DangerousRelease();
        }
    }

    private nint Acquire(out bool added)
    {
        ObjectDisposedException.ThrowIf(handle.IsClosed || handle.IsInvalid, this);
        added = false;
        handle.DangerousAddRef(ref added);
        return handle.DangerousGetHandle();
    }

    private void Release(bool added)
    {
        if (added)
            handle.DangerousRelease();
    }

    private static UnitResult<DfcError> Outcome(int status) =>
        status == Native.TransactionMacOk ? UnitResult.Success<DfcError>()
            : UnitResult.Failure(DfcError.FromStatus(status, "transaction MAC operation failed"));

    /// <summary>Adds the plain data command that was sent during the transaction.</summary>
    public UnitResult<DfcError> AddData(byte command, byte fileNumber, uint offset, uint length,
        ReadOnlySpan<byte> data)
    {
        bool added = false;
        try
        {
            nint raw = Acquire(out added);
            fixed (byte* bytes = data)
                return Outcome(Native.dfc_ffi_transaction_mac_add_data(
                    raw, command, fileNumber, offset, length, bytes, (nuint)data.Length));
        }
        finally { Release(added); }
    }

    /// <summary>Adds the plain record update that was sent during the transaction.</summary>
    public UnitResult<DfcError> AddRecordUpdate(byte command, byte fileNumber, uint recordNumber,
        uint offset, uint length, ReadOnlySpan<byte> data)
    {
        bool added = false;
        try
        {
            nint raw = Acquire(out added);
            fixed (byte* bytes = data)
                return Outcome(Native.dfc_ffi_transaction_mac_add_record_update(raw, command,
                    fileNumber, recordNumber, offset, length, bytes, (nuint)data.Length));
        }
        finally { Release(added); }
    }

    /// <summary>Adds a credit, debit, or limited-credit operation.</summary>
    public UnitResult<DfcError> AddValue(byte command, byte fileNumber, uint value) =>
        Use(raw => Native.dfc_ffi_transaction_mac_add_value(raw, command, fileNumber, value));

    /// <summary>Adds a ClearRecordFile operation.</summary>
    public UnitResult<DfcError> AddClearRecord(byte fileNumber) =>
        Use(raw => Native.dfc_ffi_transaction_mac_add_clear_record(raw, fileNumber));

    /// <summary>Adds the reader identifier inputs included by the transaction.</summary>
    public UnitResult<DfcError> AddReaderId(ReadOnlySpan<byte> current, ReadOnlySpan<byte> encryptedPrevious)
    {
        if (current.Length != 16 || encryptedPrevious.Length != 16)
            return UnitResult.Failure(DfcError.FromStatus(Native.InvalidArgument, "reader IDs must be 16 bytes"));
        bool added = false;
        try
        {
            nint raw = Acquire(out added);
            fixed (byte* currentBytes = current)
            fixed (byte* previousBytes = encryptedPrevious)
                return Outcome(Native.dfc_ffi_transaction_mac_add_reader_id(
                    raw, currentBytes, previousBytes));
        }
        finally { Release(added); }
    }

    /// <summary>Verifies the returned CommitTransaction MAC against the recorded operations.</summary>
    public Result<bool, DfcError> Verify(ReadOnlySpan<byte> mac)
    {
        if (mac.Length != 8)
            return DfcError.FromStatus(Native.InvalidArgument, "transaction MAC must be 8 bytes");
        bool added = false;
        try
        {
            nint raw = Acquire(out added);
            byte verified = 0;
            int status;
            fixed (byte* macBytes = mac)
                status = Native.dfc_ffi_transaction_mac_verify(raw, macBytes, &verified);
            return status == Native.TransactionMacOk
                ? verified != 0 : DfcError.FromStatus(status, "transaction MAC operation failed");
        }
        finally { Release(added); }
    }

    /// <summary>Wipes and releases the native verification state.</summary>
    public void Dispose() => handle.Dispose();

    private sealed class TransactionHandle : SafeHandle
    {
        internal TransactionHandle(nint value) : base(IntPtr.Zero, true) => SetHandle(value);
        public override bool IsInvalid => handle == IntPtr.Zero;
        protected override bool ReleaseHandle()
        {
            Native.dfc_ffi_transaction_mac_verifier_free(handle);
            return true;
        }
    }
}
