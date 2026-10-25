namespace Dfc.Emulation;

using System;
using Dfc.Interop;

/// <summary>Replaceable native calls used by <see cref="DfcVirtualPicc" />.</summary>
internal sealed unsafe class PiccOperations
{
    internal delegate int UnaryCall(nint picc);
    internal delegate int AdvanceTimeCall(nint picc, uint elapsedMilliseconds);
    internal delegate int SnapshotCall(nint picc, NativeSnapshot* snapshot);
    internal delegate int ExchangeCall(nint picc, byte* input, nuint inputLength, byte* output, nuint outputCapacity, nuint* outputLength);
    internal delegate nuint ResponseCapacityCall();

    internal static PiccOperations Default { get; } = new(
        Native.dfc_ffi_picc_field_off,
        Native.dfc_ffi_picc_reset_protocol,
        Native.dfc_ffi_picc_advance_time,
        Native.dfc_ffi_picc_snapshot,
        Native.dfc_ffi_picc_mark_persisted,
        Native.dfc_ffi_picc_exchange,
        Native.dfc_ffi_picc_frame_exchange,
        Native.dfc_ffi_picc_response_capacity
    );

    private readonly UnaryCall fieldOff;
    private readonly UnaryCall resetProtocol;
    private readonly AdvanceTimeCall advanceTime;
    private readonly SnapshotCall snapshot;
    private readonly UnaryCall markPersisted;
    private readonly ExchangeCall exchange;
    private readonly ExchangeCall frameExchange;
    private readonly ResponseCapacityCall responseCapacity;

    internal PiccOperations(
        UnaryCall fieldOff,
        UnaryCall resetProtocol,
        AdvanceTimeCall advanceTime,
        SnapshotCall snapshot,
        UnaryCall markPersisted,
        ExchangeCall? exchange = null,
        ExchangeCall? frameExchange = null,
        ResponseCapacityCall? responseCapacity = null
    )
    {
        this.fieldOff = fieldOff;
        this.resetProtocol = resetProtocol;
        this.advanceTime = advanceTime;
        this.snapshot = snapshot;
        this.markPersisted = markPersisted;
        this.exchange = exchange ?? Native.dfc_ffi_picc_exchange;
        this.frameExchange = frameExchange ?? Native.dfc_ffi_picc_frame_exchange;
        this.responseCapacity = responseCapacity ?? Native.dfc_ffi_picc_response_capacity;
    }

    internal void FieldOff(nint picc)
    {
        Check(this.fieldOff(picc), nameof(FieldOff));
    }

    internal void ResetProtocol(nint picc)
    {
        Check(this.resetProtocol(picc), nameof(ResetProtocol));
    }

    internal void AdvanceTime(nint picc, uint elapsedMilliseconds)
    {
        Check(this.advanceTime(picc, elapsedMilliseconds), nameof(AdvanceTime));
    }

    internal NativeSnapshot Snapshot(nint picc)
    {
        NativeSnapshot value = default;
        Check(this.snapshot(picc, &value), nameof(Snapshot));
        return value;
    }

    internal void MarkPersisted(nint picc)
    {
        Check(this.markPersisted(picc), nameof(MarkPersisted));
    }

    internal int Exchange(nint picc, byte* input, nuint inputLength, byte* output, nuint outputCapacity, nuint* outputLength, bool frame)
    {
        return (frame ? this.frameExchange : this.exchange)(picc, input, inputLength, output, outputCapacity, outputLength);
    }

    internal nuint ResponseCapacity()
    {
        return this.responseCapacity();
    }

    private static void Check(int status, string operation)
    {
        if (status != 0)
        {
            throw new InvalidOperationException(
                $"The native virtual PICC {operation} operation failed with status {status}."
            );
        }
    }
}
