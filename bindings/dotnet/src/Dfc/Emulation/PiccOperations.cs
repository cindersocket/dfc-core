namespace Dfc.Emulation;

using System;
using Dfc.Interop;

/// <summary>Checked state-only native calls used by <see cref="DfcVirtualPicc" />.</summary>
internal sealed unsafe class PiccOperations
{
    internal delegate int UnaryCall(nint picc);
    internal delegate int AdvanceTimeCall(nint picc, uint elapsedMilliseconds);
    internal delegate int SnapshotCall(nint picc, NativeSnapshot* snapshot);

    internal static PiccOperations Default { get; } = new(
        Native.dfc_ffi_picc_field_off,
        Native.dfc_ffi_picc_reset_protocol,
        Native.dfc_ffi_picc_advance_time,
        Native.dfc_ffi_picc_snapshot,
        Native.dfc_ffi_picc_mark_persisted
    );

    private readonly UnaryCall fieldOff;
    private readonly UnaryCall resetProtocol;
    private readonly AdvanceTimeCall advanceTime;
    private readonly SnapshotCall snapshot;
    private readonly UnaryCall markPersisted;

    internal PiccOperations(
        UnaryCall fieldOff,
        UnaryCall resetProtocol,
        AdvanceTimeCall advanceTime,
        SnapshotCall snapshot,
        UnaryCall markPersisted
    )
    {
        this.fieldOff = fieldOff;
        this.resetProtocol = resetProtocol;
        this.advanceTime = advanceTime;
        this.snapshot = snapshot;
        this.markPersisted = markPersisted;
    }

    internal void FieldOff(nint picc) => Check(fieldOff(picc), nameof(FieldOff));

    internal void ResetProtocol(nint picc) => Check(resetProtocol(picc), nameof(ResetProtocol));

    internal void AdvanceTime(nint picc, uint elapsedMilliseconds) =>
        Check(advanceTime(picc, elapsedMilliseconds), nameof(AdvanceTime));

    internal NativeSnapshot Snapshot(nint picc)
    {
        NativeSnapshot value = default;
        Check(snapshot(picc, &value), nameof(Snapshot));
        return value;
    }

    internal void MarkPersisted(nint picc) => Check(markPersisted(picc), nameof(MarkPersisted));

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
