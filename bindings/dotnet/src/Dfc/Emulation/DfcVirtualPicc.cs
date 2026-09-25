namespace Dfc.Emulation;

using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Dfc.Credentials;
using Dfc.Interop;

/// <summary>What anticollision presented.</summary>
/// <param name="Uid">The UID presented; the random one when random ID is on.</param>
/// <param name="Atqa">ATQA.</param>
/// <param name="Sak">SAK.</param>
/// <param name="Ats">ATS.</param>
public sealed record DfcActivation(byte[] Uid, byte[] Atqa, byte Sak, byte[] Ats);

/// <summary>Which level of the card is selected.</summary>
public enum DfcSelection
{
    /// <summary>Nothing selected yet.</summary>
    None = 0,

    /// <summary>The PICC master application.</summary>
    Picc = 1,

    /// <summary>An application.</summary>
    Application = 2,
}

/// <summary>The card's state between exchanges.</summary>
public sealed record DfcPiccSnapshot(
    DfcSelection Selection,
    byte[] SelectedAid,
    bool Dirty,
    DfcAuthenticationMode? Authentication,
    byte AuthenticatedKeyNo,
    DfcEv2SessionSnapshot? Ev2Session,
    bool VirtualCardSelected,
    bool ProximityVerified
);

/// <summary>An open EV2 session on the card.</summary>
public sealed record DfcEv2SessionSnapshot(
    byte KeyNo,
    byte[] TransactionIdentifier,
    ushort CommandCounter,
    byte[] EncryptionKey,
    byte[] MacKey
);

/// <summary>
/// A DESFire-compatible card in process. It answers anticollision, ISO 7816 and native APDUs, and ISO-DEP
/// blocks, from its own copy of a credential; the emulator is the native one a device runs.
/// </summary>
public sealed unsafe class DfcVirtualPicc : IDfcApduExchange, IDisposable
{
    private const int ResponseCapacity = 1024;
    private const int NoCard = 1;

    private readonly PiccHandle handle;
    private readonly GCHandle randomRoot;
    private readonly TimeProvider? clock;
    private long lastTimestamp;
    private readonly Lock gate = new();

    private DfcVirtualPicc(PiccHandle handle, GCHandle randomRoot, TimeProvider? clock)
    {
        this.handle = handle;
        this.randomRoot = randomRoot;
        this.clock = clock;
        lastTimestamp = clock?.GetTimestamp() ?? 0;
    }

    /// <summary>
    /// Creates a card from <paramref name="credential" />. Randomness comes from <paramref name="random" />, or from
    /// the operating system. With a <paramref name="clock" />, time-dependent state such as the transaction timer
    /// follows it; without one, time advances only through <see cref="AdvanceTime" />.
    /// </summary>
    public static Result<DfcVirtualPicc, DfcError> Create(
        DfcCredential credential,
        IDfcRandomSource? random = null,
        TimeProvider? clock = null
    )
    {
        var written = CredentialMarshaller.Write(credential);
        if (written.IsFailure)
        {
            return written.Error;
        }

        using var source = written.Value;
        var root = random is null ? default : GCHandle.Alloc(random);
        nint picc;
        int st;
        bool added = false;
        source.DangerousAddRef(ref added);
        try
        {
            st = random is null
                ? Native.dfc_ffi_picc_create(source.DangerousGetHandle(), null, 0, &picc)
                : Native.dfc_ffi_picc_create(source.DangerousGetHandle(), &RandomTrampoline, GCHandle.ToIntPtr(root), &picc);
        }
        finally
        {
            if (added)
            {
                source.DangerousRelease();
            }
        }

        if (st != 0)
        {
            if (root.IsAllocated)
            {
                root.Free();
            }

            return DfcError.FromStatus(st, "the virtual PICC could not be created");
        }

        return new DfcVirtualPicc(new PiccHandle(picc), root, clock);
    }

    /// <summary>Runs anticollision and reports what the card presented.</summary>
    public Result<DfcActivation, DfcProtocolError> Activate()
    {
        NativeActivation activation;
        int st;
        lock (gate)
        {
            st = Native.dfc_ffi_picc_activate(Raw, &activation);
        }

        if (st != 0)
        {
            return st == NoCard
                ? new DfcProtocolError(DfcProtocolErrorKind.NoCard, "No card answered anticollision.")
                : new DfcProtocolError(DfcProtocolErrorKind.Protocol, $"Activation failed with status {st}.");
        }

        return new DfcActivation(
            new ReadOnlySpan<byte>(activation.Uid, (int)activation.UidLen).ToArray(),
            new ReadOnlySpan<byte>(activation.Atqa, (int)activation.AtqaLen).ToArray(),
            activation.Sak,
            new ReadOnlySpan<byte>(activation.Ats, (int)activation.AtsLen).ToArray()
        );
    }

    /// <summary>Answers one APDU, ISO 7816 or native framed.</summary>
    public Result<byte[], DfcProtocolError> Exchange(ReadOnlySpan<byte> command) => Call(command, frame: false);

    /// <summary>Answers one ISO-DEP block, the layer below APDUs.</summary>
    public Result<byte[], DfcProtocolError> ExchangeFrame(ReadOnlySpan<byte> frame) => Call(frame, frame: true);

    /// <inheritdoc />
    public ValueTask<Result<byte[], DfcProtocolError>> TransmitAsync(
        ReadOnlyMemory<byte> frame,
        CancellationToken cancellationToken
    )
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(Exchange(frame.Span));
    }

    /// <summary>Removes the field: the card loses its session and its activation.</summary>
    public void FieldOff()
    {
        lock (gate)
        {
            _ = Native.dfc_ffi_picc_field_off(Raw);
        }
    }

    /// <summary>Clears authentication and ISO-DEP state while the field stays on.</summary>
    public void ResetProtocol()
    {
        lock (gate)
        {
            _ = Native.dfc_ffi_picc_reset_protocol(Raw);
        }
    }

    /// <summary>Advances the card's notion of time.</summary>
    public void AdvanceTime(TimeSpan elapsed)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(elapsed, TimeSpan.Zero);
        lock (gate)
        {
            _ = Native.dfc_ffi_picc_advance_time(Raw, (uint)Math.Min(elapsed.TotalMilliseconds, uint.MaxValue));
        }
    }

    /// <summary>The card's state now.</summary>
    public DfcPiccSnapshot Snapshot()
    {
        NativeSnapshot s;
        lock (gate)
        {
            _ = Native.dfc_ffi_picc_snapshot(Raw, &s);
        }

        DfcEv2SessionSnapshot? ev2 = s.Ev2Active != 0
            ? new DfcEv2SessionSnapshot(
                s.Ev2KeyNo,
                new ReadOnlySpan<byte>(s.Ev2TransactionIdentifier, 4).ToArray(),
                (ushort)s.Ev2CommandCounter,
                new ReadOnlySpan<byte>(s.Ev2EncryptionKey, 16).ToArray(),
                new ReadOnlySpan<byte>(s.Ev2MacKey, 16).ToArray()
            )
            : null;
        return new DfcPiccSnapshot(
            (DfcSelection)s.Selected,
            new ReadOnlySpan<byte>(s.SelectedAid, 3).ToArray(),
            s.Dirty != 0,
            s.AuthMode != 0 ? (DfcAuthenticationMode)s.AuthMode : null,
            s.AuthKeyNo,
            ev2,
            s.VirtualCardSelected != 0,
            s.ProximityVerified != 0
        );
    }

    /// <summary>Whether the card has changed since it was created or last persisted.</summary>
    public bool IsDirty => Snapshot().Dirty;

    /// <summary>The credential as the card holds it now.</summary>
    public DfcCredential ExportCredential()
    {
        nint exported;
        lock (gate)
        {
            CredentialMarshaller.Check(Native.dfc_ffi_picc_export(Raw, &exported));
        }

        using var credential = new CredentialHandle(exported);
        return CredentialMarshaller.Read(credential);
    }

    /// <summary>Records that the current state has been saved.</summary>
    public void MarkPersisted()
    {
        lock (gate)
        {
            _ = Native.dfc_ffi_picc_mark_persisted(Raw);
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        handle.Dispose();
        if (randomRoot.IsAllocated)
        {
            randomRoot.Free();
        }
    }

    private nint Raw
    {
        get
        {
            ObjectDisposedException.ThrowIf(handle.IsClosed, this);
            return handle.DangerousGetHandle();
        }
    }

    private Result<byte[], DfcProtocolError> Call(ReadOnlySpan<byte> command, bool frame)
    {
        Span<byte> response = stackalloc byte[ResponseCapacity];
        nuint length;
        int st;
        lock (gate)
        {
            FollowClock();
            fixed (byte* c = command)
            fixed (byte* r = response)
            {
                st = frame
                    ? Native.dfc_ffi_picc_frame_exchange(Raw, c, (nuint)command.Length, r, ResponseCapacity, &length)
                    : Native.dfc_ffi_picc_exchange(Raw, c, (nuint)command.Length, r, ResponseCapacity, &length);
            }
        }

        if (st != 0)
        {
            return st == NoCard
                ? new DfcProtocolError(DfcProtocolErrorKind.NoCard, "The card is not activated.")
                : new DfcProtocolError(DfcProtocolErrorKind.Protocol, $"The card could not answer (status {st}).");
        }

        return response[..(int)length].ToArray();
    }

    private void FollowClock()
    {
        if (clock is null)
        {
            return;
        }

        var now = clock.GetTimestamp();
        var elapsed = clock.GetElapsedTime(lastTimestamp, now);
        lastTimestamp = now;
        if (elapsed > TimeSpan.Zero)
        {
            _ = Native.dfc_ffi_picc_advance_time(Raw, (uint)Math.Min(elapsed.TotalMilliseconds, uint.MaxValue));
        }
    }

    [UnmanagedCallersOnly]
    private static void RandomTrampoline(nint context, byte* buffer, nuint length)
    {
        var destination = new Span<byte>(buffer, (int)length);
        try
        {
            ((IDfcRandomSource)GCHandle.FromIntPtr(context).Target!).Fill(destination);
        }
        catch (Exception)
        {
            // An exception cannot cross into native code, and a card must never
            // answer with a predictable challenge.
            RandomNumberGenerator.Fill(destination);
        }
    }

    private sealed class PiccHandle : SafeHandle
    {
        public PiccHandle(nint picc)
            : base(IntPtr.Zero, ownsHandle: true)
        {
            SetHandle(picc);
        }

        public override bool IsInvalid => handle == IntPtr.Zero;

        protected override bool ReleaseHandle()
        {
            Native.dfc_ffi_picc_free(handle);
            return true;
        }
    }
}
