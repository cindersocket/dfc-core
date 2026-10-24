namespace Dfc.Emulation;

using System;
using System.Runtime.InteropServices;
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
    private const int InitialResponseCapacity = 256;
    private const int NoCard = 1;
    private static readonly TimeSpan MaximumNativeElapsed = TimeSpan.FromMilliseconds(uint.MaxValue);

    internal delegate int PiccCreator(
        nint credential,
        delegate* unmanaged<nint, byte*, nuint, int> random,
        nint context,
        nint* output
    );

    internal readonly record struct CreationHooks(
        PiccCreator Create,
        Action<nint>? AfterCreate = null,
        Action<nint>? Free = null
    );

    private readonly PiccHandle handle;
    private readonly PiccOperations operations;
    private readonly TimeProvider? clock;
    private long lastTimestamp;
    private readonly Lock gate = new();

    private DfcVirtualPicc(
        PiccHandle handle,
        PiccOperations operations,
        TimeProvider? clock,
        long lastTimestamp
    )
    {
        this.handle = handle;
        this.operations = operations;
        this.clock = clock;
        this.lastTimestamp = lastTimestamp;
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
        return CreateCore(credential, random, clock, null, null);
    }

    internal static Result<DfcVirtualPicc, DfcError> CreateForTesting(
        DfcCredential credential,
        IDfcRandomSource? random,
        TimeProvider? clock,
        CreationHooks hooks
    )
    {
        return CreateCore(credential, random, clock, hooks, null);
    }

    internal static Result<DfcVirtualPicc, DfcError> CreateWithOperationsForTesting(
        DfcCredential credential,
        PiccOperations operations
    )
    {
        return CreateCore(credential, null, null, null, operations);
    }

    private static Result<DfcVirtualPicc, DfcError> CreateCore(
        DfcCredential credential,
        IDfcRandomSource? random,
        TimeProvider? clock,
        CreationHooks? hooks,
        PiccOperations? operations
    )
    {
        var written = CredentialMarshaller.Write(credential);
        if (written.IsFailure)
        {
            return written.Error;
        }

        using var source = written.Value;
        var initialTimestamp = clock?.GetTimestamp() ?? 0;
        GCHandle root = default;
        nint picc = 0;
        PiccHandle? pendingHandle = null;
        try
        {
            root = random is null ? default : GCHandle.Alloc(random);
            int st;
            var added = false;
            source.DangerousAddRef(ref added);
            try
            {
                var create = hooks?.Create;
                st = create is null
                    ? Native.dfc_ffi_picc_create(
                        source.DangerousGetHandle(),
                        random is null ? null : &RandomTrampoline,
                        random is null ? 0 : GCHandle.ToIntPtr(root),
                        &picc
                    )
                    : create(
                        source.DangerousGetHandle(),
                        random is null ? null : &RandomTrampoline,
                        random is null ? 0 : GCHandle.ToIntPtr(root),
                        &picc
                    );
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
                return DfcError.FromStatus(st, "the virtual PICC could not be created");
            }

            if (hooks?.AfterCreate is { } afterCreate)
            {
                afterCreate(picc);
            }

            pendingHandle = new PiccHandle(picc, root);
            picc = 0;
            root = default;
            var card = new DfcVirtualPicc(
                pendingHandle,
                operations ?? PiccOperations.Default,
                clock,
                initialTimestamp
            );
            pendingHandle = null;
            return card;
        }
        finally
        {
            if (pendingHandle is not null)
            {
                pendingHandle.Dispose();
            }
            else
            {
                try
                {
                    if (picc != 0)
                    {
                        if (hooks?.Free is { } free)
                        {
                            free(picc);
                        }
                        else
                        {
                            Native.dfc_ffi_picc_free(picc);
                        }
                    }
                }
                finally
                {
                    if (root.IsAllocated)
                    {
                        root.Free();
                    }
                }
            }
        }
    }

    /// <summary>Runs anticollision and reports what the card presented.</summary>
    public Result<DfcActivation, DfcProtocolError> Activate()
    {
        NativeActivation activation;
        int st;
        lock (this.gate)
        {
            using var lease = new PiccHandleLease(this.handle);
            st = Native.dfc_ffi_picc_activate(lease.Raw, &activation);
        }

        if (st != 0)
        {
            return st switch
            {
                NoCard => new DfcProtocolError(DfcProtocolErrorKind.NoCard, "No card answered anticollision."),
                Native.RandomFailed => new DfcProtocolError(
                    DfcProtocolErrorKind.RandomSource, "The virtual card's random source failed."),
                _ => new DfcProtocolError(DfcProtocolErrorKind.Protocol, $"Activation failed with status {st}."),
            };
        }

        return new DfcActivation(
            new ReadOnlySpan<byte>(activation.Uid, (int)activation.UidLen).ToArray(),
            new ReadOnlySpan<byte>(activation.Atqa, (int)activation.AtqaLen).ToArray(),
            activation.Sak,
            new ReadOnlySpan<byte>(activation.Ats, (int)activation.AtsLen).ToArray()
        );
    }

    /// <summary>Answers one APDU, ISO 7816 or native framed.</summary>
    public Result<byte[], DfcProtocolError> Exchange(ReadOnlySpan<byte> command)
    {
        return this.Call(command, frame: false);
    }

    /// <summary>Answers one ISO-DEP block, the layer below APDUs.</summary>
    public Result<byte[], DfcProtocolError> ExchangeFrame(ReadOnlySpan<byte> frame)
    {
        return this.Call(frame, frame: true);
    }

    /// <inheritdoc />
    public ValueTask<Result<byte[], DfcProtocolError>> TransmitAsync(
        ReadOnlyMemory<byte> frame,
        CancellationToken cancellationToken
    )
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(this.Exchange(frame.Span));
    }

    /// <summary>Removes the field: the card loses its session and its activation.</summary>
    public void FieldOff()
    {
        lock (this.gate)
        {
            using var lease = new PiccHandleLease(this.handle);
            this.operations.FieldOff(lease.Raw);
        }
    }

    /// <summary>Clears authentication and ISO-DEP state while the field stays on.</summary>
    public void ResetProtocol()
    {
        lock (this.gate)
        {
            using var lease = new PiccHandleLease(this.handle);
            this.operations.ResetProtocol(lease.Raw);
        }
    }

    /// <summary>Advances the card's notion of time.</summary>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="elapsed" /> is negative or exceeds <see cref="uint.MaxValue" /> milliseconds.
    /// </exception>
    public void AdvanceTime(TimeSpan elapsed)
    {
        var milliseconds = NativeMilliseconds(elapsed, saturate: false);
        lock (this.gate)
        {
            using var lease = new PiccHandleLease(this.handle);
            this.operations.AdvanceTime(lease.Raw, milliseconds);
        }
    }

    /// <summary>The card's state now.</summary>
    public DfcPiccSnapshot Snapshot()
    {
        NativeSnapshot s;
        lock (this.gate)
        {
            using var lease = new PiccHandleLease(this.handle);
            s = this.operations.Snapshot(lease.Raw);
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
    public bool IsDirty => this.Snapshot().Dirty;

    /// <summary>The credential as the card holds it now.</summary>
    public DfcCredential ExportCredential()
    {
        nint exported;
        lock (this.gate)
        {
            using var lease = new PiccHandleLease(this.handle);
            CredentialMarshaller.Check(Native.dfc_ffi_picc_export(lease.Raw, &exported));
        }

        using var credential = new CredentialHandle(exported);
        return CredentialMarshaller.Read(credential);
    }

    /// <summary>Records that the current state has been saved.</summary>
    public void MarkPersisted()
    {
        lock (this.gate)
        {
            using var lease = new PiccHandleLease(this.handle);
            this.operations.MarkPersisted(lease.Raw);
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        lock (this.gate)
        {
            this.handle.Dispose();
        }
    }

    private Result<byte[], DfcProtocolError> Call(ReadOnlySpan<byte> command, bool frame)
    {
        Span<byte> response = stackalloc byte[InitialResponseCapacity];
        byte[]? expandedResponse = null;
        nuint length;
        int st;
        lock (this.gate)
        {
            using var lease = new PiccHandleLease(this.handle);
            this.FollowClock(lease.Raw);
            fixed (byte* c = command)
            fixed (byte* r = response)
            {
                st = this.operations.Exchange(lease.Raw, c, (nuint)command.Length, r, (nuint)response.Length, &length, frame);
            }
            if (st == Native.PiccBufferTooSmall)
            {
                var capacity = this.operations.ResponseCapacity();
                if (capacity is <= InitialResponseCapacity or > int.MaxValue)
                {
                    return new DfcProtocolError(
                        DfcProtocolErrorKind.Protocol,
                        $"The card could not answer (status {Native.PiccBufferTooSmall})."
                    );
                }
                try
                {
                    expandedResponse = GC.AllocateUninitializedArray<byte>((int)capacity);
                }
                catch (OutOfMemoryException)
                {
                    return new DfcProtocolError(
                        DfcProtocolErrorKind.Protocol,
                        "The virtual card response could not be allocated."
                    );
                }
                response = expandedResponse;
                length = 0;
                fixed (byte* c = command)
                fixed (byte* r = response)
                {
                    st = this.operations.Exchange(lease.Raw, c, (nuint)command.Length, r, capacity, &length, frame);
                }
            }
        }

        if (st != 0)
        {
            return st switch
            {
                NoCard => new DfcProtocolError(DfcProtocolErrorKind.NoCard, "The card is not activated."),
                Native.RandomFailed => new DfcProtocolError(
                    DfcProtocolErrorKind.RandomSource, "The virtual card's random source failed."),
                _ => new DfcProtocolError(DfcProtocolErrorKind.Protocol, $"The card could not answer (status {st})."),
            };
        }

        if (length > (nuint)response.Length)
        {
            return new DfcProtocolError(DfcProtocolErrorKind.Protocol, "The native response length is invalid.");
        }
        return response[..(int)length].ToArray();
    }

    private void FollowClock(nint raw)
    {
        if (this.clock is null)
        {
            return;
        }

        var now = this.clock.GetTimestamp();
        var elapsed = this.clock.GetElapsedTime(this.lastTimestamp, now);
        if (elapsed > TimeSpan.Zero)
        {
            // Once the native transaction timer expires, additional elapsed time has no effect.
            this.operations.AdvanceTime(raw, NativeMilliseconds(elapsed, saturate: true));
        }
        this.lastTimestamp = now;
    }

    private static uint NativeMilliseconds(TimeSpan elapsed, bool saturate)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(elapsed, TimeSpan.Zero);
        if (elapsed > MaximumNativeElapsed)
        {
            if (saturate)
            {
                return uint.MaxValue;
            }

            ArgumentOutOfRangeException.ThrowIfGreaterThan(elapsed, MaximumNativeElapsed);
        }

        return checked((uint)elapsed.TotalMilliseconds);
    }

    [UnmanagedCallersOnly]
    private static int RandomTrampoline(nint context, byte* buffer, nuint length)
    {
        var destination = new Span<byte>(buffer, (int)length);
        try
        {
            ((IDfcRandomSource)GCHandle.FromIntPtr(context).Target!).Fill(destination);
            return 0;
        }
        catch (Exception)
        {
            // An exception cannot cross into native code. Returning failure
            // makes the native operation stop before it changes card state.
            return -5;
        }
    }

    private sealed class PiccHandle : SafeHandle
    {
        private GCHandle randomRoot;

        public PiccHandle(nint picc, GCHandle randomRoot)
            : base(IntPtr.Zero, ownsHandle: true)
        {
            this.randomRoot = randomRoot;
            this.SetHandle(picc);
        }

        public override bool IsInvalid => this.handle == IntPtr.Zero;

        protected override bool ReleaseHandle()
        {
            try
            {
                Native.dfc_ffi_picc_free(this.handle);
            }
            finally
            {
                if (this.randomRoot.IsAllocated)
                {
                    this.randomRoot.Free();
                }
            }
            return true;
        }
    }

    private readonly ref struct PiccHandleLease
    {
        private readonly PiccHandle handle;

        public PiccHandleLease(PiccHandle handle)
        {
            this.handle = handle;
            var added = false;
            try
            {
                handle.DangerousAddRef(ref added);
            }
            catch (ObjectDisposedException)
            {
                throw new ObjectDisposedException(nameof(DfcVirtualPicc));
            }
            this.Raw = handle.DangerousGetHandle();
        }

        public nint Raw { get; }

        public void Dispose()
        {
            this.handle.DangerousRelease();
        }
    }
}
