namespace Dfc.Reader;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Dfc.Credentials;
using Dfc.Interop;

/// <summary>How frames travel to the card.</summary>
public enum DfcFraming
{
    /// <summary>ISO 7816 envelopes: 90 INS 00 00 Lc data 00, answered data 91 status.</summary>
    Iso7816 = 0,

    /// <summary>Native frames: INS data, answered status data.</summary>
    Native = 1,
}

/// <summary>The authentication a reader session holds.</summary>
public enum DfcSessionKind
{
    /// <summary>Not authenticated.</summary>
    None = 0,

    /// <summary>Legacy DES.</summary>
    D40 = 0x0A,

    /// <summary>ISO.</summary>
    Iso = 0x1A,

    /// <summary>AES (EV1 secure messaging).</summary>
    Aes = 0xAA,

    /// <summary>EV2 secure messaging.</summary>
    Ev2 = 0x71,
}

/// <summary>A reader session's state.</summary>
public sealed record DfcReaderSession(
    DfcSessionKind Kind,
    byte KeyNo,
    ushort Ev2CommandCounter,
    byte[] Ev2TransactionIdentifier,
    byte[] Ev2CardCapabilities,
    byte[] Ev2ReaderCapabilities
);

/// <summary>The card's final status and its clear answer.</summary>
public sealed record DfcResponse(byte Status, byte[] Data);

/// <summary>The outcome of a proximity check.</summary>
/// <param name="Published">The parameters PrepareProximityCheck published.</param>
/// <param name="LongestRound">The slowest round trip measured.</param>
public sealed record DfcProximityCheckResult(byte[] Published, TimeSpan LongestRound);

/// <summary>What a virtual-card selection revealed.</summary>
/// <param name="ClearData">The card's clear data: information, capabilities and UID.</param>
public sealed record DfcVirtualCardSelection(byte[] ClearData);

/// <summary>A delegated-application creation.</summary>
public sealed record DfcDelegatedApplicationRequest(
    byte[] Aid,
    ushort SlotNumber,
    byte SlotVersion,
    ushort QuotaLimit,
    byte KeySettings1,
    byte KeySettings2,
    byte[] DamEncryptionKey,
    byte[] DamMacKey,
    byte[] InitialKey,
    byte InitialKeyVersion
);

/// <summary>
/// Drives a DESFire-compatible card, real or virtual, through <see cref="IDfcApduExchange" />. Authentication,
/// secure messaging and additional-frame chaining all run in the native reader; this type carries its frames.
/// One reader holds one session and is not thread safe.
/// </summary>
public sealed class DfcReader : IDisposable
{
    private const int Pending = 1;
    private const int FrameCapacity = 300;
    private const int ResultCapacity = 1024;

    private readonly IDfcApduExchange transport;
    private readonly IDfcRandomSource random;
    private readonly DfcFraming framing;
    private readonly ReaderHandle session;
    private readonly ReaderHandle exchange;

    /// <summary>Creates a reader over <paramref name="transport" />.</summary>
    public DfcReader(IDfcApduExchange transport, DfcFraming framing = DfcFraming.Iso7816, IDfcRandomSource? random = null)
    {
        ArgumentNullException.ThrowIfNull(transport);
        Native.EnsureCompatible();
        this.transport = transport;
        this.framing = framing;
        this.random = random ?? DfcSystemRandomSource.Instance;
        (session, exchange) = NewHandles();
    }

    private static unsafe (ReaderHandle Session, ReaderHandle Exchange) NewHandles()
    {
        nint s;
        nint e;
        Allocate(Native.dfc_ffi_reader_session_new(&s));
        var session = new ReaderHandle(s, &Native.dfc_ffi_reader_session_free);
        Allocate(Native.dfc_ffi_reader_exchange_new(&e));
        return (session, new ReaderHandle(e, &Native.dfc_ffi_reader_exchange_free));
    }

    /// <summary>The session this reader holds.</summary>
    public unsafe DfcReaderSession Session
    {
        get
        {
            NativeReaderState state;
            _ = Native.dfc_ffi_reader_session_state(SessionRaw, &state);
            return new DfcReaderSession(
                (DfcSessionKind)state.AuthMode,
                state.KeyNo,
                (ushort)state.Ev2CommandCounter,
                new ReadOnlySpan<byte>(state.Ev2TransactionIdentifier, 4).ToArray(),
                new ReadOnlySpan<byte>(state.Ev2CardCapabilities, 6).ToArray(),
                new ReadOnlySpan<byte>(state.Ev2ReaderCapabilities, 6).ToArray()
            );
        }
    }

    /// <summary>Whether the reader holds an authenticated session.</summary>
    public bool IsAuthenticated => Session.Kind != DfcSessionKind.None;

    /// <summary>Forgets the session, as the card does when it ends one.</summary>
    public void ClearSession() => Native.dfc_ffi_reader_session_clear(SessionRaw);

    /// <summary>
    /// Exchanges one command under the session, following every additional frame. <paramref name="mode" /> is the
    /// communication mode of the file the command addresses. <paramref name="encryptedHeaderLength" /> overrides
    /// how many data octets stay clear when the field is encrypted.
    /// </summary>
    public Task<Result<DfcResponse, DfcProtocolError>> ExchangeAsync(
        DfcCommand command,
        DfcCommunicationMode mode = DfcCommunicationMode.Plain,
        int? encryptedHeaderLength = null,
        CancellationToken cancellationToken = default
    )
    {
        ArgumentNullException.ThrowIfNull(command);
        int st = BeginExchange(command, mode, encryptedHeaderLength ?? -1);
        return st == 0 ? RunAsync(cancellationToken) : Task.FromResult(Failure<DfcResponse>(st));
    }

    private unsafe int BeginExchange(DfcCommand command, DfcCommunicationMode mode, int headerLength)
    {
        fixed (byte* d = command.Data.Span)
        {
            return Native.dfc_ffi_reader_exchange_begin(
                ExchangeRaw,
                SessionRaw,
                (uint)framing,
                command.Instruction,
                d,
                (nuint)command.Data.Length,
                (byte)mode,
                headerLength
            );
        }
    }

    /// <summary>Exchanges a command a factory may have refused.</summary>
    public async Task<Result<DfcResponse, DfcProtocolError>> ExchangeAsync(
        Result<DfcCommand, DfcProtocolError> command,
        DfcCommunicationMode mode = DfcCommunicationMode.Plain,
        CancellationToken cancellationToken = default
    ) =>
        command.IsFailure
            ? command.Error
            : await ExchangeAsync(command.Value, mode, null, cancellationToken).ConfigureAwait(false);

    /// <summary>Legacy, ISO or AES authentication with one key.</summary>
    public async Task<UnitResult<DfcProtocolError>> AuthenticateAsync(
        DfcAuthenticationMode mode,
        byte keyNo,
        ReadOnlyMemory<byte> key,
        CancellationToken cancellationToken = default
    )
    {
        var challengeLength = mode == DfcAuthenticationMode.Aes || key.Length == 24 ? 16 : 8;
        var randomA = new byte[challengeLength];
        random.Fill(randomA);
        int st = BeginAuthenticate(mode, keyNo, key, randomA);
        CryptographicZero(randomA);
        if (st != 0)
        {
            return Failure<DfcResponse>(st).Error;
        }

        var result = await RunAsync(cancellationToken).ConfigureAwait(false);
        return result.IsSuccess ? UnitResult.Success<DfcProtocolError>() : result.Error;
    }

    private unsafe int BeginAuthenticate(DfcAuthenticationMode mode, byte keyNo, ReadOnlyMemory<byte> key, byte[] randomA)
    {
        fixed (byte* k = key.Span)
        fixed (byte* r = randomA)
        {
            return Native.dfc_ffi_reader_authenticate_begin(
                ExchangeRaw,
                SessionRaw,
                (uint)framing,
                (byte)mode,
                keyNo,
                k,
                (nuint)key.Length,
                r,
                (nuint)randomA.Length
            );
        }
    }

    /// <summary>EV2 first authentication with a 16-octet AES key, optionally carrying six octets of reader capabilities.</summary>
    public Task<UnitResult<DfcProtocolError>> AuthenticateEv2FirstAsync(
        byte keyNo,
        ReadOnlyMemory<byte> key,
        ReadOnlyMemory<byte> capabilities = default,
        CancellationToken cancellationToken = default
    ) => AuthenticateEv2Async(true, keyNo, key, capabilities, cancellationToken);

    /// <summary>EV2 non-first authentication, keeping the open transaction.</summary>
    public Task<UnitResult<DfcProtocolError>> AuthenticateEv2NonFirstAsync(
        byte keyNo,
        ReadOnlyMemory<byte> key,
        CancellationToken cancellationToken = default
    ) => AuthenticateEv2Async(false, keyNo, key, ReadOnlyMemory<byte>.Empty, cancellationToken);

    /// <summary>
    /// ChangeKey under a legacy, ISO or AES session. <paramref name="currentKey" /> is needed unless the key is the
    /// authenticated one; changing that one ends the session.
    /// </summary>
    public async Task<UnitResult<DfcProtocolError>> ChangeKeyAsync(
        byte keyNo,
        ReadOnlyMemory<byte> newKey,
        ReadOnlyMemory<byte> currentKey,
        bool aesKey,
        byte newVersion,
        CancellationToken cancellationToken = default
    )
    {
        var (st, cryptogram) = BuildCryptogram(keyNo, newKey, currentKey, aesKey, newVersion);
        if (st != 0)
        {
            return Failure<DfcResponse>(st).Error;
        }

        var data = new byte[1 + cryptogram.Length];
        data[0] = keyNo;
        cryptogram.CopyTo(data.AsSpan(1));
        var result = await ExchangeAsync(new DfcCommand(0xC4, data), DfcCommunicationMode.Plain, null, cancellationToken)
            .ConfigureAwait(false);
        return result.IsSuccess ? UnitResult.Success<DfcProtocolError>() : result.Error;
    }

    private unsafe (int Status, byte[] Cryptogram) BuildCryptogram(
        byte keyNo,
        ReadOnlyMemory<byte> newKey,
        ReadOnlyMemory<byte> currentKey,
        bool aesKey,
        byte newVersion
    )
    {
        var cryptogram = new byte[64];
        nuint length = 0;
        fixed (byte* n = newKey.Span)
        fixed (byte* c = currentKey.Span)
        fixed (byte* o = cryptogram)
        {
            int st = Native.dfc_ffi_reader_change_key_cryptogram(
                SessionRaw,
                keyNo,
                n,
                (nuint)newKey.Length,
                currentKey.Length == 0 ? null : c,
                aesKey ? (byte)1 : (byte)0,
                newVersion,
                o,
                (nuint)cryptogram.Length,
                &length
            );
            return (st, cryptogram[..(int)length]);
        }
    }

    /// <summary>ChangeKeyEV2 for an AES key set under an EV2 session.</summary>
    public async Task<UnitResult<DfcProtocolError>> ChangeKeyEv2Async(
        byte keySetNo,
        byte keyNo,
        ReadOnlyMemory<byte> newKey,
        ReadOnlyMemory<byte> currentKey,
        byte newVersion,
        CancellationToken cancellationToken = default
    )
    {
        var (st, data) = BuildChangeKeyEv2(keySetNo, keyNo, newKey, currentKey, newVersion);
        if (st != 0)
        {
            return Failure<DfcResponse>(st).Error;
        }

        var result = await ExchangeAsync(
                new DfcCommand(0xC6, data),
                DfcCommunicationMode.Plain,
                null,
                cancellationToken
            )
            .ConfigureAwait(false);
        return result.IsSuccess ? UnitResult.Success<DfcProtocolError>() : result.Error;
    }

    private unsafe (int Status, byte[] Data) BuildChangeKeyEv2(
        byte keySetNo,
        byte keyNo,
        ReadOnlyMemory<byte> newKey,
        ReadOnlyMemory<byte> currentKey,
        byte newVersion
    )
    {
        if (newKey.Length != 16)
        {
            return (Native.InvalidArgument, []);
        }

        var data = new byte[DfcCommand.MaximumData];
        nuint length = 0;
        fixed (byte* n = newKey.Span)
        fixed (byte* c = currentKey.Span)
        fixed (byte* o = data)
        {
            int st = Native.dfc_ffi_reader_change_key_ev2_data(
                SessionRaw,
                keySetNo,
                keyNo,
                n,
                currentKey.Length == 0 ? null : c,
                newVersion,
                o,
                (nuint)data.Length,
                &length
            );
            return (st, data[..(int)length]);
        }
    }

    /// <summary>CreateDelegatedApplication under an EV2 session opened with the DAM authentication key.</summary>
    public async Task<UnitResult<DfcProtocolError>> CreateDelegatedApplicationAsync(
        DfcDelegatedApplicationRequest request,
        CancellationToken cancellationToken = default
    )
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.Aid.Length != 3 || request.DamEncryptionKey.Length != 16 || request.DamMacKey.Length != 16)
        {
            return new DfcProtocolError(DfcProtocolErrorKind.Invalid, "The AID or a DAM key has the wrong length.");
        }

        var header = new byte[10];
        request.Aid.CopyTo(header, 0);
        header[3] = (byte)request.SlotNumber;
        header[4] = (byte)(request.SlotNumber >> 8);
        header[5] = request.SlotVersion;
        header[6] = (byte)request.QuotaLimit;
        header[7] = (byte)(request.QuotaLimit >> 8);
        header[8] = request.KeySettings1;
        header[9] = request.KeySettings2;
        var prefix = new byte[7];
        random.Fill(prefix);
        int st = BeginDelegated(header, request, prefix);
        if (st != 0)
        {
            return Failure<DfcResponse>(st).Error;
        }

        var result = await RunAsync(cancellationToken).ConfigureAwait(false);
        return result.IsSuccess ? UnitResult.Success<DfcProtocolError>() : result.Error;
    }

    private unsafe int BeginDelegated(byte[] header, DfcDelegatedApplicationRequest request, byte[] prefix)
    {
        fixed (byte* h = header)
        fixed (byte* e = request.DamEncryptionKey)
        fixed (byte* m = request.DamMacKey)
        fixed (byte* p = prefix)
        fixed (byte* k = request.InitialKey)
        {
            return Native.dfc_ffi_reader_create_delegated_application_begin(
                ExchangeRaw,
                SessionRaw,
                (uint)framing,
                h,
                (nuint)header.Length,
                e,
                m,
                p,
                k,
                (nuint)request.InitialKey.Length,
                request.InitialKeyVersion
            );
        }
    }

    /// <summary>
    /// Runs a proximity check: PrepareProximityCheck, <paramref name="rounds" /> timed rounds covering eight random
    /// octets, then VerifyProximityCheck, whose MAC from the card is checked.
    /// </summary>
    public async Task<Result<DfcProximityCheckResult, DfcProtocolError>> ProximityCheckAsync(
        ReadOnlyMemory<byte> key,
        int rounds = 8,
        CancellationToken cancellationToken = default
    )
    {
        if (key.Length != 16 || rounds is < 1 or > 8 || 8 % rounds != 0)
        {
            return new DfcProtocolError(DfcProtocolErrorKind.Invalid, "The key is 16 octets and the rounds divide eight.");
        }

        var prepared = await ExchangeAsync(new DfcCommand(0xF0, ReadOnlyMemory<byte>.Empty), DfcCommunicationMode.Plain, null, cancellationToken)
            .ConfigureAwait(false);
        if (prepared.IsFailure)
        {
            return prepared.Error;
        }

        var published = prepared.Value.Data;
        var perRound = 8 / rounds;
        var transcript = new List<byte>(16);
        var longest = TimeSpan.Zero;
        for (var round = 0; round < rounds; round++)
        {
            var challenge = new byte[perRound];
            random.Fill(challenge);
            var data = new byte[perRound + 1];
            data[0] = (byte)perRound;
            challenge.CopyTo(data, 1);
            var started = Stopwatch.GetTimestamp();
            var answer = await ExchangeAsync(new DfcCommand(0xF2, data), DfcCommunicationMode.Plain, null, cancellationToken)
                .ConfigureAwait(false);
            var elapsed = Stopwatch.GetElapsedTime(started);
            if (answer.IsFailure)
            {
                return answer.Error;
            }

            if (answer.Value.Data.Length != perRound)
            {
                return new DfcProtocolError(DfcProtocolErrorKind.Protocol, "A proximity round answered with the wrong length.");
            }

            longest = elapsed > longest ? elapsed : longest;
            transcript.AddRange(answer.Value.Data);
            transcript.AddRange(challenge);
        }

        var transcriptBytes = transcript.ToArray();
        var mac = ProximityMac(key.Span, fromCard: false, published, transcriptBytes);
        var verify = await ExchangeAsync(new DfcCommand(0xFD, mac), DfcCommunicationMode.Plain, null, cancellationToken)
            .ConfigureAwait(false);
        if (verify.IsFailure)
        {
            return verify.Error;
        }

        var expected = ProximityMac(key.Span, fromCard: true, published, transcriptBytes);
        return System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(expected, verify.Value.Data)
            ? new DfcProximityCheckResult(published, longest)
            : new DfcProtocolError(DfcProtocolErrorKind.Integrity, "The card's proximity-check MAC did not verify.");
    }

    /// <summary>
    /// Selects a virtual card by installation identifier and proves the reader holds its select keys.
    /// </summary>
    public async Task<Result<DfcVirtualCardSelection, DfcProtocolError>> SelectVirtualCardAsync(
        ReadOnlyMemory<byte> installationId,
        ReadOnlyMemory<byte> selectEncryptionKey,
        ReadOnlyMemory<byte> selectMacKey,
        CancellationToken cancellationToken = default
    )
    {
        if (installationId.Length is < 1 or > 16 || selectEncryptionKey.Length != 16 || selectMacKey.Length != 16)
        {
            return new DfcProtocolError(DfcProtocolErrorKind.Invalid, "The identifier or a select key has the wrong length.");
        }

        var select = new byte[installationId.Length + 6];
        select[1] = 0xA4;
        select[2] = 0x04;
        select[4] = (byte)installationId.Length;
        installationId.Span.CopyTo(select.AsSpan(5));
        var answer = await transport.TransmitAsync(select, cancellationToken).ConfigureAwait(false);
        if (answer.IsFailure)
        {
            return answer.Error;
        }

        var (st, clear, authenticate) = OpenVirtualCard(answer.Value, selectEncryptionKey, selectMacKey);
        if (st != 0)
        {
            return Failure<DfcVirtualCardSelection>(st).Error;
        }

        var confirmed = await transport
            .TransmitAsync(authenticate, cancellationToken)
            .ConfigureAwait(false);
        if (confirmed.IsFailure)
        {
            return confirmed.Error;
        }

        var sw = confirmed.Value;
        return sw.Length == 2 && sw[0] == 0x90 && sw[1] == 0x00
            ? new DfcVirtualCardSelection(clear)
            : new DfcProtocolError(DfcProtocolErrorKind.CardStatus, "The card refused the virtual-card authentication.");
    }

    private static unsafe (int Status, byte[] Clear, byte[] Authenticate) OpenVirtualCard(
        byte[] answer,
        ReadOnlyMemory<byte> selectEncryptionKey,
        ReadOnlyMemory<byte> selectMacKey
    )
    {
        var challenge = new byte[16];
        var clear = new byte[16];
        var authenticate = new byte[16];
        nuint length = 0;
        fixed (byte* k = selectEncryptionKey.Span)
        fixed (byte* m = selectMacKey.Span)
        fixed (byte* r = answer)
        fixed (byte* c = challenge)
        fixed (byte* d = clear)
        fixed (byte* a = authenticate)
        {
            int st = Native.dfc_reader_virtual_card_open(k, r, (nuint)answer.Length, c, d);
            if (st == 0)
            {
                st = Native.dfc_reader_virtual_card_authenticate_apdu(m, c, d, a, (nuint)authenticate.Length, &length);
            }

            return (st, clear, authenticate[..(int)length]);
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        exchange.Dispose();
        session.Dispose();
    }

    // ---------------------------------------------------------- plumbing ---

    private nint SessionRaw
    {
        get
        {
            ObjectDisposedException.ThrowIf(session.IsClosed, this);
            return session.DangerousGetHandle();
        }
    }

    private nint ExchangeRaw
    {
        get
        {
            ObjectDisposedException.ThrowIf(exchange.IsClosed, this);
            return exchange.DangerousGetHandle();
        }
    }

    private async Task<UnitResult<DfcProtocolError>> AuthenticateEv2Async(
        bool first,
        byte keyNo,
        ReadOnlyMemory<byte> key,
        ReadOnlyMemory<byte> capabilities,
        CancellationToken cancellationToken
    )
    {
        if (key.Length != 16)
        {
            return new DfcProtocolError(DfcProtocolErrorKind.Invalid, "EV2 authentication needs a 16-octet AES key.");
        }

        var randomA = new byte[16];
        random.Fill(randomA);
        int st = BeginAuthenticateEv2(first, keyNo, key, randomA, capabilities);
        CryptographicZero(randomA);
        if (st != 0)
        {
            return Failure<DfcResponse>(st).Error;
        }

        var result = await RunAsync(cancellationToken).ConfigureAwait(false);
        return result.IsSuccess ? UnitResult.Success<DfcProtocolError>() : result.Error;
    }

    private unsafe int BeginAuthenticateEv2(
        bool first,
        byte keyNo,
        ReadOnlyMemory<byte> key,
        byte[] randomA,
        ReadOnlyMemory<byte> capabilities
    )
    {
        fixed (byte* k = key.Span)
        fixed (byte* r = randomA)
        fixed (byte* c = capabilities.Span)
        {
            return Native.dfc_ffi_reader_authenticate_ev2_begin(
                ExchangeRaw,
                SessionRaw,
                (uint)framing,
                first ? (byte)1 : (byte)0,
                keyNo,
                k,
                r,
                capabilities.Length == 0 ? null : c,
                (nuint)capabilities.Length
            );
        }
    }

    private async Task<Result<DfcResponse, DfcProtocolError>> RunAsync(CancellationToken cancellationToken)
    {
        byte[]? answer = null;
        while (true)
        {
            var (status, frame) = Step(answer);
            if (status != Pending)
            {
                return status == 0 ? Collect() : Failure<DfcResponse>(status);
            }

            var sent = await transport.TransmitAsync(frame, cancellationToken).ConfigureAwait(false);
            if (sent.IsFailure)
            {
                ClearSession();
                return sent.Error;
            }

            answer = sent.Value;
        }
    }

    private unsafe (int Status, byte[] Frame) Step(byte[]? answer)
    {
        var frame = new byte[FrameCapacity];
        nuint length;
        int st;
        fixed (byte* a = answer)
        fixed (byte* f = frame)
        {
            st = Native.dfc_ffi_reader_step(ExchangeRaw, a, (nuint)(answer?.Length ?? 0), f, FrameCapacity, &length);
        }

        return (st, st == Pending ? frame[..(int)length] : []);
    }

    private unsafe Result<DfcResponse, DfcProtocolError> Collect()
    {
        var data = new byte[ResultCapacity];
        nuint length;
        fixed (byte* d = data)
        {
            _ = Native.dfc_ffi_reader_result_data(ExchangeRaw, d, ResultCapacity, &length);
        }

        return new DfcResponse(Native.dfc_ffi_reader_result_status(ExchangeRaw), data[..(int)length]);
    }

    private Result<T, DfcProtocolError> Failure<T>(int status) =>
        DfcProtocolError.FromReaderStatus(status, Native.dfc_ffi_reader_result_status(ExchangeRaw));

    private unsafe static byte[] ProximityMac(ReadOnlySpan<byte> key, bool fromCard, byte[] published, byte[] transcript)
    {
        var mac = new byte[8];
        fixed (byte* k = key)
        fixed (byte* p = published)
        fixed (byte* t = transcript)
        fixed (byte* m = mac)
        {
            _ = Native.dfc_reader_proximity_check_mac(k, fromCard, p, (nuint)published.Length, t, (nuint)transcript.Length, m);
        }

        return mac;
    }

    private static void CryptographicZero(byte[] buffer) =>
        System.Security.Cryptography.CryptographicOperations.ZeroMemory(buffer);

    private static void Allocate(int status)
    {
        if (status != 0)
        {
            throw new OutOfMemoryException("The native reader could not be allocated.");
        }
    }

    private sealed unsafe class ReaderHandle : SafeHandle
    {
        private readonly delegate*<nint, void> free;

        public ReaderHandle(nint value, delegate*<nint, void> free)
            : base(IntPtr.Zero, ownsHandle: true)
        {
            this.free = free;
            SetHandle(value);
        }

        public override bool IsInvalid => handle == IntPtr.Zero;

        protected override bool ReleaseHandle()
        {
            free(handle);
            return true;
        }
    }
}
