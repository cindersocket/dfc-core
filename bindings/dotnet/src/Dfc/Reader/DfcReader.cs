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
    Iso7816 = (int)Interop.Native.DFC_FFI_READER_FRAMING_ISO7816,

    /// <summary>Native frames: INS data, answered status data.</summary>
    Native = (int)Interop.Native.DFC_FFI_READER_FRAMING_NATIVE,
}

/// <summary>The authentication a reader session holds.</summary>
public enum DfcSessionKind
{
    /// <summary>Not authenticated.</summary>
    None = 0,

    /// <summary>D40 DES authentication.</summary>
    D40 = (int)Native.DFC_FFI_AUTH_LEGACY,

    /// <summary>ISO.</summary>
    Iso = (int)Native.DFC_FFI_AUTH_ISO,

    /// <summary>AES (EV1 secure messaging).</summary>
    Aes = (int)Native.DFC_FFI_AUTH_AES,

    /// <summary>EV2 secure messaging.</summary>
    Ev2 = (int)Native.DFC_FFI_AUTH_EV2,
}

/// <summary>The key algorithm for standard ISO 7816 mutual authentication.</summary>
public enum DfcIso7816AuthAlgorithm : byte
{
    /// <summary>Two-key Triple DES.</summary>
    Tdea2 = (byte)Native.DFC_FFI_ISO_AUTH_TDEA2,
    /// <summary>Three-key Triple DES.</summary>
    Tdea3 = (byte)Native.DFC_FFI_ISO_AUTH_TDEA3,
    /// <summary>AES-128.</summary>
    Aes = (byte)Native.DFC_FFI_ISO_AUTH_AES,
}

/// <summary>A reader session's state.</summary>
/// <param name="Kind">The active authentication family, or None.</param>
/// <param name="KeyNo">The authenticated key number, or null when unauthenticated.</param>
/// <param name="Ev2CommandCounter">The command counter, or null outside EV2.</param>
/// <param name="Ev2TransactionIdentifier">The transaction identifier, or null outside EV2.</param>
/// <param name="Ev2CardCapabilities">The card capabilities, or null outside EV2.</param>
/// <param name="Ev2ReaderCapabilities">The reader capabilities, or null outside EV2.</param>
public sealed record DfcReaderSession(
    DfcSessionKind Kind,
    byte? KeyNo,
    ushort? Ev2CommandCounter,
    byte[]? Ev2TransactionIdentifier,
    byte[]? Ev2CardCapabilities,
    byte[]? Ev2ReaderCapabilities
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
    private const int Pending = (int)Native.DFC_FFI_READER_PENDING;
    private const int BufferTooSmall = (int)Native.DFC_FFI_READER_BUFFER_TOO_SMALL;
    private const int InitialFrameCapacity = 64;

    private readonly IDfcApduExchange transport;
    private readonly IDfcRandomSource random;
    private readonly DfcFraming framing;
    private readonly ReaderHandle session;
    private readonly ReaderHandle exchange;
    private byte[] frameBuffer = new byte[InitialFrameCapacity];

    /// <summary>Creates a reader over <paramref name="transport" />.</summary>
    public DfcReader(IDfcApduExchange transport, DfcFraming framing = DfcFraming.Iso7816, IDfcRandomSource? random = null)
    {
        ArgumentNullException.ThrowIfNull(transport);
        Native.EnsureCompatible();
        this.transport = transport;
        this.framing = framing;
        this.random = random ?? DfcSystemRandomSource.Instance;
        (this.session, this.exchange) = NewHandles();
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
            using var handles = this.AcquireHandles();
            NativeReaderState state;
            _ = Native.dfc_ffi_reader_session_state(handles.Session, &state);
            var authenticated = state.AuthMode != 0;
            var ev2 = state.AuthMode == Native.DFC_FFI_AUTH_EV2;
            return new DfcReaderSession(
                (DfcSessionKind)state.AuthMode,
                authenticated ? state.KeyNo : null,
                ev2 ? (ushort)state.Ev2CommandCounter : null,
                ev2 ? new ReadOnlySpan<byte>(state.Ev2TransactionIdentifier, 4).ToArray() : null,
                ev2 ? new ReadOnlySpan<byte>(state.Ev2CardCapabilities, 6).ToArray() : null,
                ev2 ? new ReadOnlySpan<byte>(state.Ev2ReaderCapabilities, 6).ToArray() : null
            );
        }
    }

    /// <summary>Whether the reader holds an authenticated session.</summary>
    public bool IsAuthenticated => this.Session.Kind != DfcSessionKind.None;

    /// <summary>Forgets the session, as the card does when it ends one.</summary>
    public void ClearSession()
    {
        using var handles = this.AcquireHandles();
        ClearSession(handles);
    }

    /// <summary>
    /// Exchanges one command under the session, following every additional frame. <paramref name="mode" /> is the
    /// communication mode of the file the command addresses. <paramref name="encryptedHeaderLength" /> overrides
    /// how many data octets stay clear when the field is encrypted.
    /// <c>null</c> (or -1) derives the head from the instruction. The value goes to the native library unchanged, which
    /// alone owns the bound (DFC_FFI_READER_MAX_CLEAR_HEADER_LENGTH); a refusal returns a failure of kind
    /// <see cref="DfcProtocolErrorKind.Invalid" />, leaving the session and this reader untouched.
    /// </summary>
    public async Task<Result<DfcResponse, DfcProtocolError>> ExchangeAsync(
        DfcCommand command,
        DfcCommunicationMode mode = DfcCommunicationMode.Plain,
        int? encryptedHeaderLength = null,
        CancellationToken cancellationToken = default
    )
    {
        ArgumentNullException.ThrowIfNull(command);
        using var handles = this.AcquireHandles();
        return await this.ExchangeAsync(handles, command, mode, encryptedHeaderLength, cancellationToken).ConfigureAwait(false);
    }

    private async Task<Result<DfcResponse, DfcProtocolError>> ExchangeAsync(
        ReaderHandles handles,
        DfcCommand command,
        DfcCommunicationMode mode,
        int? encryptedHeaderLength,
        CancellationToken cancellationToken
    )
    {
        var st = this.BeginExchange(handles, command, mode, encryptedHeaderLength ?? -1);
        return st == 0
            ? await this.RunAsync(handles, cancellationToken).ConfigureAwait(false)
            : Failure<DfcResponse>(handles, st);
    }

    /// <summary>Writes a caller-owned payload in bounded commands.</summary>
    public async Task<Result<DfcResponse, DfcProtocolError>> WriteDataAsync(
        byte fileNumber,
        uint offset,
        ReadOnlyMemory<byte> data,
        DfcCommunicationMode mode = DfcCommunicationMode.Plain,
        CancellationToken cancellationToken = default)
    {
        using var handles = this.AcquireHandles();
        using var pinned = data.Pin();
        int status;
        unsafe
        {
            status = Native.dfc_ffi_reader_write_data_begin(
                handles.Exchange, handles.Session, (uint)this.framing, fileNumber, offset,
                (byte*)pinned.Pointer, (nuint)data.Length, (byte)mode);
        }
        return status == 0
            ? await this.RunAsync(handles, cancellationToken).ConfigureAwait(false)
            : Failure<DfcResponse>(handles, status);
    }

    /// <summary>Writes one record across bounded commands; commit or abort the record afterward.</summary>
    public async Task<Result<DfcResponse, DfcProtocolError>> WriteRecordAsync(
        byte fileNumber,
        uint offset,
        ReadOnlyMemory<byte> data,
        DfcCommunicationMode mode = DfcCommunicationMode.Plain,
        CancellationToken cancellationToken = default)
    {
        using var handles = this.AcquireHandles();
        using var pinned = data.Pin();
        int status;
        unsafe
        {
            status = Native.dfc_ffi_reader_write_record_begin(
                handles.Exchange, handles.Session, (uint)this.framing, fileNumber, offset,
                (byte*)pinned.Pointer, (nuint)data.Length, (byte)mode);
        }
        return status == 0
            ? await this.RunAsync(handles, cancellationToken).ConfigureAwait(false)
            : Failure<DfcResponse>(handles, status);
    }

    /// <summary>Updates one record across bounded commands; commit or abort afterward.</summary>
    public async Task<Result<DfcResponse, DfcProtocolError>> UpdateRecordAsync(
        byte fileNumber,
        uint recordNumber,
        uint offset,
        ReadOnlyMemory<byte> data,
        DfcCommunicationMode mode = DfcCommunicationMode.Plain,
        CancellationToken cancellationToken = default)
    {
        using var handles = this.AcquireHandles();
        using var pinned = data.Pin();
        int status;
        unsafe
        {
            status = Native.dfc_ffi_reader_update_record_begin(
                handles.Exchange, handles.Session, (uint)this.framing, fileNumber, recordNumber, offset,
                (byte*)pinned.Pointer, (nuint)data.Length, (byte)mode);
        }
        return status == 0
            ? await this.RunAsync(handles, cancellationToken).ConfigureAwait(false)
            : Failure<DfcResponse>(handles, status);
    }

    private unsafe int BeginExchange(
        ReaderHandles handles,
        DfcCommand command,
        DfcCommunicationMode mode,
        int headerLength
    )
    {
        fixed (byte* d = command.Data.Span)
        {
            return Native.dfc_ffi_reader_exchange_begin(
                handles.Exchange,
                handles.Session,
                (uint)this.framing,
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
    )
    {
        return command.IsFailure
            ? command.Error
            : await this.ExchangeAsync(command.Value, mode, null, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>D40, native ISO or native AES authentication with one key.</summary>
    public async Task<UnitResult<DfcProtocolError>> AuthenticateAsync(
        DfcAuthenticationMode mode,
        byte keyNo,
        ReadOnlyMemory<byte> key,
        CancellationToken cancellationToken = default
    )
    {
        var challengeLength = NativeAuthenticationChallengeLength(mode, key.Length);
        if (challengeLength is null)
        {
            return new DfcProtocolError(DfcProtocolErrorKind.Invalid, "The authentication mode and key length are incompatible.");
        }

        using var handles = this.AcquireHandles();
        var randomA = new byte[challengeLength.Value];
        this.random.Fill(randomA);
        var st = this.BeginAuthenticate(handles, mode, keyNo, key, randomA);
        CryptographicZero(randomA);
        if (st != 0)
        {
            return Failure<DfcResponse>(handles, st).Error;
        }

        var result = await this.RunAsync(handles, cancellationToken).ConfigureAwait(false);
        return result.IsSuccess ? UnitResult.Success<DfcProtocolError>() : result.Error;
    }

    internal static int? NativeAuthenticationChallengeLength(DfcAuthenticationMode mode, int keyLength)
    {
        return (mode, keyLength) switch
        {
            (DfcAuthenticationMode.D40, 8 or 16) => 8,
            (DfcAuthenticationMode.Iso, 8 or 16) => 8,
            (DfcAuthenticationMode.Iso, 24) => 16,
            (DfcAuthenticationMode.Aes, 16) => 16,
            _ => null,
        };
    }

    private unsafe int BeginAuthenticate(
        ReaderHandles handles,
        DfcAuthenticationMode mode,
        byte keyNo,
        ReadOnlyMemory<byte> key,
        byte[] randomA
    )
    {
        fixed (byte* k = key.Span)
        fixed (byte* r = randomA)
        {
            return Native.dfc_ffi_reader_authenticate_begin(
                handles.Exchange,
                handles.Session,
                (uint)this.framing,
                (byte)mode,
                keyNo,
                k,
                (nuint)key.Length,
                r,
                (nuint)randomA.Length
            );
        }
    }

    /// <summary>Runs standard ISO 7816 mutual authentication with a PICC or application key reference.</summary>
    public async Task<UnitResult<DfcProtocolError>> AuthenticateIso7816Async(
        byte keyReference,
        DfcIso7816AuthAlgorithm algorithm,
        ReadOnlyMemory<byte> key,
        CancellationToken cancellationToken = default)
    {
        using var handles = this.AcquireHandles();
        var challengeLength = algorithm == DfcIso7816AuthAlgorithm.Tdea2 ? 8 : 16;
        var randomFirst = new byte[challengeLength];
        var randomSecond = new byte[challengeLength];
        this.random.Fill(randomFirst);
        this.random.Fill(randomSecond);
        int status;
        unsafe
        {
            fixed (byte* k = key.Span)
            fixed (byte* first = randomFirst)
            fixed (byte* second = randomSecond)
            {
                status = Native.dfc_ffi_reader_authenticate_iso7816_begin(
                    handles.Exchange, handles.Session, keyReference, k, (nuint)key.Length,
                    (byte)algorithm, first, second, (nuint)challengeLength);
            }
        }
        CryptographicZero(randomFirst);
        CryptographicZero(randomSecond);
        if (status != 0)
        {
            return Failure<DfcResponse>(handles, status).Error;
        }

        var result = await this.RunAsync(handles, cancellationToken).ConfigureAwait(false);
        return result.IsSuccess ? UnitResult.Success<DfcProtocolError>() : result.Error;
    }

    /// <summary>EV2 first authentication with a 16-octet AES key, optionally carrying six octets of reader capabilities.</summary>
    public Task<UnitResult<DfcProtocolError>> AuthenticateEv2FirstAsync(
        byte keyNo,
        ReadOnlyMemory<byte> key,
        ReadOnlyMemory<byte> capabilities = default,
        CancellationToken cancellationToken = default
    )
    {
        return this.AuthenticateEv2Async(true, keyNo, key, capabilities, cancellationToken);
    }

    /// <summary>EV2 non-first authentication, keeping the open transaction.</summary>
    public Task<UnitResult<DfcProtocolError>> AuthenticateEv2NonFirstAsync(
        byte keyNo,
        ReadOnlyMemory<byte> key,
        CancellationToken cancellationToken = default
    )
    {
        return this.AuthenticateEv2Async(false, keyNo, key, ReadOnlyMemory<byte>.Empty, cancellationToken);
    }

    /// <summary>
    /// ChangeKey under a D40, native ISO or native AES session. <paramref name="currentKey" /> is needed unless the key is the
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
        using var handles = this.AcquireHandles();
        var (st, cryptogram) = this.BuildCryptogram(handles, keyNo, newKey, currentKey, aesKey, newVersion);
        if (st != 0)
        {
            return Failure<DfcResponse>(handles, st).Error;
        }

        var data = new byte[1 + cryptogram.Length];
        data[0] = keyNo;
        cryptogram.CopyTo(data.AsSpan(1));
        var result = await this.ExchangeAsync(handles, new DfcCommand(0xC4, data), DfcCommunicationMode.Plain, null, cancellationToken)
            .ConfigureAwait(false);
        return result.IsSuccess ? UnitResult.Success<DfcProtocolError>() : result.Error;
    }

    private unsafe (int Status, byte[] Cryptogram) BuildCryptogram(
        ReaderHandles handles,
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
            var st = Native.dfc_ffi_reader_change_key_cryptogram(
                handles.Session,
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
        using var handles = this.AcquireHandles();
        var (st, data) = this.BuildChangeKeyEv2(handles, keySetNo, keyNo, newKey, currentKey, newVersion);
        if (st != 0)
        {
            return Failure<DfcResponse>(handles, st).Error;
        }

        var result = await this.ExchangeAsync(
                handles,
                new DfcCommand(0xC6, data),
                DfcCommunicationMode.Plain,
                null,
                cancellationToken
            )
            .ConfigureAwait(false);
        return result.IsSuccess ? UnitResult.Success<DfcProtocolError>() : result.Error;
    }

    private unsafe (int Status, byte[] Data) BuildChangeKeyEv2(
        ReaderHandles handles,
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
            var st = Native.dfc_ffi_reader_change_key_ev2_data(
                handles.Session,
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

        using var handles = this.AcquireHandles();
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
        this.random.Fill(prefix);
        var st = this.BeginDelegated(handles, header, request, prefix);
        if (st != 0)
        {
            return Failure<DfcResponse>(handles, st).Error;
        }

        var result = await this.RunAsync(handles, cancellationToken).ConfigureAwait(false);
        return result.IsSuccess ? UnitResult.Success<DfcProtocolError>() : result.Error;
    }

    private unsafe int BeginDelegated(
        ReaderHandles handles,
        byte[] header,
        DfcDelegatedApplicationRequest request,
        byte[] prefix
    )
    {
        fixed (byte* h = header)
        fixed (byte* e = request.DamEncryptionKey)
        fixed (byte* m = request.DamMacKey)
        fixed (byte* p = prefix)
        fixed (byte* k = request.InitialKey)
        {
            return Native.dfc_ffi_reader_create_delegated_application_begin(
                handles.Exchange,
                handles.Session,
                (uint)this.framing,
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

        using var handles = this.AcquireHandles();
        var prepared = await this.ExchangeAsync(
                handles,
                new DfcCommand(0xF0, ReadOnlyMemory<byte>.Empty),
                DfcCommunicationMode.Plain,
                null,
                cancellationToken
            )
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
            this.random.Fill(challenge);
            var data = new byte[perRound + 1];
            data[0] = (byte)perRound;
            challenge.CopyTo(data, 1);
            var started = Stopwatch.GetTimestamp();
            var answer = await this.ExchangeAsync(
                    handles,
                    new DfcCommand(0xF2, data),
                    DfcCommunicationMode.Plain,
                    null,
                    cancellationToken
                )
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
        var verify = await this.ExchangeAsync(
                handles,
                new DfcCommand(0xFD, mac),
                DfcCommunicationMode.Plain,
                null,
                cancellationToken
            )
            .ConfigureAwait(false);
        if (verify.IsFailure)
        {
            return verify.Error;
        }

        var expected = ProximityMac(key.Span, fromCard: true, published, transcriptBytes);
        return NativeCrypto.FixedTimeEquals(expected, verify.Value.Data)
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

        using var handles = this.AcquireHandles();
        var select = new byte[installationId.Length + 6];
        select[1] = 0xA4;
        select[2] = 0x04;
        select[4] = (byte)installationId.Length;
        installationId.Span.CopyTo(select.AsSpan(5));
        var answer = await this.TransmitAsync(handles, select, cancellationToken).ConfigureAwait(false);
        if (answer.IsFailure)
        {
            return answer.Error;
        }

        var (st, clear, authenticate) = OpenVirtualCard(answer.Value, selectEncryptionKey, selectMacKey);
        if (st != 0)
        {
            return Failure<DfcVirtualCardSelection>(handles, st).Error;
        }

        var confirmed = await this.TransmitAsync(handles, authenticate, cancellationToken).ConfigureAwait(false);
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
            var st = Native.dfc_reader_virtual_card_open(k, r, (nuint)answer.Length, c, d);
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
        CryptographicZero(this.frameBuffer);
        this.exchange.Dispose();
        this.session.Dispose();
    }

    // ---------------------------------------------------------- plumbing ---

    private ReaderHandles AcquireHandles()
    {
        return new(this.session, this.exchange);
    }

    private static void ClearSession(ReaderHandles handles)
    {
        Native.dfc_ffi_reader_session_clear(handles.Session);
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

        using var handles = this.AcquireHandles();
        var randomA = new byte[16];
        this.random.Fill(randomA);
        var st = this.BeginAuthenticateEv2(handles, first, keyNo, key, randomA, capabilities);
        CryptographicZero(randomA);
        if (st != 0)
        {
            return Failure<DfcResponse>(handles, st).Error;
        }

        var result = await this.RunAsync(handles, cancellationToken).ConfigureAwait(false);
        return result.IsSuccess ? UnitResult.Success<DfcProtocolError>() : result.Error;
    }

    private unsafe int BeginAuthenticateEv2(
        ReaderHandles handles,
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
                handles.Exchange,
                handles.Session,
                (uint)this.framing,
                first ? (byte)1 : (byte)0,
                keyNo,
                k,
                r,
                capabilities.Length == 0 ? null : c,
                (nuint)capabilities.Length
            );
        }
    }

    private async Task<Result<DfcResponse, DfcProtocolError>> RunAsync(
        ReaderHandles handles,
        CancellationToken cancellationToken
    )
    {
        byte[]? answer = null;
        var frame = this.frameBuffer;
        while (true)
        {
            var (status, frameLength) = this.Step(handles, answer, frame);
            if (status == BufferTooSmall && frameLength > frame.Length)
            {
                CryptographicZero(frame);
                frame = new byte[frameLength];
                this.frameBuffer = frame;
                continue;
            }

            if (status != Pending)
            {
                CryptographicZero(frame);
                return status == 0 ? this.Collect(handles) : Failure<DfcResponse>(handles, status);
            }

            Result<byte[], DfcProtocolError> sent;
            try
            {
                sent = await this.TransmitAsync(
                    handles,
                    frame.AsMemory(0, frameLength),
                    cancellationToken
                ).ConfigureAwait(false);
            }
            finally
            {
                CryptographicZero(frame);
            }
            if (sent.IsFailure)
            {
                ClearSession(handles);
                return sent.Error;
            }

            answer = sent.Value;
        }
    }

    private async ValueTask<Result<byte[], DfcProtocolError>> TransmitAsync(
        ReaderHandles handles,
        ReadOnlyMemory<byte> frame,
        CancellationToken cancellationToken
    )
    {
        try
        {
            return await this.transport.TransmitAsync(frame, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            ClearSession(handles);
            throw;
        }
    }

    private unsafe (int Status, int FrameLength) Step(
        ReaderHandles handles,
        byte[]? answer,
        byte[] frame
    )
    {
        nuint length;
        int st;
        fixed (byte* a = answer)
        fixed (byte* f = frame)
        {
            st = Native.dfc_ffi_reader_step(
                handles.Exchange,
                a,
                (nuint)(answer?.Length ?? 0),
                f,
                (nuint)frame.Length,
                &length
            );
        }

        return (st, st is Pending or BufferTooSmall ? checked((int)length) : 0);
    }

    private unsafe Result<DfcResponse, DfcProtocolError> Collect(ReaderHandles handles)
    {
        nuint length;
        var st = Native.dfc_ffi_reader_result_data(handles.Exchange, null, 0, &length);
        if (st != 0)
        {
            return Failure<DfcResponse>(handles, st);
        }

        var data = new byte[checked((int)length)];
        byte empty = 0;
        fixed (byte* d = data)
        {
            st = Native.dfc_ffi_reader_result_data(
                handles.Exchange,
                data.Length == 0 ? &empty : d,
                (nuint)data.Length,
                &length
            );
        }

        return st == 0
            ? new DfcResponse(Native.dfc_ffi_reader_result_status(handles.Exchange), data)
            : Failure<DfcResponse>(handles, st);
    }

    private static Result<T, DfcProtocolError> Failure<T>(ReaderHandles handles, int status)
    {
        return DfcProtocolError.FromReaderStatus(status, Native.dfc_ffi_reader_result_status(handles.Exchange));
    }

    private static unsafe byte[] ProximityMac(ReadOnlySpan<byte> key, bool fromCard, byte[] published, byte[] transcript)
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

    private static void CryptographicZero(byte[] buffer)
    {
        NativeCrypto.Zero(buffer);
    }

    private static void Allocate(int status)
    {
        if (status != 0)
        {
            throw new InsufficientMemoryException("The native reader could not be allocated.");
        }
    }

    private readonly struct ReaderHandles : IDisposable
    {
        private readonly ReaderHandle sessionHandle;
        private readonly ReaderHandle exchangeHandle;

        public ReaderHandles(ReaderHandle session, ReaderHandle exchange)
        {
            var sessionAdded = false;
            var exchangeAdded = false;
            try
            {
                session.DangerousAddRef(ref sessionAdded);
                exchange.DangerousAddRef(ref exchangeAdded);
                this.sessionHandle = session;
                this.exchangeHandle = exchange;
                this.Session = session.DangerousGetHandle();
                this.Exchange = exchange.DangerousGetHandle();
            }
            catch (ObjectDisposedException)
            {
                if (exchangeAdded)
                {
                    exchange.DangerousRelease();
                }
                if (sessionAdded)
                {
                    session.DangerousRelease();
                }
                throw new ObjectDisposedException(nameof(DfcReader));
            }
        }

        public nint Session { get; }

        public nint Exchange { get; }

        public void Dispose()
        {
            this.exchangeHandle.DangerousRelease();
            this.sessionHandle.DangerousRelease();
        }
    }

    private sealed unsafe class ReaderHandle : SafeHandle
    {
        private readonly delegate*<nint, void> free;

        public ReaderHandle(nint value, delegate*<nint, void> free)
            : base(IntPtr.Zero, ownsHandle: true)
        {
            this.free = free;
            this.SetHandle(value);
        }

        public override bool IsInvalid => this.handle == IntPtr.Zero;

        protected override bool ReleaseHandle()
        {
            this.free(this.handle);
            return true;
        }
    }
}
