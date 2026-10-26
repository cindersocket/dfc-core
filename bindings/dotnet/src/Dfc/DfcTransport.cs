namespace Dfc;

using System;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Dfc.Interop;

/// <summary>What went wrong in an exchange with a card.</summary>
public enum DfcProtocolErrorKind
{
    /// <summary>An argument was out of range, or the operation does not fit the session.</summary>
    Invalid = (int)Native.DFC_FFI_READER_INVALID,

    /// <summary>A buffer or a bound of the native library was too small.</summary>
    BufferTooSmall = (int)Native.DFC_FFI_READER_BUFFER_TOO_SMALL,

    /// <summary>The card's answer was malformed or unexpected.</summary>
    Protocol = (int)Native.DFC_FFI_READER_PROTOCOL_ERROR,

    /// <summary>A MAC, a CRC or a returned challenge did not verify.</summary>
    Integrity = (int)Native.DFC_FFI_READER_INTEGRITY_ERROR,

    /// <summary>The card answered with an error status; see <see cref="DfcProtocolError.CardStatus" />.</summary>
    CardStatus = (int)Native.DFC_FFI_READER_CARD_ERROR,

    /// <summary>The native build does not carry what the operation needs.</summary>
    Unsupported = (int)Native.DFC_FFI_READER_UNSUPPORTED,

    /// <summary>The virtual card's random source could not fill a request.</summary>
    RandomSource = 8,

    /// <summary>The transport failed to deliver a frame.</summary>
    Transport = 100,

    /// <summary>No card is in the field.</summary>
    NoCard = 101,
}

/// <summary>A failed exchange.</summary>
/// <param name="Kind">The kind of failure.</param>
/// <param name="Message">A description for people.</param>
/// <param name="CardStatus">The card's native status, when it answered with one.</param>
public sealed record DfcProtocolError(DfcProtocolErrorKind Kind, string Message, byte CardStatus = 0)
{
    /// <summary>A transport failure.</summary>
    public static DfcProtocolError Transport(string message) => new(DfcProtocolErrorKind.Transport, message);

    internal static DfcProtocolError FromReaderStatus(int status, byte cardStatus) =>
        status switch
        {
            (int)Native.DFC_FFI_READER_CARD_ERROR => new(DfcProtocolErrorKind.CardStatus, $"The card answered with status {cardStatus:X2}.", cardStatus),
            (int)Native.DFC_FFI_READER_INTEGRITY_ERROR => new(DfcProtocolErrorKind.Integrity, "A MAC, CRC or challenge from the card did not verify."),
            (int)Native.DFC_FFI_READER_PROTOCOL_ERROR => new(DfcProtocolErrorKind.Protocol, "The card's answer was malformed or unexpected."),
            (int)Native.DFC_FFI_READER_BUFFER_TOO_SMALL or Interop.Native.BufferTooSmall => new(DfcProtocolErrorKind.BufferTooSmall, "The exchange exceeds a bound of the native library."),
            (int)Native.DFC_FFI_READER_UNSUPPORTED or Interop.Native.Unsupported => new(DfcProtocolErrorKind.Unsupported, "The native library was built without this feature."),
            _ => new(DfcProtocolErrorKind.Invalid, "The operation does not fit its arguments or the session."),
        };
}

/// <summary>Anything that carries one command frame to a card and brings its answer back.</summary>
public interface IDfcApduExchange
{
    /// <summary>Sends one frame and returns the card's answer.</summary>
    ValueTask<Result<byte[], DfcProtocolError>> TransmitAsync(ReadOnlyMemory<byte> frame, CancellationToken cancellationToken);
}

/// <summary>Unpredictable octets for challenges.</summary>
public interface IDfcRandomSource
{
    /// <summary>Fills <paramref name="destination" /> with unpredictable octets.</summary>
    void Fill(Span<byte> destination);
}

/// <summary>The operating system's cryptographic generator.</summary>
public sealed class DfcSystemRandomSource : IDfcRandomSource
{
    /// <summary>The shared instance.</summary>
    public static DfcSystemRandomSource Instance { get; } = new();

    /// <inheritdoc />
    public void Fill(Span<byte> destination) => NativeCrypto.Fill(destination);
}

/// <summary>A fixed sequence of octets, for tests that replay a recorded session.</summary>
public sealed class DfcScriptedRandomSource : IDfcRandomSource
{
    private readonly object gate = new();
    private byte[] buffer;
    private int offset;
    private int count;

    /// <summary>Creates a queue initialized with <paramref name="script" />.</summary>
    public DfcScriptedRandomSource(ReadOnlyMemory<byte> script)
    {
        buffer = script.ToArray();
        count = buffer.Length;
    }

    /// <summary>Octets not yet handed out.</summary>
    public int Remaining
    {
        get { lock (gate) return count - offset; }
    }

    /// <summary>Appends octets that become visible to the next random request.</summary>
    public void Append(ReadOnlySpan<byte> bytes)
    {
        lock (gate)
        {
            var remaining = count - offset;
            if (offset != 0)
            {
                buffer.AsSpan(offset, remaining).CopyTo(buffer);
                CryptographicOperations.ZeroMemory(buffer.AsSpan(remaining, count - remaining));
                offset = 0;
                count = remaining;
            }
            var required = checked(remaining + bytes.Length);
            if (required > buffer.Length)
            {
                var doubled = buffer.Length <= int.MaxValue / 2 ? buffer.Length * 2 : required;
                var grown = new byte[Math.Max(required, Math.Max(16, doubled))];
                buffer.AsSpan(0, remaining).CopyTo(grown);
                CryptographicOperations.ZeroMemory(buffer);
                buffer = grown;
            }
            bytes.CopyTo(buffer.AsSpan(count));
            count += bytes.Length;
        }
    }

    /// <summary>Discards and wipes every unread octet.</summary>
    public void Clear()
    {
        lock (gate)
        {
            CryptographicOperations.ZeroMemory(buffer);
            offset = 0;
            count = 0;
        }
    }

    /// <inheritdoc />
    public void Fill(Span<byte> destination)
    {
        lock (gate)
        {
            if (destination.Length > count - offset)
            {
                throw new InvalidOperationException("The scripted random source is exhausted.");
            }

            buffer.AsSpan(offset, destination.Length).CopyTo(destination);
            CryptographicOperations.ZeroMemory(buffer.AsSpan(offset, destination.Length));
            offset += destination.Length;
            if (offset == count)
            {
                offset = 0;
                count = 0;
            }
        }
    }
}
