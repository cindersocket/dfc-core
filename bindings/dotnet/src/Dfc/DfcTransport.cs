namespace Dfc;

using System;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;

/// <summary>What went wrong in an exchange with a card.</summary>
public enum DfcProtocolErrorKind
{
    /// <summary>An argument was out of range, or the operation does not fit the session.</summary>
    Invalid = 2,

    /// <summary>A buffer or a bound of the native library was too small.</summary>
    BufferTooSmall = 3,

    /// <summary>The card's answer was malformed or unexpected.</summary>
    Protocol = 4,

    /// <summary>A MAC, a CRC or a returned challenge did not verify.</summary>
    Integrity = 5,

    /// <summary>The card answered with an error status; see <see cref="DfcProtocolError.CardStatus" />.</summary>
    CardStatus = 6,

    /// <summary>The native build does not carry what the operation needs.</summary>
    Unsupported = 7,

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
            6 => new(DfcProtocolErrorKind.CardStatus, $"The card answered with status {cardStatus:X2}.", cardStatus),
            5 => new(DfcProtocolErrorKind.Integrity, "A MAC, CRC or challenge from the card did not verify."),
            4 => new(DfcProtocolErrorKind.Protocol, "The card's answer was malformed or unexpected."),
            3 or Interop.Native.BufferTooSmall => new(DfcProtocolErrorKind.BufferTooSmall, "The exchange exceeds a bound of the native library."),
            7 or Interop.Native.Unsupported => new(DfcProtocolErrorKind.Unsupported, "The native library was built without this feature."),
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
    public void Fill(Span<byte> destination) => RandomNumberGenerator.Fill(destination);
}

/// <summary>A fixed sequence of octets, for tests that replay a recorded session.</summary>
public sealed class DfcScriptedRandomSource(ReadOnlyMemory<byte> script) : IDfcRandomSource
{
    private int offset;

    /// <summary>Octets not yet handed out.</summary>
    public int Remaining => script.Length - offset;

    /// <inheritdoc />
    public void Fill(Span<byte> destination)
    {
        var available = Math.Min(destination.Length, Remaining);
        script.Span.Slice(offset, available).CopyTo(destination);
        destination[available..].Clear();
        offset += available;
    }
}
