namespace Dfc;

/// <summary>Why a credential could not be read, written or built.</summary>
public enum DfcErrorClass
{
    /// <summary>The input breaks the encoding or a rule of the model.</summary>
    Malformed = 1,

    /// <summary>The input is sound but names something the native build omits.</summary>
    Unsupported = 2,

    /// <summary>The input is sound but larger than the native build can hold.</summary>
    Capacity = 3,

    /// <summary>An argument was out of range before any input was examined.</summary>
    InvalidArgument = 10,

    /// <summary>The native library ran out of memory.</summary>
    OutOfMemory = 11,
}

/// <summary>A credential failure, with the line of a text document where one applies.</summary>
/// <param name="Class">The failure class; conformance is on the class, not the message.</param>
/// <param name="Message">A description for people.</param>
/// <param name="Line">The 1-based line of a text failure, or 0.</param>
public sealed record DfcError(DfcErrorClass Class, string Message, int Line = 0)
{
    internal static DfcError FromStatus(int status, string? message = null, int line = 0) =>
        new(ClassOf(status), message ?? DescribeStatus(status), line);

    private static DfcErrorClass ClassOf(int status) =>
        status switch
        {
            1 => DfcErrorClass.Malformed,
            2 or Interop.Native.Unsupported => DfcErrorClass.Unsupported,
            3 => DfcErrorClass.Capacity,
            Interop.Native.OutOfMemory => DfcErrorClass.OutOfMemory,
            _ => DfcErrorClass.InvalidArgument,
        };

    private static string DescribeStatus(int status) =>
        status switch
        {
            1 => "malformed",
            2 or Interop.Native.Unsupported => "unsupported by this build",
            3 => "exceeds this build's capacity",
            Interop.Native.OutOfMemory => "out of memory",
            _ => "invalid argument",
        };
}
