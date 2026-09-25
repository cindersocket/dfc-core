namespace Dfc.Credentials;

using System;
using System.Text;
using CSharpFunctionalExtensions;
using Dfc.Interop;

/// <summary>
/// Reads and writes credentials in both encodings: the <c>.dfc</c> text a person authors and the <c>.dfcb</c>
/// octets a card loads. Parsing, validation and encoding all run in the native library, so the rules here are
/// exactly the rules a device applies.
/// </summary>
public static unsafe class DfcCredentialCodec
{
    /// <summary>The octet every binary credential opens with.</summary>
    public const byte BinaryTag = 0x60;

    /// <summary>Parses a <c>.dfc</c> text document.</summary>
    public static Result<DfcCredential, DfcError> Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        var bytes = Encoding.UTF8.GetBytes(text);
        return Read(bytes, static (p, n, h, e) => Native.dfc_ffi_credential_parse_text(p, n, h, e));
    }

    /// <summary>Decodes <c>.dfcb</c> octets.</summary>
    public static Result<DfcCredential, DfcError> Decode(ReadOnlySpan<byte> octets) =>
        Read(octets, static (p, n, h, e) => Native.dfc_ffi_credential_decode(p, n, h, e));

    /// <summary>Reads either encoding, telling them apart by the first octet.</summary>
    public static Result<DfcCredential, DfcError> Load(ReadOnlySpan<byte> content) =>
        Read(content, static (p, n, h, e) => Native.dfc_ffi_credential_load(p, n, h, e));

    /// <summary>Whether <paramref name="content" /> is the binary encoding.</summary>
    public static bool IsBinary(ReadOnlySpan<byte> content) => content.Length > 0 && content[0] == BinaryTag;

    /// <summary>Encodes a credential as <c>.dfcb</c> octets.</summary>
    public static Result<byte[], DfcError> Encode(DfcCredential credential) =>
        WithHandle(credential, static raw =>
        {
            nuint length = 0;
            int st = Native.dfc_ffi_credential_encode(raw, null, 0, &length);
            if (st != 0)
            {
                return DfcError.FromStatus(st);
            }

            var output = new byte[(int)length];
            fixed (byte* p = output)
            {
                st = Native.dfc_ffi_credential_encode(raw, p, length, &length);
            }

            return st == 0 ? Result.Success<byte[], DfcError>(output) : DfcError.FromStatus(st);
        });

    /// <summary>Writes a credential as canonical <c>.dfc</c> text.</summary>
    public static Result<string, DfcError> WriteText(DfcCredential credential) =>
        WithHandle(credential, static raw =>
        {
            nuint length = 0;
            int st = Native.dfc_ffi_credential_write_text(raw, null, 0, &length);
            if (st != 0)
            {
                return DfcError.FromStatus(st);
            }

            var output = new byte[(int)length];
            fixed (byte* p = output)
            {
                st = Native.dfc_ffi_credential_write_text(raw, p, length, &length);
            }

            return st == 0
                ? Result.Success<string, DfcError>(Encoding.UTF8.GetString(output, 0, (int)length))
                : DfcError.FromStatus(st);
        });

    /// <summary>Checks every rule both encodings share, without encoding.</summary>
    public static UnitResult<DfcError> Validate(DfcCredential credential)
    {
        var written = CredentialMarshaller.Write(credential);
        if (written.IsFailure)
        {
            return written.Error;
        }

        written.Value.Dispose();
        return UnitResult.Success<DfcError>();
    }

    private delegate int NativeReader(byte* content, nuint length, nint* output, NativeError* error);

    private static Result<DfcCredential, DfcError> Read(ReadOnlySpan<byte> content, NativeReader read)
    {
        Native.EnsureCompatible();
        nint raw;
        NativeError error;
        int st;
        fixed (byte* p = content)
        {
            st = read(p, (nuint)content.Length, &raw, &error);
        }

        if (st != 0)
        {
            return CredentialMarshaller.ToError(in error, st);
        }

        using var handle = new CredentialHandle(raw);
        return CredentialMarshaller.Read(handle);
    }

    private static Result<T, DfcError> WithHandle<T>(DfcCredential credential, Func<nint, Result<T, DfcError>> use)
    {
        var written = CredentialMarshaller.Write(credential);
        if (written.IsFailure)
        {
            return written.Error;
        }

        using var handle = written.Value;
        bool added = false;
        handle.DangerousAddRef(ref added);
        try
        {
            return use(handle.DangerousGetHandle());
        }
        finally
        {
            if (added)
            {
                handle.DangerousRelease();
            }
        }
    }
}
