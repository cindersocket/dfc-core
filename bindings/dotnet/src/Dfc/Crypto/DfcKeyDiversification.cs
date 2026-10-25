namespace Dfc.Crypto;

#pragma warning disable CS1591 // Public API is documented at the operation level below.

using System;
using System.Security.Cryptography;
using CSharpFunctionalExtensions;
using Dfc.Interop;

/// <summary>Algorithms supported by the AN10922 key-diversification helper.</summary>
public enum DfcDiversificationAlgorithm : uint
{
    Aes128 = 0,
    TwoKeyTdea = 1,
    ThreeKeyTdea = 2,
}
#pragma warning restore CS1591

/// <summary>Derives application keys without exposing the native KDF details.</summary>
public static unsafe class DfcKeyDiversification
{
    /// <summary>Derives a key from the master key and diversification input.</summary>
    public static Result<byte[], DfcError> Diversify(
        DfcDiversificationAlgorithm algorithm,
        ReadOnlySpan<byte> masterKey,
        ReadOnlySpan<byte> input)
    {
        Native.EnsureCompatible();
        Span<byte> output = stackalloc byte[24];
        nuint length = 0;
        int status;
        fixed (byte* master = masterKey)
        fixed (byte* data = input)
        fixed (byte* result = output)
        {
            status = Native.dfc_ffi_an10922_diversify((uint)algorithm, master,
                (nuint)masterKey.Length, data, (nuint)input.Length, result,
                (nuint)output.Length, &length);
        }

        try
        {
            return status == Native.ResponseOk
                ? output[..(int)length].ToArray()
                : DfcError.FromStatus(status, "key diversification failed");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(output);
        }
    }
}
