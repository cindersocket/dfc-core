namespace Dfc.Crypto;

using System;
using System.Security.Cryptography;
using CSharpFunctionalExtensions;
using Dfc.Interop;

/// <summary>Algorithms supported by the AN10922 key-diversification helper.</summary>
public enum DfcDiversificationAlgorithm : uint
{
    /// <summary>AES-128 diversification, producing a 16-byte key.</summary>
    Aes128 = 0,

    /// <summary>Two-key TDEA diversification, producing a 16-byte key.</summary>
    TwoKeyTdea = 1,

    /// <summary>Three-key TDEA diversification, producing a 24-byte key.</summary>
    ThreeKeyTdea = 2,
}

/// <summary>Derives application keys without exposing the native KDF details.</summary>
public static unsafe class DfcKeyDiversification
{
    private const int MaximumDiversifiedKeyLength = 24;

    /// <summary>Derives a DESFire application key from a master key and diversification input.</summary>
    /// <param name="algorithm">Key algorithm and output size.</param>
    /// <param name="masterKey">Master key whose length must match <paramref name="algorithm"/>.</param>
    /// <param name="input">Diversification data: 1–31 bytes for AES-128 or 1–15 bytes for TDEA.</param>
    /// <returns>A newly allocated diversified key, or a native validation or cryptographic error.</returns>
    /// <remarks>TDEA output preserves the version bits encoded in the first eight bytes of the master key.</remarks>
    public static Result<byte[], DfcError> Diversify(
        DfcDiversificationAlgorithm algorithm,
        ReadOnlySpan<byte> masterKey,
        ReadOnlySpan<byte> input)
    {
        Native.EnsureCompatible();
        Span<byte> output = stackalloc byte[MaximumDiversifiedKeyLength];
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
