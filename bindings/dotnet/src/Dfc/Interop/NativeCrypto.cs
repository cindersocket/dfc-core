namespace Dfc.Interop;

using System;

internal static unsafe class NativeCrypto
{
    internal static void Fill(Span<byte> destination)
    {
        Native.EnsureCompatible();
        fixed (byte* output = destination)
        {
            if (Native.dfc_ffi_random_fill(output, (nuint)destination.Length) != 0)
            {
                throw new InvalidOperationException("The native random generator rejected its buffer.");
            }
        }
    }

    internal static bool FixedTimeEquals(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
    {
        if (left.Length != right.Length)
        {
            return false;
        }

        Native.EnsureCompatible();
        fixed (byte* leftBytes = left)
        fixed (byte* rightBytes = right)
        {
            return Native.dfc_ffi_fixed_time_equal(leftBytes, rightBytes, (nuint)left.Length);
        }
    }

    internal static void Zero(Span<byte> buffer)
    {
        Native.EnsureCompatible();
        fixed (byte* bytes = buffer)
        {
            Native.dfc_ffi_secure_zero(bytes, (nuint)buffer.Length);
        }
    }
}
