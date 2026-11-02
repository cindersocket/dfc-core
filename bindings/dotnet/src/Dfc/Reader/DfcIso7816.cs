using System;

namespace Dfc.Reader;

/// <summary>Helpers for standard ISO/IEC 7816 APDUs used alongside native DESFire commands.</summary>
public static class DfcIso7816
{
    /// <summary>Builds an ISO APPEND RECORD command APDU.</summary>
    /// <param name="shortFileId">Zero for the current file, or an SFI from 1 through 30.</param>
    /// <param name="data">Record data to append.</param>
    /// <returns>The complete command APDU.</returns>
    /// <exception cref="ArgumentOutOfRangeException">The SFI or data length is invalid.</exception>
    public static byte[] BuildAppendRecord(byte shortFileId, ReadOnlySpan<byte> data)
    {
        if (shortFileId > 0x1e)
            throw new ArgumentOutOfRangeException(nameof(shortFileId));
        if (data.IsEmpty || data.Length > ushort.MaxValue)
            throw new ArgumentOutOfRangeException(nameof(data));

        var headerLength = data.Length <= byte.MaxValue ? 5 : 7;
        var apdu = new byte[headerLength + data.Length];
        apdu[1] = 0xe2;
        apdu[3] = (byte)(shortFileId << 3);
        if (headerLength == 5)
        {
            apdu[4] = (byte)data.Length;
        }
        else
        {
            apdu[5] = (byte)(data.Length >> 8);
            apdu[6] = (byte)data.Length;
        }
        data.CopyTo(apdu.AsSpan(headerLength));
        return apdu;
    }

    /// <summary>Splits an ISO response APDU into response data and its two-byte status word.</summary>
    /// <param name="response">Complete response APDU.</param>
    /// <returns>Copied response data and the unsigned status word.</returns>
    /// <exception cref="ArgumentException">The response has no status word.</exception>
    public static DfcIso7816Response ParseResponse(ReadOnlySpan<byte> response)
    {
        if (response.Length < 2)
            throw new ArgumentException("ISO response must include SW1 and SW2.", nameof(response));
        return new DfcIso7816Response(
            response[..^2].ToArray(),
            (ushort)((response[^2] << 8) | response[^1])
        );
    }
}

/// <summary>A standard ISO response APDU after status-word separation.</summary>
/// <param name="Data">Response data without SW1 and SW2.</param>
/// <param name="StatusWord">The unsigned two-byte ISO status word.</param>
public readonly record struct DfcIso7816Response(ReadOnlyMemory<byte> Data, ushort StatusWord);
