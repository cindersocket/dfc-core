namespace Dfc.Tests;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Dfc.Credentials;
using Dfc.Emulation;
using Dfc.Reader;
using NUnit.Framework;

internal static class Fixtures
{
    public static readonly byte[] AesKey0 = Convert.FromHexString("00112233445566778899AABBCCDDEEFF");
    public static readonly byte[] AesKey1 = Convert.FromHexString("102132435465768798A9BACBDCEDFE0F");
    public static readonly byte[] TdesKey0 = Convert.FromHexString("C6EF847CAE0A2A56C0192AA1C4E8D9FB");
    public static readonly byte[] DesKey0 = Convert.FromHexString("0123456789ABCDEF0123456789ABCDEF");

    // AIDs as the model stores them; the wire carries them reversed.
    public static readonly byte[] AesAid = [0x00, 0x00, 0x01];
    public static readonly byte[] IsoAid = [0x00, 0x00, 0x02];
    public static readonly byte[] D40Aid = [0x00, 0x00, 0x04];

    public const byte FilePlain = 0x01;
    public const byte FileMac = 0x02;
    public const byte FileFull = 0x03;
    public const byte FileValueMac = 0x04;
    public const byte FileValueFull = 0x05;

    public static byte[] Wire(byte[] aid) => aid.Reverse().ToArray();

    public static byte[] Pattern(byte number, int length) =>
        Enumerable.Range(0, length).Select(i => (byte)(number * 0x10 + i)).ToArray();

    private static IReadOnlyList<DfcFile> Files() =>
    [
        DataFile(FilePlain, DfcCommunicationMode.Plain),
        DataFile(FileMac, DfcCommunicationMode.Mac),
        DataFile(FileFull, DfcCommunicationMode.Full),
        ValueFile(FileValueMac, DfcCommunicationMode.Mac),
        ValueFile(FileValueFull, DfcCommunicationMode.Full),
    ];

    private static DfcFile DataFile(byte number, DfcCommunicationMode mode) =>
        new(number, DfcFileType.StandardData, (byte)mode, 0x0000, new DfcFileContents.Data(32, Pattern(number, 32), true));

    private static DfcFile ValueFile(byte number, DfcCommunicationMode mode) =>
        new(number, DfcFileType.Value, (byte)mode, 0x0000, new DfcFileContents.Value(0, 1000, 100, 0));

    public static DfcCredential Credential(DfcGeneration generation = DfcGeneration.Ev2) =>
        new(
            new DfcCard(generation, 4096, Convert.FromHexString("04112233445566"), DfcUidProvenance.Real),
            new DfcPicc(0x0F, 0x01, DfcAuthenticationMode.D40, [new DfcKey(new byte[16], 0)], []),
            [
                new DfcApplication(
                    AesAid,
                    0x0F,
                    0x82,
                    DfcAuthenticationMode.Aes,
                    [new DfcKey(AesKey0, 0), new DfcKey(AesKey1, 0)],
                    Files()
                ),
                new DfcApplication(
                    IsoAid,
                    0x0F,
                    0x02,
                    DfcAuthenticationMode.Iso,
                    [new DfcKey(TdesKey0, 0), new DfcKey(new byte[16], 0)],
                    Files()
                ),
                new DfcApplication(
                    D40Aid,
                    0x0F,
                    0x02,
                    DfcAuthenticationMode.D40,
                    [new DfcKey(DesKey0, 0), new DfcKey(new byte[16], 0)],
                    Files()
                ),
            ]
        );

    public static T Ok<T, TError>(CSharpFunctionalExtensions.Result<T, TError> result)
    {
        Assert.That(result.IsSuccess, Is.True, () => $"Expected success, got {result.Error}");
        return result.Value;
    }

    public static void Ok<TError>(CSharpFunctionalExtensions.UnitResult<TError> result) =>
        Assert.That(result.IsSuccess, Is.True, () => $"Expected success, got {result.Error}");

    public static async Task SelectAsync(DfcReader reader, byte[] aid) =>
        Ok(await reader.ExchangeAsync(DfcCommand.SelectApplication(Wire(aid))));

    public static DfcVirtualPicc Picc(DfcCredential credential, IDfcRandomSource? random = null)
    {
        var picc = Ok(DfcVirtualPicc.Create(credential, random));
        Ok(picc.Activate());
        return picc;
    }
}
