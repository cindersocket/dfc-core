namespace Dfc.Tests;

using System;
using System.Threading.Tasks;
using Dfc.Credentials;
using Dfc.Emulation;
using Dfc.Reader;
using NUnit.Framework;

[TestFixture]
public sealed class PiccBehaviorTests
{
    [Test]
    public void GetVersion_UsesThreeNativeResponseFrames()
    {
        using var picc = Fixtures.Picc(Fixtures.Credential(DfcGeneration.Ev1));

        var first = Fixtures.Ok(picc.Exchange(Hex("9060000000")));
        var second = Fixtures.Ok(picc.Exchange(Hex("90AF000000")));
        var last = Fixtures.Ok(picc.Exchange(Hex("90AF000000")));

        Assert.Multiple(() =>
        {
            Assert.That(first.Length, Is.EqualTo(9));
            Assert.That(second.Length, Is.EqualTo(9));
            Assert.That(last.Length, Is.EqualTo(16));
            Assert.That(first[^2..], Is.EqualTo(new byte[] { 0x91, 0xAF }));
            Assert.That(second[^2..], Is.EqualTo(new byte[] { 0x91, 0xAF }));
            Assert.That(last[^2..], Is.EqualTo(new byte[] { 0x91, 0x00 }));
        });
    }

    [Test]
    public void WriteData_TwoFrames_AppliesTheWholePayload()
    {
        using var picc = FreeFilePicc(DfcCommunicationMode.Plain);
        Assert.That(Fixtures.Ok(picc.Exchange(Hex("905A00000301020300"))), Is.EqualTo(Hex("9100")));

        var first = Fixtures.Ok(picc.Exchange(Hex("903D00000B01000000080000AABBCCDD00")));
        Assert.That(first, Is.EqualTo(Hex("91AF")));

        var second = Fixtures.Ok(picc.Exchange(Hex("90AF000004EEFF001100")));
        var read = Fixtures.Ok(picc.Exchange(Hex("90BD0000070100000008000000")));
        Assert.Multiple(() =>
        {
            Assert.That(second, Is.EqualTo(Hex("9100")));
            Assert.That(read, Is.EqualTo(Hex("AABBCCDDEEFF00119100")));
        });
    }

    [Test]
    public void ReadData_FreeAccessFullMode_ReturnsPlaintextWithoutAuthentication()
    {
        using var picc = FreeFilePicc(DfcCommunicationMode.Full);
        Assert.That(Fixtures.Ok(picc.Exchange(Hex("905A00000301020300"))), Is.EqualTo(Hex("9100")));

        var read = Fixtures.Ok(picc.Exchange(Hex("90BD0000070100000000000000")));

        Assert.That(read, Is.EqualTo(Hex("00000000000000009100")));
    }

    [TestCase("C2")]
    [TestCase("CA00")]
    public void IsoDepRelease_EchoesTheFrame(string release)
    {
        using var picc = Fixtures.Picc(Fixtures.Credential(DfcGeneration.Ev1));
        Fixtures.Ok(picc.ExchangeFrame(Hex("E050")));

        var frame = Hex(release);
        Assert.That(Fixtures.Ok(picc.ExchangeFrame(frame)), Is.EqualTo(frame));
    }

    [TestCase("904200000000", "911C")]
    [TestCase("906A00000200", "917E")]
    [TestCase("900A0000010100", "9140")]
    [TestCase("90AA0000010000", "91AE")]
    [TestCase("90AF00000000", "911C")]
    public void NativeApdu_RejectsInvalidCommands(string command, string response)
    {
        using var picc = Fixtures.Picc(Fixtures.Credential(DfcGeneration.Ev1));

        Assert.That(Fixtures.Ok(picc.Exchange(Hex(command))), Is.EqualTo(Hex(response)));
    }

    [Test]
    public void DataFile_RejectsWritesAndReadsPastItsEnd()
    {
        using var picc = FreeFilePicc(DfcCommunicationMode.Plain);
        Assert.That(Fixtures.Ok(picc.Exchange(Hex("905A00000301020300"))), Is.EqualTo(Hex("9100")));

        var write = Fixtures.Ok(picc.Exchange(Hex("903D00000901070000020000010200")));
        var readPastEnd = Fixtures.Ok(picc.Exchange(Hex("90BD0000070107000002000000")));
        var unchanged = Fixtures.Ok(picc.Exchange(Hex("90BD0000070100000000000000")));

        Assert.Multiple(() =>
        {
            Assert.That(write, Is.EqualTo(Hex("91BE")));
            Assert.That(readPastEnd, Is.EqualTo(Hex("91BE")));
            Assert.That(unchanged, Is.EqualTo(Hex("00000000000000009100")));
        });
    }

    [Test]
    public async Task BackupData_HidesUncommittedWrite()
    {
        using var picc = FreeFilePicc(DfcCommunicationMode.Plain, DfcFileType.BackupData, 4);
        using var reader = new DfcReader(picc);
        Fixtures.Ok(await reader.ExchangeAsync(DfcCommand.SelectApplication(Hex("010203"))));

        Fixtures.Ok(await reader.WriteDataAsync(1, 0, Hex("01020304")));
        var before = Fixtures.Ok(await reader.ExchangeAsync(DfcCommand.ReadData(1, 0, 0)));
        Fixtures.Ok(await reader.ExchangeAsync(DfcCommand.CommitTransaction()));
        var after = Fixtures.Ok(await reader.ExchangeAsync(DfcCommand.ReadData(1, 0, 0)));

        Assert.Multiple(() =>
        {
            Assert.That(before.Data, Is.EqualTo(new byte[4]));
            Assert.That(after.Data, Is.EqualTo(Hex("01020304")));
        });
    }

    private static DfcVirtualPicc FreeFilePicc(
        DfcCommunicationMode mode,
        DfcFileType type = DfcFileType.StandardData,
        uint size = 8)
    {
        var credential = Fixtures.Credential(DfcGeneration.Ev1);
        var application = new DfcApplication(
            [0x03, 0x02, 0x01],
            0x0F,
            0x01,
            DfcAuthenticationMode.D40,
            [new DfcKey(new byte[16], 0)],
            [new DfcFile(1, type, (byte)mode, 0xEEEE,
                new DfcFileContents.Data(size, new byte[size], true))]
        );
        return Fixtures.Picc(credential with { Applications = [application] });
    }

    private static byte[] Hex(string value) => Convert.FromHexString(value);
}
