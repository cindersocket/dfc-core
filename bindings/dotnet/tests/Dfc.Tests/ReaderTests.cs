namespace Dfc.Tests;

using System;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Dfc.Credentials;
using Dfc.Emulation;
using Dfc.Reader;
using NUnit.Framework;

[TestFixture]
public sealed class ReaderTests
{
    private static async Task ExerciseFilesAsync(DfcReader reader)
    {
        foreach (var (file, mode) in new[]
                 {
                     (Fixtures.FilePlain, DfcCommunicationMode.Plain),
                     (Fixtures.FileMac, DfcCommunicationMode.Mac),
                     (Fixtures.FileFull, DfcCommunicationMode.Full),
                 })
        {
            var read = Fixtures.Ok(await reader.ExchangeAsync(DfcCommand.ReadData(file, 0, 32), mode));
            Assert.That(read.Data, Is.EqualTo(Fixtures.Pattern(file, 32)), $"read of file {file}");

            byte[] payload = [0xDE, 0xAD, 0xBE, 0xEF];
            Fixtures.Ok(await reader.ExchangeAsync(DfcCommand.WriteData(file, 4, payload), mode));
            var back = Fixtures.Ok(await reader.ExchangeAsync(DfcCommand.ReadData(file, 4, 4), mode));
            Assert.That(back.Data, Is.EqualTo(payload), $"write of file {file}");
        }

        foreach (var (file, mode) in new[]
                 {
                     (Fixtures.FileValueMac, DfcCommunicationMode.Mac),
                     (Fixtures.FileValueFull, DfcCommunicationMode.Full),
                 })
        {
            Fixtures.Ok(await reader.ExchangeAsync(DfcCommand.Credit(file, 25), mode));
            Fixtures.Ok(await reader.ExchangeAsync(DfcCommand.CommitTransaction()));
            var value = Fixtures.Ok(await reader.ExchangeAsync(DfcCommand.GetValue(file), mode));
            Assert.That(BitConverter.ToInt32(value.Data), Is.EqualTo(125), $"value of file {file}");
        }

        Assert.That(reader.IsAuthenticated, Is.True);
    }

    [TestCase(DfcAuthenticationMode.Aes, DfcFraming.Iso7816)]
    [TestCase(DfcAuthenticationMode.Aes, DfcFraming.Native)]
    [TestCase(DfcAuthenticationMode.Iso, DfcFraming.Iso7816)]
    [TestCase(DfcAuthenticationMode.D40, DfcFraming.Iso7816)]
    public async Task Session_SecuresEveryFileMode(DfcAuthenticationMode mode, DfcFraming framing)
    {
        using var picc = Fixtures.Picc(Fixtures.Credential());
        using var reader = new DfcReader(picc, framing);
        var (aid, key) = mode switch
        {
            DfcAuthenticationMode.Aes => (Fixtures.AesAid, Fixtures.AesKey0),
            DfcAuthenticationMode.Iso => (Fixtures.IsoAid, Fixtures.TdesKey0),
            _ => (Fixtures.D40Aid, Fixtures.DesKey0),
        };

        await Fixtures.SelectAsync(reader, aid);
        Fixtures.Ok(await reader.AuthenticateAsync(mode, 0, key));
        Assert.That(reader.Session.Kind, Is.EqualTo((DfcSessionKind)mode));
        Assert.That(picc.Snapshot().Authentication, Is.EqualTo(mode));

        await ExerciseFilesAsync(reader);
        Assert.That(picc.IsDirty, Is.True);
    }

    [Test]
    public async Task Ev2Session_SecuresEveryFileMode()
    {
        using var picc = Fixtures.Picc(Fixtures.Credential(DfcGeneration.Ev2));
        using var reader = new DfcReader(picc);
        await Fixtures.SelectAsync(reader, Fixtures.AesAid);
        Fixtures.Ok(await reader.AuthenticateEv2FirstAsync(0, Fixtures.AesKey0, new byte[6]));
        Assert.That(reader.Session.Kind, Is.EqualTo(DfcSessionKind.Ev2));

        await ExerciseFilesAsync(reader);

        var card = picc.Snapshot().Ev2Session;
        Assert.That(card, Is.Not.Null);
        Assert.That(card!.CommandCounter, Is.EqualTo(reader.Session.Ev2CommandCounter));
        Assert.That(card.TransactionIdentifier, Is.EqualTo(reader.Session.Ev2TransactionIdentifier));

        var transaction = reader.Session.Ev2TransactionIdentifier;
        Fixtures.Ok(await reader.AuthenticateEv2NonFirstAsync(0, Fixtures.AesKey0));
        Assert.That(reader.Session.Ev2TransactionIdentifier, Is.EqualTo(transaction));
        Assert.That(reader.Session.Ev2CommandCounter, Is.EqualTo((ushort)0));
    }

    [Test]
    public async Task WrongKey_FailsWithCardStatusAndClearsSession()
    {
        using var picc = Fixtures.Picc(Fixtures.Credential());
        using var reader = new DfcReader(picc);
        await Fixtures.SelectAsync(reader, Fixtures.AesAid);
        Fixtures.Ok(await reader.AuthenticateAsync(DfcAuthenticationMode.Aes, 0, Fixtures.AesKey0));

        var result = await reader.AuthenticateAsync(DfcAuthenticationMode.Aes, 0, Fixtures.AesKey1);

        Assert.That(result.IsFailure, Is.True);
        Assert.That(result.Error.Kind, Is.EqualTo(DfcProtocolErrorKind.CardStatus));
        Assert.That(result.Error.CardStatus, Is.EqualTo((byte)0xAE));
        Assert.That(reader.IsAuthenticated, Is.False);
    }

    [Test]
    public async Task ChangeKey_CarriesOnAndThenEndsTheSession()
    {
        using var picc = Fixtures.Picc(Fixtures.Credential());
        using var reader = new DfcReader(picc);
        await Fixtures.SelectAsync(reader, Fixtures.AesAid);
        Fixtures.Ok(await reader.AuthenticateAsync(DfcAuthenticationMode.Aes, 0, Fixtures.AesKey0));

        var newKey1 = Convert.FromHexString("5A5A5A5A5A5A5A5AA5A5A5A5A5A5A5A5");
        Fixtures.Ok(await reader.ChangeKeyAsync(1, newKey1, Fixtures.AesKey1, aesKey: true, newVersion: 7));
        Assert.That(reader.IsAuthenticated, Is.True);

        var newKey0 = Convert.FromHexString("0F0E0D0C0B0A09080706050403020100");
        Fixtures.Ok(await reader.ChangeKeyAsync(0, newKey0, ReadOnlyMemory<byte>.Empty, aesKey: true, newVersion: 1));
        Assert.That(reader.IsAuthenticated, Is.False);

        Fixtures.Ok(await reader.AuthenticateAsync(DfcAuthenticationMode.Aes, 1, newKey1));
        var exported = picc.ExportCredential();
        Assert.That(exported.Applications[0].Keys[0].Value, Is.EqualTo(newKey0));
        Assert.That(exported.Applications[0].Keys[1].Version, Is.EqualTo((byte)7));
    }

    [Test]
    public async Task GetVersion_IsTheSameUnderASession()
    {
        using var picc = Fixtures.Picc(Fixtures.Credential());
        using var reader = new DfcReader(picc);
        var plain = Fixtures.Ok(await reader.ExchangeAsync(DfcCommand.GetVersion()));

        await Fixtures.SelectAsync(reader, Fixtures.AesAid);
        Fixtures.Ok(await reader.AuthenticateAsync(DfcAuthenticationMode.Aes, 0, Fixtures.AesKey0));
        var secured = Fixtures.Ok(await reader.ExchangeAsync(DfcCommand.GetVersion()));

        Assert.That(secured.Data, Is.EqualTo(plain.Data));
        Fixtures.Ok(await reader.ExchangeAsync(DfcCommand.ReadData(Fixtures.FileMac, 0, 8), DfcCommunicationMode.Mac));
    }

    [Test]
    public async Task ScriptedRandomness_ReplaysTheSameWire()
    {
        async Task<byte[]> Session()
        {
            var script = new byte[64];
            new Random(7).NextBytes(script);
            using var picc = Fixtures.Picc(Fixtures.Credential(), new DfcScriptedRandomSource(script));
            var recorder = new Recorder(picc);
            using var reader = new DfcReader(recorder, DfcFraming.Iso7816, new DfcScriptedRandomSource(script));
            await Fixtures.SelectAsync(reader, Fixtures.AesAid);
            Fixtures.Ok(await reader.AuthenticateAsync(DfcAuthenticationMode.Aes, 0, Fixtures.AesKey0));
            return recorder.Wire.ToArray();
        }

        Assert.That(await Session(), Is.EqualTo(await Session()));
    }

    [Test]
    public async Task TransportFailure_ClearsTheSession()
    {
        using var picc = Fixtures.Picc(Fixtures.Credential());
        var flaky = new Recorder(picc);
        using var reader = new DfcReader(flaky);
        await Fixtures.SelectAsync(reader, Fixtures.AesAid);
        Fixtures.Ok(await reader.AuthenticateAsync(DfcAuthenticationMode.Aes, 0, Fixtures.AesKey0));

        flaky.Fail = true;
        var result = await reader.ExchangeAsync(DfcCommand.GetVersion());

        Assert.That(result.IsFailure, Is.True);
        Assert.That(result.Error.Kind, Is.EqualTo(DfcProtocolErrorKind.Transport));
        Assert.That(reader.IsAuthenticated, Is.False);
    }

    [Test]
    public async Task FieldOff_EndsTheCardSession()
    {
        using var picc = Fixtures.Picc(Fixtures.Credential());
        using var reader = new DfcReader(picc);
        await Fixtures.SelectAsync(reader, Fixtures.AesAid);
        Fixtures.Ok(await reader.AuthenticateAsync(DfcAuthenticationMode.Aes, 0, Fixtures.AesKey0));

        picc.FieldOff();
        Assert.That(picc.Snapshot().Authentication, Is.Null);
        var result = await reader.ExchangeAsync(DfcCommand.GetVersion());
        Assert.That(result.IsFailure, Is.True);
        Assert.That(result.Error.Kind, Is.EqualTo(DfcProtocolErrorKind.NoCard));
    }

    private sealed class Recorder(IDfcApduExchange inner) : IDfcApduExchange
    {
        public System.Collections.Generic.List<byte> Wire { get; } = [];

        public bool Fail { get; set; }

        public async ValueTask<Result<byte[], DfcProtocolError>> TransmitAsync(
            ReadOnlyMemory<byte> frame,
            CancellationToken cancellationToken
        )
        {
            if (Fail)
            {
                return DfcProtocolError.Transport("The link dropped.");
            }

            Wire.AddRange(frame.ToArray());
            var answer = await inner.TransmitAsync(frame, cancellationToken).ConfigureAwait(false);
            if (answer.IsSuccess)
            {
                Wire.AddRange(answer.Value);
            }

            return answer;
        }
    }
}
