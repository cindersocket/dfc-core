namespace Dfc.Tests;

using System;
using System.Threading.Tasks;
using Dfc.Credentials;
using Dfc.Reader;
using NUnit.Framework;

[TestFixture]
public sealed class FeatureTests
{
    private static readonly byte[] ProximityKey = Convert.FromHexString("0A0B0C0D0E0F10111213141516171819");
    private static readonly byte[] SelectEncryptionKey = Convert.FromHexString("2122232425262728292A2B2C2D2E2F20");
    private static readonly byte[] SelectMacKey = Convert.FromHexString("3132333435363738393A3B3C3D3E3F30");
    private static readonly byte[] InstallationId = [0xF0, 0x01, 0x02, 0x03, 0x04];
    private static readonly byte[] DamAuth = Convert.FromHexString("4142434445464748494A4B4C4D4E4F40");
    private static readonly byte[] DamMac = Convert.FromHexString("5152535455565758595A5B5C5D5E5F50");
    private static readonly byte[] DamEncryption = Convert.FromHexString("6162636465666768696A6B6C6D6E6F60");

    [Test]
    public async Task ChangeKeyEv2_ChangesAnotherKeyInTheActiveSet()
    {
        var credential = Fixtures.Credential(DfcGeneration.Ev2);
        var aes = credential.Applications[0];
        var keySets = new DfcKeySets(
            16,
            0x00,
            [
                new DfcKeySet(0x00, 0x02, true, aes.Keys),
                new DfcKeySet(0x00, 0x02, true, [new DfcKey(new byte[16], 0), new DfcKey(new byte[16], 0)]),
            ]
        );
        credential = credential with
        {
            Applications = [aes with { KeySets = keySets }, credential.Applications[1], credential.Applications[2]],
        };

        using var picc = Fixtures.Picc(credential);
        using var reader = new DfcReader(picc);
        await Fixtures.SelectAsync(reader, Fixtures.AesAid);
        Fixtures.Ok(await reader.AuthenticateEv2FirstAsync(0, Fixtures.AesKey0));

        var newKey = Convert.FromHexString("7172737475767778797A7B7C7D7E7F70");
        Fixtures.Ok(await reader.ChangeKeyEv2Async(0, 1, newKey, Fixtures.AesKey1, 9));
        Assert.That(reader.IsAuthenticated, Is.True);
        Fixtures.Ok(await reader.AuthenticateEv2NonFirstAsync(1, newKey));
        Assert.That(picc.ExportCredential().Applications[0].Keys[1].Value, Is.EqualTo(newKey));
    }

    [Test]
    public async Task ProximityCheck_VerifiesBothMacs()
    {
        var credential = Fixtures.Credential(DfcGeneration.Ev3);
        credential = credential with
        {
            Picc = credential.Picc with { ProximityCheck = new DfcProximityConfiguration(ProximityKey, 0x00, 0x0102) },
        };
        using var picc = Fixtures.Picc(credential);
        using var reader = new DfcReader(picc);

        var result = Fixtures.Ok(await reader.ProximityCheckAsync(ProximityKey, rounds: 2));

        Assert.That(result.Published, Is.EqualTo(new byte[] { 0x00, 0x01, 0x02 }));
        Assert.That(picc.Snapshot().ProximityVerified, Is.True);
    }

    [Test]
    public async Task ProximityCheck_WrongKeyIsRefused()
    {
        var credential = Fixtures.Credential(DfcGeneration.Ev3);
        credential = credential with
        {
            Picc = credential.Picc with { ProximityCheck = new DfcProximityConfiguration(ProximityKey, 0x00, 0x0102) },
        };
        using var picc = Fixtures.Picc(credential);
        using var reader = new DfcReader(picc);

        var result = await reader.ProximityCheckAsync(new byte[16], rounds: 1);

        Assert.That(result.IsFailure, Is.True);
        Assert.That(result.Error.Kind, Is.EqualTo(DfcProtocolErrorKind.CardStatus));
    }

    [Test]
    public async Task VirtualCard_SelectsAndAuthenticates()
    {
        var credential = Fixtures.Credential(DfcGeneration.Ev2);
        credential = credential with
        {
            Picc = credential.Picc with
            {
                VirtualCard = new DfcVirtualCardConfiguration(
                    InstallationId,
                    0x5A,
                    [0x00, 0x00],
                    credential.Card.Uid,
                    SelectMacKey,
                    SelectEncryptionKey,
                    AuthenticationMandatory: true,
                    ProximityMandatory: false
                ),
            },
        };
        using var picc = Fixtures.Picc(credential);
        using var reader = new DfcReader(picc);

        var selection = Fixtures.Ok(await reader.SelectVirtualCardAsync(InstallationId, SelectEncryptionKey, SelectMacKey));

        Assert.That(selection.ClearData[0], Is.EqualTo((byte)0x5A));
        Assert.That(selection.ClearData.AsSpan(3, 7).ToArray(), Is.EqualTo(credential.Card.Uid));
        Assert.That(picc.Snapshot().VirtualCardSelected, Is.True);
    }

    [Test]
    public async Task DelegatedApplication_IsCreatedWithItsInitialKey()
    {
        var credential = Fixtures.Credential(DfcGeneration.Ev2);
        credential = credential with
        {
            Picc = credential.Picc with
            {
                KeySettings2 = 0x81,
                AuthenticationMode = DfcAuthenticationMode.Aes,
                DamKeys = new DfcDamKeys(DamAuth, DamMac, DamEncryption),
            },
        };
        using var picc = Fixtures.Picc(credential);
        using var reader = new DfcReader(picc);
        Fixtures.Ok(await reader.ExchangeAsync(DfcCommand.SelectApplication(new byte[3])));
        Fixtures.Ok(await reader.AuthenticateEv2FirstAsync(0x10, DamAuth));

        var initialKey = Convert.FromHexString("ABABABABABABABABCDCDCDCDCDCDCDCD");
        var paddedKey = new byte[24];
        initialKey.CopyTo(paddedKey, 0);
        Fixtures.Ok(
            await reader.CreateDelegatedApplicationAsync(
                new DfcDelegatedApplicationRequest(
                    [0x0A, 0x0B, 0x0C],
                    0x0001,
                    0x00,
                    0x0040,
                    0x0F,
                    0x81,
                    DamEncryption,
                    DamMac,
                    paddedKey,
                    0x03
                )
            )
        );

        Fixtures.Ok(await reader.ExchangeAsync(DfcCommand.SelectApplication(new byte[] { 0x0A, 0x0B, 0x0C })));
        Fixtures.Ok(await reader.AuthenticateAsync(DfcAuthenticationMode.Aes, 0, initialKey));
        var created = picc.ExportCredential().Applications[^1];
        Assert.That(created.Delegation, Is.Not.Null);
        Assert.That(created.Keys[0].Version, Is.EqualTo((byte)0x03));
    }
}
