namespace Dfc.Tests;

using System;
using System.Linq;
using Dfc.Credentials;
using NUnit.Framework;

[TestFixture]
public sealed class CredentialCodecTests
{
    private const string Minimal =
        "Filetype: DFC Credential\n"
        + "Version: 4\n"
        + "Card Generation: EV1\n"
        + "Card Storage: 2048\n"
        + "UID: 04 22 33 44 55 66 77\n"
        + "UID Provenance: Real\n"
        + "PICC Key Settings 1: 0F\n"
        + "PICC Key Settings 2: 01\n"
        + "PICC Authentication Mode: D40\n"
        + "PICC Key Count: 1\n"
        + "PICC Key 00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00\n"
        + "PICC Key 00 Version: 00\n"
        + "PICC File Count: 0\n"
        + "Application Count: 1\n"
        + "Application 00 AID: 00 00 01\n"
        + "Application 00 Key Settings 1: 0F\n"
        + "Application 00 Key Settings 2: 81\n"
        + "Application 00 Authentication Mode: AES\n"
        + "Application 00 Key Count: 1\n"
        + "Application 00 Key 00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00\n"
        + "Application 00 Key 00 Version: 00\n"
        + "Application 00 File Count: 1\n"
        + "Application 00 File 00 Number: 01\n"
        + "Application 00 File 00 Type: Standard Data\n"
        + "Application 00 File 00 Communication Settings: 00\n"
        + "Application 00 File 00 Access Rights: EE EE\n"
        + "Application 00 File 00 Size: 32\n"
        + "Application 00 File 00 Data Complete: 0\n";

    [Test]
    public void Parse_Minimal_BuildsTheRecordTree()
    {
        var credential = Fixtures.Ok(DfcCredentialCodec.Parse(Minimal));

        Assert.That(credential.Card.Generation, Is.EqualTo(DfcGeneration.Ev1));
        Assert.That(credential.Card.Storage, Is.EqualTo(2048u));
        Assert.That(credential.Card.Uid, Is.EqualTo(new byte[] { 0x04, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 }));
        Assert.That(credential.Picc.Keys, Has.Count.EqualTo(1));
        var app = credential.Applications.Single();
        Assert.That(app.Aid, Is.EqualTo(new byte[] { 0x00, 0x00, 0x01 }));
        Assert.That(app.AuthenticationMode, Is.EqualTo(DfcAuthenticationMode.Aes));
        var file = app.Files.Single();
        Assert.That(file.Type, Is.EqualTo(DfcFileType.StandardData));
        Assert.That(file.AccessRights, Is.EqualTo((ushort)0xEEEE));
        Assert.That(((DfcFileContents.Data)file.Contents).Size, Is.EqualTo(32u));
    }

    [Test]
    public void TextAndBinary_RoundTrip()
    {
        var credential = Fixtures.Ok(DfcCredentialCodec.Parse(Minimal));
        var octets = Fixtures.Ok(DfcCredentialCodec.Encode(credential));
        Assert.That(DfcCredentialCodec.IsBinary(octets), Is.True);

        var decoded = Fixtures.Ok(DfcCredentialCodec.Decode(octets));
        Assert.That(Fixtures.Ok(DfcCredentialCodec.Encode(decoded)), Is.EqualTo(octets));

        var text = Fixtures.Ok(DfcCredentialCodec.WriteText(decoded));
        var reparsed = Fixtures.Ok(DfcCredentialCodec.Load(System.Text.Encoding.UTF8.GetBytes(text)));
        Assert.That(Fixtures.Ok(DfcCredentialCodec.Encode(reparsed)), Is.EqualTo(octets));
    }

    [Test]
    public void BuiltRecords_EncodeLikeParsedOnes()
    {
        var credential = Fixtures.Credential();
        var octets = Fixtures.Ok(DfcCredentialCodec.Encode(credential));
        var decoded = Fixtures.Ok(DfcCredentialCodec.Decode(octets));

        Assert.That(decoded.Applications, Has.Count.EqualTo(3));
        Assert.That(decoded.Applications[0].Keys[0].Value, Is.EqualTo(Fixtures.AesKey0));
        var value = (DfcFileContents.Value)decoded.Applications[0].Files[3].Contents;
        Assert.That(value.Current, Is.EqualTo(100));
        Assert.That(((DfcFileContents.Data)decoded.Applications[0].Files[1].Contents).Known,
            Is.EqualTo(Fixtures.Pattern(Fixtures.FileMac, 32)));
    }

    [Test]
    public void Parse_Malformed_ReportsClassAndLine()
    {
        var broken = Minimal.Replace("Card Generation: EV1", "Card Generation: EV9");
        var result = DfcCredentialCodec.Parse(broken);

        Assert.That(result.IsFailure, Is.True);
        Assert.That(result.Error.Class, Is.EqualTo(DfcErrorClass.Malformed));
        Assert.That(result.Error.Line, Is.EqualTo(3));
    }

    [Test]
    public void Decode_Truncated_IsMalformed()
    {
        var octets = Fixtures.Ok(DfcCredentialCodec.Encode(Fixtures.Credential()));
        var result = DfcCredentialCodec.Decode(octets.AsSpan(0, octets.Length - 1));

        Assert.That(result.IsFailure, Is.True);
        Assert.That(result.Error.Class, Is.EqualTo(DfcErrorClass.Malformed));
    }

    [Test]
    public void Validate_RejectsDuplicateApplications()
    {
        var credential = Fixtures.Credential();
        var duplicated = credential with { Applications = [credential.Applications[0], credential.Applications[0]] };

        Assert.That(DfcCredentialCodec.Validate(duplicated).IsFailure, Is.True);
        Assert.That(DfcCredentialCodec.Validate(credential).IsSuccess, Is.True);
    }
}
