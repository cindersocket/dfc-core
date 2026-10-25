namespace Dfc.Tests;

using System;
using Dfc.Credentials;
using Dfc.Crypto;
using Dfc.Reader;
using Dfc.Sdm;
using Dfc.Transactions;
using NUnit.Framework;

[TestFixture]
public sealed class AdvancedApiTests
{
    private static readonly byte[] Uid = Convert.FromHexString("0483B4F2CF1890");

    [Test]
    public void DiversificationCoversEveryAlgorithmAndRejectsBadLengths()
    {
        var master = Convert.FromHexString("00112233445566778899AABBCCDDEEFF");
        Assert.That(DfcKeyDiversification.Diversify(DfcDiversificationAlgorithm.Aes128, master,
                Convert.FromHexString("04782E21801D803042F54E585020416275")).Value,
            Is.EqualTo(Convert.FromHexString("A8DD63A3B89D54B37CA802473FDA9175")));
        Assert.That(DfcKeyDiversification.Diversify(DfcDiversificationAlgorithm.TwoKeyTdea, master,
                Convert.FromHexString("04782E21801D803042F54E58502041")).Value,
            Is.EqualTo(Convert.FromHexString("16F9587D9E8910C96B9648D006107DD7")));
        Assert.That(DfcKeyDiversification.Diversify(DfcDiversificationAlgorithm.ThreeKeyTdea,
                Convert.FromHexString("00112233445566778899AABBCCDDEEFF0102030405060708"),
                Convert.FromHexString("04782E21801D803042F54E5850")).Value,
            Is.EqualTo(Convert.FromHexString("2E0DD03774D3FA9B5705AB0BDA91CA0B55B8E07FCDBF10EC")));
        Assert.That(DfcKeyDiversification.Diversify(
            DfcDiversificationAlgorithm.Aes128, new byte[15], [1]).IsFailure, Is.True);
        Assert.That(DfcKeyDiversification.Diversify(
            DfcDiversificationAlgorithm.Aes128, new byte[16], new byte[32]).IsFailure, Is.True);
        Assert.That(DfcKeyDiversification.Diversify(
            (DfcDiversificationAlgorithm)99, new byte[16], [1]).IsFailure, Is.True);
    }

    [Test]
    public void TypedDecodersCoverEveryResponseAndVariant()
    {
        var version = DfcResponseDecoders.DecodeVersion(Convert.FromHexString(
            "04010101001A0504010101041A05045704EA916F80B90C2145901921"));
        Assert.That(version.IsSuccess, Is.True);
        Assert.Multiple(() =>
        {
            Assert.That(version.Value.Hardware.VendorId, Is.EqualTo(4));
            Assert.That(version.Value.Software.MinorVersion, Is.EqualTo(4));
            Assert.That(version.Value.Uid, Is.EqualTo(Convert.FromHexString("045704EA916F80")));
        });
        Assert.That(DfcResponseDecoders.DecodeVersion(new byte[27]).IsFailure, Is.True);

        var aids = DfcResponseDecoders.DecodeApplicationIds(Convert.FromHexString("3141F5030201"));
        Assert.That(aids.IsSuccess, Is.True);
        Assert.That(aids.Value, Is.EqualTo(new[]
        {
            Convert.FromHexString("F54131"), Convert.FromHexString("010203"),
        }));
        Assert.That(DfcResponseDecoders.DecodeApplicationIds([1, 2]).IsFailure, Is.True);

        var files = DfcResponseDecoders.DecodeFileIds([1, 7, 31]);
        Assert.That(files.Value, Is.EqualTo(new byte[] { 1, 7, 31 }));

        var standard = DfcResponseDecoders.DecodeFileSettings(
            Convert.FromHexString("00013012360000")).Value;
        Assert.Multiple(() =>
        {
            Assert.That(standard.Type, Is.EqualTo(DfcFileType.StandardData));
            Assert.That(standard.CommunicationMode, Is.EqualTo(DfcCommunicationMode.Mac));
            Assert.That(standard.Size, Is.EqualTo(54));
            Assert.That(standard.Access.Read.KeyNumber, Is.EqualTo(1));
        });
        var value = DfcResponseDecoders.DecodeFileSettings(
            Convert.FromHexString("0200EEEE9CFFFFFF640000000B00000001")).Value;
        Assert.Multiple(() =>
        {
            Assert.That(value.Type, Is.EqualTo(DfcFileType.Value));
            Assert.That(value.CommunicationMode, Is.EqualTo(DfcCommunicationMode.Plain));
            Assert.That(value.LowerLimit, Is.EqualTo(-100));
            Assert.That(value.UpperLimit, Is.EqualTo(100));
            Assert.That(value.LimitedCreditEnabled, Is.True);
        });
        var records = DfcResponseDecoders.DecodeFileSettings(
            Convert.FromHexString("0301EF12200000100000070000")).Value;
        Assert.Multiple(() =>
        {
            Assert.That(records.Type, Is.EqualTo(DfcFileType.LinearRecord));
            Assert.That(records.CommunicationMode, Is.EqualTo(DfcCommunicationMode.Mac));
            Assert.That(records.RecordSize, Is.EqualTo(32));
            Assert.That(records.MaxRecords, Is.EqualTo(16));
            Assert.That(records.CurrentRecords, Is.EqualTo(7));
        });
        Assert.That(DfcResponseDecoders.DecodeFileSettings(Convert.FromHexString("7F000000")).IsFailure, Is.True);
        Assert.That(DfcResponseDecoders.DecodeFileSettings([0]).IsFailure, Is.True);

        var simpleKeys = DfcResponseDecoders.DecodeKeySettings(Convert.FromHexString("0F01")).Value;
        Assert.That(simpleKeys.KeyCount, Is.EqualTo(1));
        Assert.That(simpleKeys.ActiveKeySetVersion, Is.Null);
        var extendedKeys = DfcResponseDecoders.DecodeKeySettings(
            Convert.FromHexString("0F8321041002")).Value;
        Assert.Multiple(() =>
        {
            Assert.That(extendedKeys.ActiveKeySetVersion, Is.EqualTo(0x21));
            Assert.That(extendedKeys.KeySetCount, Is.EqualTo(4));
            Assert.That(extendedKeys.MaxKeySize, Is.EqualTo(16));
        });
        Assert.That(DfcResponseDecoders.DecodeKeySettings(Convert.FromHexString("0F0F")).IsFailure, Is.True);
        Assert.That(DfcResponseDecoders.DecodeKeySettings([0]).IsFailure, Is.True);
        Assert.That(DfcResponseDecoders.DecodeKeyVersion([0xA5]).Value, Is.EqualTo(0xA5));
        Assert.That(DfcResponseDecoders.DecodeKeyVersion([]).IsFailure, Is.True);
        Assert.That(DfcResponseDecoders.DecodeKeyVersion([1, 2]).IsFailure, Is.True);
    }

    [Test]
    public void SdmVerificationPublishesOnlyAuthenticatedFields()
    {
        var message = "0483B4F2CF1890000001163F0AC4319102F37F4B61FE6BFDE1469CF53E287D682A2E"u8.ToArray();
        var config = new DfcSdmConfig(20, 52, new DfcSdmField(0, 7), 14,
            EncryptedFileData: new DfcSdmField(20, 32));
        var verified = DfcSdmVerifier.Verify(message, config, new byte[16]);
        Assert.That(verified.IsSuccess, Is.True);
        Assert.Multiple(() =>
        {
            Assert.That(verified.Value.Uid, Is.EqualTo(Uid));
            Assert.That(verified.Value.ReadCounter, Is.EqualTo(1));
            Assert.That(verified.Value.DecryptedFileData,
                Is.EqualTo(Convert.FromHexString("00112233445566778899AABBCCDDEEFF")));
        });

        var wrongKey = new byte[16];
        wrongKey[0] = 1;
        Assert.That(DfcSdmVerifier.Verify(message, config, wrongKey).IsFailure, Is.True);
        Assert.That(DfcSdmVerifier.Verify(message,
            config with { PlainUid = new DfcSdmField(0, 14) }, new byte[16]).IsFailure, Is.True,
            "plain UID length is the decoded byte count, not the ASCII field width");
        Assert.That(DfcSdmVerifier.Verify(message,
            config with { EncryptedFileData = new DfcSdmField(20, 16) }, new byte[16]).IsFailure, Is.True,
            "encrypted file length is the ASCII field width, not the decoded byte count");
        var modified = (byte[])message.Clone();
        modified[30] ^= 1;
        Assert.That(DfcSdmVerifier.Verify(modified, config, new byte[16]).IsFailure, Is.True);
        Assert.Throws<ArgumentException>(() => DfcSdmVerifier.Verify(message, config, new byte[15]));
        Assert.Throws<ArgumentException>(() => DfcSdmVerifier.Verify(
            message, config, new byte[16], new byte[15]));
        Assert.Throws<ArgumentOutOfRangeException>(() => DfcSdmVerifier.Verify(message,
            new DfcSdmConfig(-1, 52), new byte[16]));
        Assert.Throws<ArgumentException>(() => DfcSdmVerifier.Verify(message,
            new DfcSdmConfig(20, 52, EncryptedFileData: new DfcSdmField(0, int.MaxValue)),
            new byte[16]));
    }

    private static DfcTransactionMacVerifier Verifier(int capacity = 128) =>
        DfcTransactionMacVerifier.Create(new byte[16], Uid, 1, capacity).Value;

    [Test]
    public void TransactionMacCoversEveryInputAndFailureBoundary()
    {
        Assert.That(DfcTransactionMacVerifier.Create(new byte[15], Uid, 1).IsFailure, Is.True);
        Assert.That(DfcTransactionMacVerifier.Create(new byte[16], new byte[6], 1).IsFailure, Is.True);
        Assert.That(DfcTransactionMacVerifier.Create(new byte[16], Uid, 1, 0).IsFailure, Is.True);
        using (var receipt = Verifier(64))
        {
            Assert.That(receipt.AddValue(0x0C, 5, 1).IsSuccess, Is.True);
            Assert.That(receipt.Verify(Convert.FromHexString("352E57ADDA911EDC")).Value, Is.True);
            Assert.That(receipt.Verify(Convert.FromHexString("352E57ADDA911EDD")).Value, Is.False);
            Assert.That(receipt.Verify(new byte[7]).IsFailure, Is.True);
        }
        using (var allInputs = Verifier(192))
        {
            Assert.That(allInputs.AddData(0x3D, 2, 0x030201, 3, Convert.FromHexString("A1B2C3")).IsSuccess, Is.True);
            Assert.That(allInputs.AddRecordUpdate(0xDB, 3, 4, 5, 2, Convert.FromHexString("4455")).IsSuccess, Is.True);
            Assert.That(allInputs.AddValue(0x0C, 5, 1).IsSuccess, Is.True);
            Assert.That(allInputs.AddClearRecord(4).IsSuccess, Is.True);
            Assert.That(allInputs.AddReaderId(new byte[16], new byte[16]).IsSuccess, Is.True);
            Assert.That(allInputs.Verify(new byte[8]).Value, Is.False);
        }
        using (var bounded = Verifier(192))
        {
            Assert.That(bounded.AddData(0x3D, 2, 0, 2, [1]).IsFailure, Is.True);
            Assert.That(bounded.AddReaderId(new byte[15], new byte[16]).IsFailure, Is.True);
            Assert.That(bounded.AddValue(0x0C, 5, 1).IsSuccess, Is.True);
            Assert.That(bounded.Verify(Convert.FromHexString("352E57ADDA911EDC")).Value, Is.True);
        }
        using (var tooSmall = Verifier(16))
            Assert.That(tooSmall.AddData(0x3D, 2, 0, 3, Convert.FromHexString("A1B2C3")).IsFailure, Is.True);

        var wrongKey = new byte[16];
        wrongKey[0] = 1;
        using (var receipt = DfcTransactionMacVerifier.Create(wrongKey, Uid, 1, 64).Value)
        {
            receipt.AddValue(0x0C, 5, 1);
            Assert.That(receipt.Verify(Convert.FromHexString("352E57ADDA911EDC")).Value, Is.False);
        }
        using (var receipt = DfcTransactionMacVerifier.Create(new byte[16], Uid, 2, 64).Value)
        {
            receipt.AddValue(0x0C, 5, 1);
            Assert.That(receipt.Verify(Convert.FromHexString("352E57ADDA911EDC")).Value, Is.False);
        }
        using (var reordered = Verifier(64))
        {
            reordered.AddValue(0xDC, 5, 2);
            reordered.AddValue(0x0C, 5, 1);
            Assert.That(reordered.Verify(Convert.FromHexString("7BEE577D5D8D0C69")).Value, Is.False);
        }
    }
}
