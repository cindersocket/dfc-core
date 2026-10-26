using Dfc.Credentials;
using Dfc.Emulation;
using Dfc.Reader;
using Dfc.Sdm;
using Dfc.Transactions;

if (args.Length != 1)
{
    Console.Error.WriteLine("usage: dotnet run --project examples/dotnet -- <credential.dfc|dfcb>");
    return 2;
}

// Load accepts both credential encodings, which avoids trusting the extension.
var loaded = DfcCredentialCodec.Load(await File.ReadAllBytesAsync(args[0]));
if (loaded.IsFailure)
{
    Console.Error.WriteLine($"Credential rejected: {loaded.Error}");
    return 1;
}

var created = DfcVirtualPicc.Create(loaded.Value);
if (created.IsFailure)
{
    Console.Error.WriteLine($"Card creation failed: {created.Error}");
    return 1;
}

// The virtual PICC implements the same transport contract used by hardware adapters.
using var picc = created.Value;
var activated = picc.Activate();
if (activated.IsFailure)
{
    Console.Error.WriteLine($"Activation failed: {activated.Error}");
    return 1;
}

using var reader = new DfcReader(picc);
// DfcReader follows GetVersion's additional frames and assembles one response.
var exchanged = await reader.ExchangeAsync(DfcCommand.GetVersion());
if (exchanged.IsFailure || exchanged.Value.Status != 0 || exchanged.Value.Data.Length != 28)
{
    Console.Error.WriteLine(exchanged.IsFailure
        ? $"GetVersion failed: {exchanged.Error}"
        : $"GetVersion returned status {exchanged.Value.Status:X2}");
    return 1;
}

Console.WriteLine($"UID: {Convert.ToHexString(activated.Value.Uid)}");
var version = DfcResponseDecoders.DecodeVersion(exchanged.Value.Data);
if (version.IsFailure)
{
    Console.Error.WriteLine($"GetVersion decoding failed: {version.Error}");
    return 1;
}
Console.WriteLine($"GetVersion UID: {Convert.ToHexString(version.Value.Uid)}");

var applications = await reader.ExchangeAsync(DfcCommand.GetApplicationIds());
if (applications.IsSuccess && applications.Value.Status == 0)
{
    var aids = DfcResponseDecoders.DecodeApplicationIds(applications.Value.Data);
    if (aids.IsSuccess && aids.Value.Count > 0)
    {
        await reader.ExchangeAsync(DfcCommand.SelectApplication(aids.Value[0]));
        var filesResponse = await reader.ExchangeAsync(DfcCommand.GetFileIds());
        var files = DfcResponseDecoders.DecodeFileIds(filesResponse.Value.Data);
        if (files.IsSuccess && files.Value.Count > 0)
        {
            var settingsResponse = await reader.ExchangeAsync(DfcCommand.GetFileSettings(files.Value[0]));
            var settings = DfcResponseDecoders.DecodeFileSettings(settingsResponse.Value.Data);
            if (settings.IsSuccess)
                Console.WriteLine($"File {files.Value[0]}: type={settings.Value.Type} communication={settings.Value.CommunicationMode}");
        }
    }
}

var sdmMessage = "0483B4F2CF1890000001163F0AC4319102F37F4B61FE6BFDE1469CF53E287D682A2E"u8;
var sdmConfig = new DfcSdmConfig(20, 52, new DfcSdmField(0, 7), 14,
    EncryptedFileData: new DfcSdmField(20, 32));
var verifiedSdm = DfcSdmVerifier.Verify(sdmMessage, sdmConfig, new byte[16]);
if (verifiedSdm.IsFailure)
{
    Console.Error.WriteLine($"SDM verification failed: {verifiedSdm.Error}");
    return 1;
}
Console.WriteLine($"Verified SDM UID: {Convert.ToHexString(verifiedSdm.Value.Uid!)}, counter={verifiedSdm.Value.ReadCounter}");

// Mirror the plain Credit operation, then authenticate the CommitTransaction receipt.
var receiptResult = DfcTransactionMacVerifier.Create(
    new byte[16], Convert.FromHexString("0483B4F2CF1890"), 1);
if (receiptResult.IsFailure)
{
    Console.Error.WriteLine($"Transaction verifier failed: {receiptResult.Error}");
    return 1;
}
using (var receipt = receiptResult.Value)
{
    var added = receipt.AddValue(0x0C, 5, 1);
    var receiptVerified = receipt.Verify(Convert.FromHexString("352E57ADDA911EDC"));
    if (added.IsFailure || receiptVerified.IsFailure || !receiptVerified.Value)
    {
        Console.Error.WriteLine("Transaction receipt did not match");
        return 1;
    }
}
Console.WriteLine("Transaction receipt verified");
return 0;
