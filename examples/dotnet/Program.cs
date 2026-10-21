using Dfc.Credentials;
using Dfc.Emulation;
using Dfc.Reader;

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
Console.WriteLine($"GetVersion: {Convert.ToHexString(exchanged.Value.Data)}");
return 0;
