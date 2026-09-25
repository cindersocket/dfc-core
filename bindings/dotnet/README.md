# Dfc for .NET

`Dfc` is a slim .NET library over the native DFC core. Parsing, validation,
encoding, the card emulator, and the reader's secure messaging all run in
native code. .NET applies exactly the rules a device applies.

| Namespace | Contents |
|---|---|
| `Dfc.Credentials` | The credential record tree and `DfcCredentialCodec` for `.dfc` text and `.dfcb` octets |
| `Dfc.Emulation` | `DfcVirtualPicc`, a card in process |
| `Dfc.Reader` | `DfcReader`, which drives any card through `IDfcApduExchange`, and `DfcCommand` |

## Use

```csharp
var credential = DfcCredentialCodec.Parse(File.ReadAllText("card.dfc")).Value;

using var card = DfcVirtualPicc.Create(credential).Value;
card.Activate();

using var reader = new DfcReader(card);
await reader.ExchangeAsync(DfcCommand.SelectApplication([0x01, 0x00, 0x00]));
await reader.AuthenticateAsync(DfcAuthenticationMode.Aes, 0, key);
var data = await reader.ExchangeAsync(DfcCommand.ReadData(1, 0, 32), DfcCommunicationMode.Mac);
```

A host that loads hardware converts text to octets first:

```csharp
var octets = DfcCredentialCodec.Encode(DfcCredentialCodec.Parse(text).Value).Value;
```

To drive a physical card, implement `IDfcApduExchange` over your transport and
pass it to `DfcReader`. That transport can be PC/SC, a serial bridge, or an NFC
front end.

## Build and test

Build the native library first. The tests load it from `build/` at the root of
the repository:

```sh
cmake -S ../.. -B ../../build -DCMAKE_BUILD_TYPE=Release
cmake --build ../../build
dotnet test Dfc.sln -c Release
```

Set `DfcNativeDirectory` to load the native library from somewhere else. A
packed `Dfc` package carries each platform's native build under `runtimes/`.
