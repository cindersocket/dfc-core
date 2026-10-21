# DFC for .NET

`Dfc` is a .NET 10 binding for credential codecs, an in-process virtual card,
and reader-side secure messaging. Protocol behavior runs in the native DFC
core; the managed layer owns resources and adapts transports.

## API map

| Namespace | Purpose |
|---|---|
| `Dfc.Credentials` | Read, validate, and write `.dfc` text and `.dfcb` octets |
| `Dfc.Emulation` | Activate and transceive with `DfcVirtualPicc` |
| `Dfc.Reader` | Drive a virtual or physical card through `IDfcApduExchange` |

## Load and transceive

Handle `Result` failures before taking `.Value`. Both the card and reader own
native resources and must be disposed:

```csharp
var loaded = DfcCredentialCodec.Load(await File.ReadAllBytesAsync("card.dfc"));
if (loaded.IsFailure)
    throw new InvalidDataException(loaded.Error.ToString());

var created = DfcVirtualPicc.Create(loaded.Value);
if (created.IsFailure)
    throw new InvalidOperationException(created.Error.ToString());
using var card = created.Value;

var activated = card.Activate();
if (activated.IsFailure)
    throw new InvalidOperationException(activated.Error.ToString());

using var reader = new DfcReader(card);
var exchanged = await reader.ExchangeAsync(DfcCommand.GetVersion());
if (exchanged.IsFailure)
    throw new InvalidOperationException(exchanged.Error.ToString());
var version = exchanged.Value;
```

`DfcVirtualPicc` implements `IDfcApduExchange`. For hardware, implement that
interface over PC/SC, NFC, or a serial bridge and pass it to `DfcReader`.
Transport failures clear the managed reader session.
`DfcCommand.SelectApplication` accepts the same human-readable AID byte order
used by `DfcApplication.Aid` and converts it to wire order.

The runnable [.NET example](../../examples/dotnet/README.md) validates a
credential, activates a virtual card, and performs a multi-frame `GetVersion`
exchange through the public reader and transport APIs.

## Build and verify

From the repository root, build the native library before the managed code:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
  -DDFC_ROLE=simulator -DDFC_PROFILE=full_ev3 -DDFC_CRYPTO=tiny
cmake --build build --parallel
dotnet test bindings/dotnet/Dfc.sln -c Release
dotnet run --project examples/dotnet/Dfc.TransceiveExample.csproj \
  -- examples/credentials/v6-minimal.dfc
```

Set `DfcNativeDirectory` if the native build is elsewhere. Published packages
place the library under `runtimes/<RID>/native`; local builds copy it beside the
test or example assembly.
