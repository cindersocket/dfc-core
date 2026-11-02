# DFC for .NET

`Dfc` is a .NET 10 binding for credential codecs, an in-process virtual card,
and reader-side secure messaging. Protocol behavior runs in the native DFC
core; the managed layer owns resources and adapts transports.

Install the package, which selects its native library from `runtimes/`:

```xml
<PackageReference Include="Dfc" Version="2.0.0" />
```

## API map

| Namespace | Purpose |
|---|---|
| `Dfc.Credentials` | Read, validate, and write `.dfc` text and `.dfcb` octets |
| `Dfc.Emulation` | Activate and transceive with `DfcVirtualPicc` |
| `Dfc.Reader` | Drive a card and decode clear responses into typed records |
| `Dfc.Crypto` | Derive AES and two- or three-key TDEA application keys |
| `Dfc.Sdm` | Authenticate ASCII SDM input and return verified mirrored fields |
| `Dfc.Transactions` | Reconstruct transaction input and verify its returned receipt |

Raw `DfcResponse` values remain available to applications that need commands
outside the typed decoder set. `DfcSdmVerifier.Verify` authenticates one
message. The backend must persist the last accepted read counter for the
relevant card and application context, then reject duplicate or older counters
before acting on the result. The binding does not store replay state.

`DfcTransactionMacVerifier` follows the
[native transaction-input contract](../../src/dfc_transaction_mac.h) for its
supported commands, fields, padding, and card-order rules. Receipt counter
history and duplicate detection remain application policy.

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

For deterministic tests, pass a `DfcScriptedRandomSource` to
`DfcVirtualPicc.Create`. `Append` queues bytes for later random requests,
`Remaining` reports the unread count, and `Clear` wipes and discards unread
bytes before a new replay segment is appended. A request larger than the queue
fails without consuming bytes.

The runnable [.NET example](https://github.com/cindersocket/dfc-core/tree/master/examples/dotnet) validates a
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
  -- examples/credentials/v6-minimal.dfcb
```

The production project generates XML documentation and treats missing public
API documentation (`CS1591`) as an error, so the normal Release test build is
also the binding documentation gate.

Set `DfcNativeDirectory` if the native build is elsewhere. Published packages
place the library under `runtimes/<RID>/native`; local builds copy it beside the
test or example assembly. The assembly verifies the complete generated native
layout fingerprint before constructing a handle.


## Conformance vectors

The DESFire conformance vectors replay through this binding's virtual card: `dotnet test bindings/dotnet/tests/Dfc.Tests/Dfc.Tests.csproj --filter FullyQualifiedName~ReplayPlanTests`. It reports how many vectors it replayed and skipped. See [Replay plans](../../docs/conformance-vector-format.md#replay-plans).

## Secret lifetime

Ordinary card snapshots exclude session keys. `DiagnosticSnapshot()` returns a
disposable secret-bearing object for diagnostics and conformance tests; dispose
it promptly to clear its managed buffers. The runtime may retain copies created
by application code. Credential records expose mutable `byte[]` fields whose
lifetime belongs to the caller; native marshalling temporaries are cleared on
every exit.

## Security

Report suspected vulnerabilities through the project's
[private reporting process](https://github.com/cindersocket/dfc-core/security/policy).
