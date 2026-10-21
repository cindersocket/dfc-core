# .NET transceive example

This console app loads a `.dfc` or `.dfcb` credential, activates an in-process
card, and sends `GetVersion` through `DfcReader`. The reader communicates only
through `IDfcApduExchange`, so the same flow works with a hardware adapter.

From the repository root, build the native library and run the app with the
.NET 10 SDK:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
  -DDFC_ROLE=simulator -DDFC_PROFILE=full_ev3 -DDFC_CRYPTO=tiny
cmake --build build --parallel
dotnet run --project examples/dotnet/Dfc.TransceiveExample.csproj \
  -- examples/credentials/v6-minimal.dfc
```

For a physical card, implement `IDfcApduExchange` and pass that transport to
`DfcReader` instead of `DfcVirtualPicc`.
