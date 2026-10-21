# Python virtual-card example

`virtual_card.py` loads the repository's maximal credential, activates a virtual
card, selects its first application, and reads the public backup-data file through
the blocking reader transport. This exercises a real command/response exchange,
including native command framing and application selection.

From the repository root, build the shared library and run the example:

```sh
cmake -S . -B build -DDFC_BUILD_SHARED=ON -DDFC_BUILD_TESTS=OFF
cmake --build build
DFC_LIBRARY_PATH="$PWD/build/libdfc.dylib" \
  uv run --project bindings/python python examples/python/virtual_card.py
```

On Linux, use `build/libdfc.so` instead. To inspect another credential, pass its
path as the first argument. The example expects its first application to expose
file number 2 for free read access, as `v6-maximal.dfcb` does.

Replace `VirtualPicc` with an object that implements
`transceive(command: bytes) -> bytes` to drive a physical reader while keeping
the same `Reader` calls.
