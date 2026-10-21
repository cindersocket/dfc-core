# dfc-core for Python

`dfc_core` is the blocking Python 3.11+ interface to dfc-core. Protocol rules,
cryptography, credential validation, and secure messaging remain in the native
library. Python owns handles, transports frames, and presents immutable values.

Set `DFC_LIBRARY_PATH` to an exact `libdfc` path while developing. Production
wheels place the matching native library in `dfc_core/lib/`. Loading fails before
the first operation when the ABI version or any shared structure layout differs.

```python
from dfc_core import Credential, VirtualPicc

with Credential.load(open("card.dfcb", "rb").read()) as credential:
    with VirtualPicc(credential) as picc:  # consumes credential on current ABIs
        activation = picc.activate()
        answer = picc.exchange(bytes.fromhex("9060000000"))
```

A reader uses a small blocking transport protocol:

```python
from dfc_core import Command, Reader

class Device:
    def transceive(self, command: bytes) -> bytes:
        return send_to_device(command)

with Reader(Device()) as reader:
    response = reader.exchange(Command.select_application(bytes.fromhex("000000")))
```

`Credential`, `VirtualPicc`, and `Reader` are context managers. Their finalizers
are a fallback, not the normal lifetime mechanism. Calls on one handle are
serialized, but a transport still controls its own thread safety.

Key and generated challenge copies held in mutable native/Python buffers are
wiped after use. Python cannot wipe immutable `bytes` supplied by an application;
applications with strict secret-lifetime requirements should avoid retaining
extra immutable copies.

Random callbacks must return exactly the requested number of bytes. Exceptions
are captured, the native callback falls back to the operating system random
source, and Python raises after native control returns, so an exception never
unwinds through C. The buffer is cleared only if that fallback also fails.

