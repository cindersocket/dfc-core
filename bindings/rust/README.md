# dfc-core for Rust

`dfc-core` is the safe, idiomatic Rust interface to DFC. `dfc-core-sys` is the
raw C ABI crate. The default build compiles a simulator-role, full-EV3 native
library and requires no preinstalled `libdfc`.

```rust,no_run
use dfc_core::{Credential, VirtualPicc};

let credential = Credential::load(include_bytes!("card.dfcb"))?;
let mut picc = VirtualPicc::from_credential(credential)?;
let activation = picc.activate()?;
# Ok::<(), dfc_core::Error>(())
```

Disable default features and enable `system` to link an installed `libdfc`.
Set `DFC_LIB_DIR` when it is outside the platform linker search path. Handles
can move between threads, but are deliberately not shareable between threads.

For firmware, disable defaults and select one target profile, for example
`bundled,role-target,profile-full-ev3`. This exposes the `no_std`
`TargetCredential` and `TargetVirtualPicc` API. The binding asks native code for
the exact storage layouts, owns those allocations in Rust, and accepts caller
buffers for encoding and exchanges. The platform still supplies the normal DFC
port functions and the one protocol-session allocation.

Target builds do not enable workstation capacities. File, key, and application
storage stays at the selected native profile values unless the application
explicitly overrides the corresponding CMake capacity variables.

