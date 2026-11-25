# DFC emulator vector format, version 2

A vector is a UTF-8, line-oriented scripted card session. Blank lines and lines
starting with `#` are ignored. Informational and PICC headers use `key: value`.
Steps start at the first non-header line. Unknown headers are ignored so later
corpus revisions can add setup data without breaking older runners. Unknown
steps and assertion paths are errors.

## Steps

- `scan` activates the card.
- `field-off` drops the field and ends the authenticated session.
- `exchange <dialect> <request> => <response>` exchanges a command using
  `native`, `native-apdu`, or `iso-apdu` without translating its bytes.
- `status <apdu> => <sw>` requires a response of exactly `91 <sw>`.
- `frame-exchange <frame> => <response>` exchanges a raw ISO-DEP frame.
- A vector containing `random-source finite` or `inject-random` uses an empty,
  finite replay queue from creation. A draw larger than the queued bytes fails.
- `random-source finite` discards any unread replay bytes and leaves the finite
  queue empty.
- `inject-random <hex>` appends bytes to the replay queue at that exact point.
  A runner rejects the vector if it cannot append every byte without truncation.
- `expect-error random-source scan` requires activation to fail because the
  finite replay queue cannot satisfy a draw.
- `expect-error random-source exchange <dialect> <request>` and
  `expect-error random-source frame-exchange <frame>` require the operation to
  report a random-source failure with an empty response. The failed draw must
  consume no queued bytes or change session state.
- `expect-error protocol-error frame-exchange <frame>` requires raw ISO-DEP
  processing to report a protocol error with an empty response. The session
  remains active so later steps can verify that a retry or reset recovers.
- `advance-time <milliseconds>` advances the injected monotonic clock.
- `assert <path> = <value>` compares credential, emulator, or activation state.
- `clear-dirty` clears the credential persistence flag.
- `set-model <path> = <value>` mutates a supported numeric model field for a
  synthetic boundary case. Supported fields cover application key storage,
  key-set metadata, authentication-command override flags, and SDM encrypted
  file ranges.
- `roll-model-key-set <application> <key-set>` rotates a modeled key set without
  requiring a secure-channel transcript.

Expected response bytes can contain `??`, which matches one octet. Other hex is
uppercase and contains complete octets.

An `exchange` or `frame-exchange` step can end with one or more tolerance
clauses after its expected response:

```text
exchange native-apdu 906E000000 => 001F009100 tolerance 0+3 512
```

`tolerance <offset>+<length> <delta>` reads the `length` octets that start at
octet `offset` of the response, counted from zero, as an unsigned little-endian
integer, 1 to 4 octets long. The actual integer may differ from the expected one
by at most `delta`, a decimal number of units. Every other octet, and the
response length, still compares exactly, and a tolerated field cannot overlap a
`??` octet or another tolerated field. A tolerance is for a quantity that is a
property of one chip's memory layout rather than of the protocol, such as free
space, and a vector that uses one says why in a comment.

## Headers

`name`, `description`, `source`, `case-id`, and `requires` are informational.
Every DESFire vector also has `origin: physical-card` or `origin: synthetic`.
`case-id` is globally unique. `requires` is a comma-separated list of feature
names used by reduced-profile runners; unknown names fail corpus validation.
Use `auth-d40`, `auth-iso`, and `auth-aes` for vectors that authenticate with
those native commands. A full EV3 runner executes every replayable vector.

The supported PICC setup headers are `uid`, `picc-generation`, `picc-storage`,
`picc-key-settings-1`, `picc-key-settings-2`,
`picc-auth-mode`, `picc-key-len`, `picc-key`, `picc-key-version`,
`picc-random-id`, `picc-format-disabled`, `picc-ats`, `picc-sak`,
`picc-atqa`, `picc-hardware-version`, and `picc-software-version`. Version
headers are optional seven-octet raw GetVersion frames.
`picc-ev2-card-capabilities` supplies six PICC capability bytes for EV2 First
authentication at the PICC master AID. EV2 and EV3 support
`picc-static-signature`. EV3 setup also supports `picc-proximity-key`,
`picc-proximity-option`, `picc-proximity-published-response-time`,
`picc-proximity-bitrate`.

EV2 setup supports the delegated-application master keys
`picc-dam-auth-key`, `picc-dam-mac-key`, and `picc-dam-encryption-key`, and the
virtual-card group `vc-iid`, `vc-info`, `vc-capabilities`, `vc-uid`,
`vc-select-mac-key`, `vc-select-enc-key`, `vc-auth-mandatory`, and
`vc-pc-mandatory`. A runner whose build omits a feature ignores the headers that
configure it.

## Assertion paths

Runners support the following paths:

```text
credential.dirty
credential.num_apps
credential.num_files
credential.uid
credential.model_status
apps[i].aid
apps[i].key_settings_1
apps[i].key_settings_2
apps[i].auth_command
apps[i].num_keys
apps[i].key_len
apps[i].keys[k]
apps[i].key_versions[k]
apps[i].num_key_sets
apps[i].max_key_size
apps[i].key_set_settings
apps[i].key_set_versions[k]
apps[i].key_set_types[k]
apps[i].key_set_initialized[k]
apps[i].has_iso_file_id
apps[i].iso_file_id
apps[i].iso_aid_len
files[i].app_index
files[i].number
files[i].type
files[i].comm_settings
files[i].access_rights
files[i].has_iso_file_id
files[i].iso_file_id
files[i].data_len
files[i].data
files[i].record_count
files[i].value
files[i].transaction_counter
emulator.selected_application
emulator.secure_messaging
emulator.virtual_card_selected
session.transaction_identifier
session.command_counter
session.encryption_key
session.mac_key
activation.uid
activation.uid_len
activation.sak
activation.atqa
activation.ats
```

`emulator.secure_messaging` is `null` or `present`. Activation assertions are
valid only after `scan` and before `field-off`.

`native` records the native command octets and native status. `native-apdu`
records the complete proprietary APDU and a response ending in `91xx`.
`iso-apdu` records a complete standard ISO command and its ISO status word.
Frame boundaries and response chaining are part of the expected evidence.

## Replay plans

The language bindings do not parse vectors. `make -C tests replay-plans` runs the
C runner with `--export-plans`, which writes one plan per replayable vector to
`tests/replay-plans/`, named `<version>-<directory>-<vector>.plan`. A plan is
recorded while the C engine passes the vector, so it carries what the engine did
rather than a second reading of the headers. Plans are committed, and
`make -C tests check-replay-plans` (part of `make -C tests test`) fails when a
vector changed without regenerating them. Committing keeps every binding job
free of the C runner and its crypto backend.

A plan is lines of `key value`, with uppercase hex and `-` for no bytes:

```text
plan 1
source v6-synthetic-finite-random-reset
random finite               # `finite`: draw from the injected queue; `os`: system random
credential <hex>            # the initial model after every header, in the DER encoding
step scan | field-off | clear-dirty | advance-time <ms>
step random-clear | random-inject <hex>
step exchange <request> <expected> [tol=<offset>+<length>:<delta> ...]
step frame <request> <expected> [tol=...]
step error random-source|protocol-error scan|exchange|frame [<request>]
step assert <path> <value>
final <hex>                 # the C engine's credential after the last step
skip <reason>               # instead of the lines above, a counted skip
```

`status` and `select-application` are already expanded to `exchange`, and a scan
the runner performed implicitly is explicit. `??` and `tol=` keep their meaning.
A binding replays each step through its own virtual PICC, injects randoms from a
queue that refuses, without consuming, a draw it cannot fill, and finally
exports its credential and compares the encoding to `final`. It evaluates the
`credential.dirty` and `activation.*` assertions itself; the other credential
assertions are covered by the final comparison, and `emulator.*` and `session.*`
assertions are checked by the C runner only.

Two vectors are skipped by every binding, with the reason in the plan:
`set-model` and `roll-model-key-set` edit the model in place, which no binding
exposes, and `vecb-ev1-create-file-full-pool` expects the runner's compile-time
file table, which is smaller than the one the shipped libraries use.

Run a binding's replay locally (each prints replayed and skipped counts):

```sh
# Python (after building libdfc, see the binding README)
DFC_LIBRARY_PATH=build/libdfc.so pytest bindings/python/tests/test_replay_plans.py -s
# Rust
cargo test -p dfc-core --test replay_plans -- --nocapture
# .NET
dotnet test bindings/dotnet/tests/Dfc.Tests/Dfc.Tests.csproj --filter FullyQualifiedName~ReplayPlanTests --logger "console;verbosity=detailed"
# Java (after building the JNI library as in CI)
java -Djava.library.path=build-jni -cp build-jni/java DfcReplayPlanTest tests/replay-plans
```

See also [Measured card behavior](measured-card-behavior.md) for the rules the
physical-card vectors establish and how a new capture is added.
