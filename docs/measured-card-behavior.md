# Measured card behavior

The emulator follows what a genuine DESFire EV3 did on the wire. This page lists
the rules that were settled by measurement, the vector that proves each one, and
the checks that stop them from drifting. Everything here can be re-checked by
replaying the vectors; nothing depends on anyone's reading of a document.

## Ground rules

- **A physical-card vector always wins.** If a synthetic vector, a unit test or
  the code disagrees with a capture, the capture is right and the other thing is
  changed.
- **Genuine bytes in physical vectors never change.**
  `scripts/check-physical-vectors-append-only.py` fails a pull request that changes
  a genuine line of a vector with `origin: physical-card`, or deletes or renames
  one. A wrong capture is retired by adding a corrected one and saying why.
  **Annotation is allowed**: comment lines, blank lines, `inject-random` steps
  (the random the card drew, recovered from the capture) and the `replayable:` and
  `requires:` headers. These tell the replay what to do and leave every frame,
  status, setup header and the origin exactly as captured; the gate compares the
  old and new file with those lines removed and requires the rest to be identical.
- **Unmeasured behavior is labelled.** Where no capture exists, the code says so
  in a comment ("not measured") instead of presenting a guess as fact.
- **Generation matters.** Rules measured on an EV3 are applied to EV2 and EV3
  only when an EV1 capture does not contradict them. For example a wrapped native
  APDU must end in an `Le` byte on EV2 and EV3, but a genuine EV1 capture shows
  the card accepting it without one, so EV1 keeps the lenient parse.

## ISO-DEP block layer

Vector: `tests/vectors/desfire/v6/hardware/hardware_physical_ev3_2k_iso_dep_block_numbering.vec`
(the model is also written out above `build_iso_dep_i_block` in
`src/dfc_virtual_picc.c`).

| What the reader sends | What the card does |
| --- | --- |
| Any I-block, with any block number | Answers with its own next number. It never checks the reader's number. |
| A repeated request fragment | Appends it again as a new fragment. |
| Reader R-block repeating the card's last number (ACK or NAK) | Resends the last block it sent, I-block or R(ACK). |
| R(ACK) with the other number | Sends the next block of a response chain, or ignores it if there is none. |
| R(NAK) with the other number | Answers with an R(ACK) carrying its last number. |
| Empty I-block | Answers with an empty I-block. |
| A second RATS in an active session | Ignores it and keeps its numbering. |
| S-block other than DESELECT | Ignores it. DESELECT is answered and ends the session. |
| R-block straight after RATS | Treats its last block as an empty I-block numbered 1. |

A repeated I-block is therefore executed again. Nothing at this layer drops a
replay, so a transport that needs replay protection has to provide it (secure
messaging sessions do, through their own counters and IVs).

The size of each response block follows the frame size the reader announces in
RATS (its FSDI nibble): a block is PCB + INF + 2 CRC bytes, so INF is the frame
size minus three, capped at 48. RATS `E0 00` (16-byte frames) gives 13-byte
pieces. See the last section of the block-numbering vector.

The card keeps one block number per activation. It starts at 0 and toggles each
time the card sends an I-block or an R(ACK) that answers an I-block.

## APDU rules

Vectors: `hardware_physical_ev3_2k_iso_file_negatives.vec` and
`hardware_physical_ev3_2k_bad_commands.vec` in the same directory.

- **Wrapped native commands** (`CLA 90`): `P1 = P2 = 00`; the final `Le` byte is
  required and must be `00`; anything shorter, longer or with another `Le` is
  `91 7E`. With `Lc = 0` only the bare 5-byte form (or the header plus a zero
  extended `Le`) reaches the command.
- **File numbers:** above `1F` is `91 9E`; an unused valid number is `91 F0`; a
  file of the wrong kind for the command is `91 9D`.
- **Short file identifiers** select their file for later commands, including for
  APPEND RECORD, and the selection happens before anything is validated, so a
  failed command still moves it. A reserved identifier (all ones) is `6A 86` and
  an unused one is `6A 82`.
- **READ BINARY / UPDATE BINARY:** with the identifier bit set the offset is the
  low byte alone. An offset at or past the end is `69 85`. An update of zero
  bytes is `67 00`, and one that runs past the end is `69 85`.
- **READ RECORD:** `P2` bits 2-0 must be `100b` (one record) or `101b` (that
  record through the last); anything else is `6A 86`. Record `00` is the last
  written. An absent record, or any record of an empty file, is `69 85`. Cyclic
  files number newest first; this part is **not measured** (the captured card
  had no memory left to build one) and is covered by a unit test that says so.
- **SELECT:** `P2` of `00` and `0C` are accepted, `04` and `08` are `6A 86`; an
  `Lc` that promises data that is not there is `6A 87`.
- **The current file belongs to an application.** A file made current in one
  application is not reachable after another application, or the card level, is
  selected, and selecting an application (even the same one again) or starting a
  new ISO 14443-3 selection ends it. A refused caller (secure session, or a
  Transaction MAC application) is refused before any short identifier is looked
  up, so it learns nothing about which identifiers exist.
- **Parameterless commands** answer `91 7E` to any stray parameter byte.
- **FormatPICC** with format disabled is `91 1C` whether or not the caller is
  authenticated.

A few answers describe the captured card's fill level rather than card behavior
(`91 0E` from creating anything, `FreeMem` of zero). They are noted in comments
in the vector and are not replayed.

## ISO commands and an open native transaction

Vector: `hardware_physical_ev3_2k_iso_write_transaction.vec`, a **provisional
batch** (see `docs/capture-batches.md`; it can be retired as a unit).

- A native WriteRecord waiting for CommitTransaction survives other successful
  commands (native commands, ISO SELECT, a successful ISO READ RECORD).
- A failing command discards it, native or ISO READ RECORD (6985). CommitTransaction
  then answers `0C`.
- A successful ISO APPEND RECORD writes its own record at once and does not publish
  the staged native write; that write is discarded.
- While a transaction is open GetFileSettings reports the committed record count.

## Value-file rights

Vector: `hardware_physical_ev3_2k_value_rights.vec`, a provisional batch
(`docs/capture-batches.md`). One value file, every combination of free, denied, key 0 and
key 1 for the Read, Write and Read&Write rights, each command tried unauthenticated and as
key 0 and key 1.

- GetValue and Debit work with any one of the Read, Write or Read&Write rights.
- LimitedCredit works with the Write or Read&Write right; Read alone is denied.
- Credit needs the Read&Write right; Read or Write alone is denied.
- A command that no right can ever allow answers `9D`. One that a key could allow answers
  `AE` until that key authenticates.

## Which right sets the protection of a value command

Vector: `hardware_physical_ev3_2k_value_comm_modes.vec` (same provisional batch). An
enciphered value file, Debit and Credit sent plain and enciphered, by authorising right and
session key.

- Unauthenticated, a free right makes the command plain.
- Authenticated, if the session key matches any right that can authorise the command, the
  file's mode applies and the command must be enciphered; the plain form answers `7E`.
- Authenticated, if the key matches none of them but one is free, the command is plain and
  the enciphered form answers `7E`.
- So the mode follows the right that authorised the command, not the Write right.
- An enciphered payload that is not a whole number of cipher blocks, and a plain amount that
  is not exactly four bytes, are length errors (`7E`), answered before any integrity check.

## ISO UPDATE BINARY and READ BINARY against an open transaction

Vector: `hardware_physical_ev3_2k_iso_update_binary_transaction.vec` (same provisional batch). A
staged native WriteData on a backup file, or a staged Debit on a value file, with an ISO
command in between.

- A successful ISO UPDATE BINARY publishes the open transaction: the staged write and a
  staged Debit are committed with it, and a later CommitTransaction or AbortTransaction
  answers `0C`.
- An ISO UPDATE BINARY aimed at a backup file is written at once.
- A failing ISO UPDATE BINARY (offset past the end, `6985`) discards the open transaction.
- A successful ISO READ BINARY leaves the staged write alone; CommitTransaction publishes it.
- ISO APPEND RECORD is different: it discards the staged write (see above).

## The communication byte when a file is created

Vector: `hardware_physical_ev3_2k_create_comm_bytes.vec` (same provisional batch), with the SDM
captures in `v4/hardware`. CreateStdDataFile, CreateBackupDataFile, CreateLinearRecordFile and
CreateValueFile, each with an unusual communication byte, then GetFileSettings.

- Mode values 0 to 3 are all accepted and reported back as given.
- Bit 7 (additional access rights) is accepted and reported back, with one zero byte, the count
  of additional access rights, after the settings.
- Bit 2 (a reserved bit) is refused with `9E` on every type.
- The SDM flag (bit 6) is refused with `9E` on a backup, record or value file. On a standard
  data file it is refused with `9D` unless the file has an ISO file id, and accepted with one.

## Rules that are not measured

These follow how DESFire access rights are meant to work, not a capture, and the
code and tests say so. A capture that disagrees replaces them.

- **File creation refuses access rights that name a missing key.** Creating a
  standard, backup, record or value file whose rights name a key the application
  does not have is a parameter error, as ChangeFileSettings already does.
- **Cyclic record numbering** (see READ RECORD above).
- **Cyclic record numbering** (see READ RECORD above).
- **ISO UPDATE BINARY publishes the application's open transaction.** This
  predates this change and a synthetic vector asserts it. The measured ISO APPEND
  RECORD behaviour below contradicts the same assumption for APPEND RECORD, so UPDATE
  BINARY is likely wrong too; it stays until it can be captured (the captured card had
  no data file that was writable without authentication).

## What keeps these true

| Check | What it prevents |
| --- | --- |
| `tests/check_iso_dep_block_numbers.py` | A vector, physical or synthetic, that breaks the block-number rules. It is an independent model, so the emulator and the check cannot share a bug. |
| `tests/check_virtual_picc_staging.py` | Writes to retry or reassembly storage, or to the card block number, from outside the functions that bound or own them. |
| `tests/test_dfc_iso_dep_frame_properties.c` | Thousands of random frames and response-buffer sizes, with the storage and block-number invariants checked after every one. Run it under ASan and UBSan. |
| `scripts/check-physical-vectors-append-only.py` | Editing a genuine capture to make something pass. |

## Superseded notes in older captures

Captures are never edited, so a comment in one can outlive the understanding that
produced it. `hardware_physical_ev3_2k_iso_dep_request_chaining.vec` says a
repeated old-sequence fragment "is not appended twice". Its frames are genuine,
but the comment over-read them: that trace ends in a length error whether or not
the repeat was appended. The block-numbering vector above shows the repeat IS
appended, and it is the authority.

## Adding a capture

1. Build frames as raw wire bytes. The card ignores the reader's block number,
   but alternate it anyway so only the content under test varies.
2. Start each section from a fresh selection and RATS, and set any state it needs
   in the section itself, so sections replay independently.
3. Record silence as `expect-error protocol-error frame-exchange ...`.
4. Replay the section against the emulator. If it differs, fix the emulator, not
   the capture.
5. Regenerate the manifest with `python3 tests/check_desfire_vectors.py --write-manifest`.
