# Provisional capture batches

A capture batch is a set of physical-card vectors taken in one sitting from one
card that has not yet been proven healthy. Every vector in a batch carries two
headers:

```
capture-batch: <batch-id>
capture-status: provisional
```

If the card turns out to be faulty, the whole batch is thrown away: delete the
files listed below, and anything in the emulator that was changed *only* because
of them (listed under "What it changed") is put back or re-measured.

The append-only gate (`scripts/check-physical-vectors-append-only.py`) lets a
provisional capture be **deleted**. It still rejects editing or renaming one, and a
genuine capture cannot be turned provisional afterwards (adding the header is an
edit). `tests/check_desfire_vectors.py` requires a provisional vector to be
`origin: physical-card` and to name its batch.

To list a batch:

```
grep -l 'capture-batch: iso-write-2026-11-01' tests/vectors/desfire/v*/*/*.vec
```

## iso-write-2026-11-01

- **Card:** the second genuine DESFire EV3 2K used for the other
  `hardware_physical_ev3_2k_*` captures (random UID; application `123456`, linear
  record file 3 with ISO id `1003`, free access, four 4-byte records). The card has
  no free memory, so only files already on it could be used.
- **Taken with:** Proxmark3, raw ISO-DEP frames in one session per section. Each
  section begins by emptying file 3 (ClearRecordFile, CommitTransaction) so sections
  replay independently.
- **File:** `tests/vectors/desfire/v6/hardware/hardware_physical_ev3_2k_iso_write_transaction.vec`
- **What it shows:**
  - A native WriteRecord waiting for CommitTransaction survives other successful
    commands: native commands, ISO SELECT, a successful ISO READ RECORD.
  - Any failing command discards it: a native error, or an ISO READ RECORD that
    answers 6985. CommitTransaction then answers `0C`.
  - A successful ISO APPEND RECORD writes its own record at once and does **not**
    publish the staged write. The staged write is discarded.
  - While a transaction is open, GetFileSettings reports the committed record count.
- **What it changed in the emulator** (undo these if the batch is retired):
  - `src/dfc_virtual_picc.c`: ISO APPEND RECORD discards the open transaction before
    appending (was: published it); an ISO READ RECORD that fails discards the open
    transaction (`abort_transaction_after_failed_iso_data_command`).
  - `src/dfc_emulator_commands_lifecycle.c`: GetFileSettings reports the committed
    record count of a record file while a transaction is open.
  - `tests/test_dfc_iso_file_access.c`: `append-record-transaction-and-cyclic` follows the vector.

## value-rights-2026-11-01

- **Card:** a factory-fresh genuine DESFire EV3 2K (random UID, PICC master key at its zero
  default, format enabled). One application with two keys and one value file whose rights are
  changed section by section.
- **Taken with:** Proxmark3 in one interactive session per section, real DES (legacy)
  authentication with the card's own random recovered from its first answer.
- **Files:** `tests/vectors/desfire/v6/hardware/hardware_physical_ev3_2k_value_rights.vec` and
  `hardware_physical_ev3_2k_value_comm_modes.vec` and
  `hardware_physical_ev3_2k_iso_update_binary_transaction.vec` and
  `hardware_physical_ev3_2k_create_comm_bytes.vec`
- **What it shows:** which of the Read, Write and Read&Write rights each of GetValue, Credit,
  Debit and LimitedCredit needs, when a refusal is `AE` versus `9D`, and which right decides
  whether an authenticated value command is plain or enciphered, and how ISO UPDATE BINARY and
  READ BINARY interact with an open native transaction, and how file creation treats unusual
  communication bytes.
- **What it changed in the emulator** (undo these if the batch is retired):
  - `src/dfc_emulator_commands_transactions.c`: GetValue accepts the Write right too; the
    refusal status of GetValue, Credit, Debit and LimitedCredit follows which rights could
    authorise the command (`value_refusal_status`); a plain amount must be exactly four bytes
    and an enciphered one a whole number of cipher blocks.
  - `src/dfc_emulator_access.c`: `dfc_emulator_file_effective_comm_settings_for_rights`, the
    protection of a value command follows the right that authorised it.
  - `src/dfc_virtual_picc.c`: a failing ISO UPDATE BINARY discards the open transaction
    (`abort_transaction_after_failed_iso_data_command`).
  - `tests/test_dfc_transaction_selection.c`: the failing-update cases of the old unit test were
    removed in favour of the vector.
  - `src/dfc_common.c`, `src/dfc_emulator_commands_lifecycle.c`: file creation accepts mode 2 and
    the additional-access-rights flag and refuses the SDM flag except on a standard data file
    with an ISO file id; GetFileSettings appends the zero count byte; ChangeFileSettings accepts
    SDM only on standard data files.
  - `src/dfc_ev2.c`: the EV2 layer picks the protection of a value command with the same
    set-level rule as the native handlers.
  - `tests/test_dfc_der.c`, `tests/test_dfc_text.c`, `tests/test_dfc_model.c`: the byte they use
    as "invalid" is now `0x04`, and the model sweep expects modes 0-3 and bit 7 to be valid.
