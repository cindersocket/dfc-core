# DFC v6 examples

These credentials are **synthetic** and use public test keys. They were not
captured from a physical card. Never install their keys on a production card.
Each `.dfc` file and same-named `.dfcb` file represent the same credential.

| Pair | Shows |
| --- | --- |
| [v6-minimal.dfc](v6-minimal.dfc) / [v6-minimal.dfcb](v6-minimal.dfcb) | A small EV3 PICC with a 2TDEA key, ISO and ISO 7816 support, and ISO 7816 preferred. |
| [v6-auth-commands.dfc](v6-auth-commands.dfc) / [v6-auth-commands.dfcb](v6-auth-commands.dfcb) | Multiple applications, 2TDEA and AES command masks, preferred commands, version overrides, data/value/record files, and application secure-messaging disable. |

The larger pair is also an independent vector in the `dfc-conformance` corpus.
Both pairs can be checked with `tools/dfc_check.py --pair` in
`dfc-conformance`, and with DFC core's text and binary codecs. See the
[full schema](../../docs/credential-schema-v6.md) for every field and tag.
