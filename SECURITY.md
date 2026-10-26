# Security policy

## Supported versions

| Version | Security support |
| --- | --- |
| 2.0.x | Supported |
| 1.2.x | Not supported |
| Earlier releases | Not supported |

The changelog identifies the current release status. This table is updated when
a release changes the supported lines.

## Report a vulnerability privately

Use a [private GitHub security advisory](https://github.com/cindersocket/dfc-core/security/advisories/new).
If that is unavailable, email [cindersocket@protonmail.ch](mailto:cindersocket@protonmail.ch).
Do not open a public issue for a suspected vulnerability.

Include the affected version or commit, reproduction steps, expected impact,
and the build, platform, and crypto backend involved. Say whether the evidence
comes from physical hardware, a captured trace, or a synthetic test. Include a
minimal reproducer when it is safe to share privately.

Do not send production keys, credentials, cardholder data, proprietary traces,
or other third-party secrets. Replace them with synthetic material that still
reproduces the problem.

## What to expect

We aim to acknowledge a report within five business days and provide periodic
status updates while it is under review. These are communication targets, not
remediation guarantees. Complexity, interoperability testing, and access to
affected hardware can change the repair schedule.

We will distinguish reproducible implementation defects from unsupported
configurations, interoperability differences, and side-channel claims that
require target-hardware evidence. We may ask for more evidence before assigning
impact or affected versions.

Please coordinate publication while a fix and release are prepared. We will
discuss disclosure timing, advisory and CVE handling, and credit before making
technical details public. Tell us if you prefer anonymity. Duplicate reports
are handled using the earliest complete private report.

Cryptographic and interoperability testing does not constitute certification or
a guarantee that the software is free of security defects.
