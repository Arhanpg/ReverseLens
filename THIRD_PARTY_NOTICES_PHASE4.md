# Phase 4 third-party tool notices

ReverseLens source remains under the repository's Apache-2.0 license. The following independently maintained tools keep their own licenses and notices. This document records the versions/status used by the Phase 4 adapters; it is not legal advice.

| Tool | Version / source | License noted upstream | Distribution status |
|---|---|---|---|
| APKEditor | 1.4.9 release JAR | Apache-2.0 | Included in standard worker image; pinned SHA-256 |
| APKLeaks | 2.6.3 | Apache-2.0 per upstream README | Included in standard worker image |
| Hermes Decompiler | 0.1.8 | AGPL-3.0-or-later | Optional; not installed by default |
| Blutter | Commit 4a60ac648bf448c5a7596437243bcd0b9376fdf0 | MIT | Optional reviewed checkout; not bundled |
| Ghidra | 12.2 | Apache-2.0 | Optional separately provisioned distribution |
| MobSF | Self-hosted API | GPL-3.0 | External private service; not bundled or hosted by default |
| Exodus Standalone | 1.5.0 | AGPL-3.0 | Optional separately provisioned checkout |
| Quark Engine | Not integrated | Not verified in this milestone | Blocked pending repository/license/CLI compatibility review |

APKEditor 1.4.9 is downloaded from its tagged upstream release and verified against SHA-256 a9cd40df818845456be6d696de6110c89edf4b0a0580cb83438ed6b25a366e67 before being copied into the worker image.

APKLeaks relies on the worker's existing JADX installation. Its normalized output treats URI/string matches as unverified candidates, and recognized token-like strings are redacted. Raw engine output remains in the local workspace and may contain sensitive material; protect and delete workspaces according to your retention policy.

Hermes Decompiler, Blutter, Ghidra and Exodus are not copied into the standard worker image. Provision them separately, inspect upstream notices/dependencies and review the applicable license obligations before distribution or hosted use. MobSF requires its own deployment and API key. Use a private/internal service and do not commit keys or APKs.

The versions/metadata above are tool provenance, not a statement that all license obligations have been independently cleared for every distribution or hosted deployment.
