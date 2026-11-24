# Phase 1 pinned tool versions

| Tool | Pin | Phase 1 role | License note |
|---|---:|---|---|
| JADX | 1.5.7 | DEX to Java-like source | Apache-2.0 |
| Apktool | 3.0.3 | Manifest/resources/Smali decoding | Apache-2.0 |
| Androguard | 4.1.4 | APK metadata and DEX inventory | Apache-2.0 |
| APKiD | 3.2.0 | Compiler/packer fingerprinting | Dual licensed upstream; verify terms |
| bundletool | 1.18.3 | AAB validation/manifest and APKS split inspection | Apache-2.0 |

The Dockerfile verifies SHA-256 release asset digests for JADX, Apktool and bundletool. Python packages are version-pinned in `worker/requirements.txt`.

Upstream releases:
- https://github.com/skylot/jadx/releases/tag/v1.5.7
- https://github.com/iBotPeaches/Apktool/releases/tag/v3.0.3
- https://github.com/androguard/androguard/releases/tag/v4.1.4
- https://github.com/rednaga/APKiD/releases/tag/v3.2.0
- https://github.com/google/bundletool/releases/tag/1.18.3
