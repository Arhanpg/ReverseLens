# Phase 1 third-party tool notices

ReverseLens's own source code remains governed by the repository's Apache-2.0 license. The following independently maintained tools are installed into the local Phase 1 worker image and retain their own licenses and notices.

| Tool | Version | Upstream license note | Source |
|---|---:|---|---|
| JADX | 1.5.7 | Apache-2.0 | https://github.com/skylot/jadx |
| Apktool | 3.0.3 | Apache-2.0 | https://github.com/iBotPeaches/Apktool |
| Androguard | 4.1.4 | Apache-2.0 | https://github.com/androguard/androguard |
| APKiD | 3.2.0 | Upstream states dual GPL/commercial licensing; review exact terms | https://github.com/rednaga/APKiD |
| bundletool | 1.18.3 | Apache-2.0 | https://github.com/google/bundletool |

**Distribution warning:** the Phase 1 worker Docker image installs APKiD. Before distributing a prebuilt image or hosted offering, review APKiD's exact LICENSE.GPL and LICENSE.COMMERCIAL terms and dependency notices. This table is not a substitute for license review. Third-party tool licenses do not change the license of ReverseLens's own code.
