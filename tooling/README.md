# Optional specialist tool provisioning

This directory is mounted read-only into the local worker at /opt/reverselens-tooling. It contains no third-party binaries by default.

Expected optional layouts:

- blutter/: reviewed Blutter checkout with blutter.py and prebuilt bin/ Dart VM binaries.
- ghidra/: unpacked Ghidra 12.2 distribution with support/analyzeHeadless.
- exodus-standalone/: reviewed Exodus Standalone checkout with exodus_analyze.py.

Do not commit tool binaries, Dart SDKs, private APKs, API keys, MobSF reports or proprietary decompilation outputs. Keep the optional checkouts local or manage them through your own artifact/provisioning process.

Compose configures BLUTTER_HOME, GHIDRA_HOME and EXODUS_ANALYZE to these paths. A missing optional tool results in an explicit failed tool execution with a useful configuration message; a runtime mismatch results in incompatible before the tool is invoked.

MobSF is not mounted here. Point MOBSF_URL to a separate private/self-hosted service reachable only on the internal backend network and provide MOBSF_API_KEY through an environment secret. Do not expose the MobSF service or worker network to untrusted public traffic.
