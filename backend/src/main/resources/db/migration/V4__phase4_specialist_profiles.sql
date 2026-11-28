-- Phase 4 specialist Android/native benchmark profiles.
-- Runtime-incompatible attempts remain visible but are excluded from accuracy scoring.
INSERT INTO benchmark_profiles(
  profile_key,name,platform,capability_classes,engine_ids,default_repetitions,default_concurrency,is_builtin
) VALUES
(
  'android-specialist-foundation','Android specialist foundation','android',
  'apk_processing,android_resources,manifest,smali,uri_extraction,string_pattern_triage,tracker_signature_matching,mobile_static_analysis,elf_analysis,arm64_disassembly,native_pseudocode,native_call_graph',
  'apkeditor,apkleaks,exodus-standalone,mobsf,ghidra',1,1,TRUE
),
(
  'android-flutter-aot','Android Flutter ARM64 AOT','android',
  'flutter_aot,dart_object_pool,arm64','blutter',1,1,TRUE
),
(
  'android-react-native-hermes','Android React Native Hermes','android',
  'react_native,hermes_bytecode','hermes-dec',1,1,TRUE
)
ON CONFLICT(profile_key) DO UPDATE SET
  name=EXCLUDED.name,
  capability_classes=EXCLUDED.capability_classes,
  engine_ids=EXCLUDED.engine_ids,
  default_repetitions=EXCLUDED.default_repetitions,
  default_concurrency=EXCLUDED.default_concurrency,
  is_builtin=TRUE;
