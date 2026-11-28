package io.reverselens.api;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

record DatasetRequest(String datasetId,String name,String version,String sourceType,String description,
 List<String> platforms,List<String> capabilityClasses,List<UUID> targetIds,String sourceRepository,
 String sourceRevision,String artifactManifestSha256,Boolean groundTruthAvailable,String licenseIdentifier,
 String redistributionStatus,String licenseNotes,String maintainerNotes) {}
record GroundTruthRequest(String capabilityClass,String itemType,String expectedValue,String canonicalKey,
 String validationStatus,Map<String,Object> sourceReference,List<String> owaspMappings,String reviewer,String notes) {}
record ProfileRequest(String profileKey,String name,String platform,List<String> capabilityClasses,
 List<String> engineIds,Integer defaultRepetitions,Integer defaultConcurrency,String description) {}
record ExperimentRequest(String name,String datasetId,String profileKey,List<UUID> targetIds,List<String> engineIds,
 Integer repetitions,Integer concurrency,String cachePolicy,String notes) {}
record WorkerBenchmarkData(String inputSha256,Map<String,Object> metrics,
 List<Map<String,Object>> observations,List<String> limitations) {}

@Service
class BenchmarkService {
 private static final Set<String> DATASET_TYPES=Set.of("source_known","owasp_training","open_source_with_known_revision","authorized_exploratory","fictional_example");
 private static final Set<String> REDISTRIBUTION=Set.of("allowed","conditional","not_allowed","not_reviewed");
 private static final Set<String> GT_STATES=Set.of("unreviewed","reviewed","verified","disputed","not_applicable");
 private static final Set<String> CACHE_POLICIES=Set.of("cold_each_run","warm_each_run","mixed","not_controlled");
 private static final Set<String> TERMINAL=Set.of("succeeded","partial","failed","timed_out","cancelled","incompatible");
 private static final Map<String,Set<String>> CAPS=Map.ofEntries(
  Map.entry("jadx",Set.of("dex_to_source","cross_references")),
  Map.entry("apktool",Set.of("android_resources","manifest","smali")),
  Map.entry("androguard",Set.of("apk_parsing","dex_analysis","call_graph")),
  Map.entry("apkid",Set.of("packer_detection","compiler_detection","protector_detection")),
  Map.entry("bundletool",Set.of("aab_processing","split_apk_processing")),
  Map.entry("apkeditor",Set.of("android_resources","manifest","smali","apk_processing")),
  Map.entry("apkleaks",Set.of("uri_extraction","string_pattern_triage")),
  Map.entry("hermes-dec",Set.of("react_native","hermes_bytecode")),
  Map.entry("blutter",Set.of("flutter_aot","dart_object_pool","arm64")),
  Map.entry("ghidra",Set.of("elf_analysis","arm64_disassembly","native_pseudocode","native_call_graph")),
  Map.entry("mobsf",Set.of("mobile_static_analysis")),
  Map.entry("exodus-standalone",Set.of("tracker_signature_matching"))
 );
 private final JdbcTemplate jdbc;
 private final ObjectMapper mapper;
 private final EngineCatalog engines;
 private final TargetService targets;
 private final RunService runs;
 private final WorkspaceService workspace;

 BenchmarkService(JdbcTemplate jdbc,ObjectMapper mapper,EngineCatalog engines,TargetService targets,RunService runs,WorkspaceService workspace){
  this.jdbc=jdbc;this.mapper=mapper;this.engines=engines;this.targets=targets;this.runs=runs;this.workspace=workspace;
 }

 @Transactional
 Map<String,Object> createDataset(DatasetRequest r)throws Exception{
  text(r.name(),"Dataset name");text(r.version(),"Dataset version");
  if(!DATASET_TYPES.contains(r.sourceType()))throw bad("Unsupported dataset source_type.");
  if(r.platforms()==null||r.platforms().isEmpty()||r.capabilityClasses()==null||r.capabilityClasses().isEmpty())throw bad("Dataset needs platforms and capability classes.");
  if(r.targetIds()==null||r.targetIds().isEmpty())throw bad("Dataset must include at least one target.");
  text(r.licenseIdentifier(),"Dataset license identifier");
  if(!REDISTRIBUTION.contains(r.redistributionStatus()))throw bad("Invalid redistribution status.");
  if(r.artifactManifestSha256()!=null&&!r.artifactManifestSha256().matches("(?i)^[a-f0-9]{64}$"))throw bad("Invalid artifact manifest SHA-256.");
  String key=(r.datasetId()==null||r.datasetId().isBlank())?"dataset-"+UUID.randomUUID().toString().substring(0,8):r.datasetId().trim();
  UUID id=UUID.randomUUID();Instant now=Instant.now();
  jdbc.update("""
   INSERT INTO benchmark_datasets(id,dataset_key,name,version,source_type,description,platforms,capability_classes,
    source_repository,source_revision,artifact_manifest_sha256,ground_truth_available,license_identifier,
    redistribution_status,license_notes,maintainer_notes,created_at)
   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
   """,id,key,r.name().trim(),r.version().trim(),r.sourceType(),r.description(),csv(r.platforms()),csv(r.capabilityClasses()),
    r.sourceRepository(),r.sourceRevision(),r.artifactManifestSha256(),false,
    r.licenseIdentifier(),r.redistributionStatus(),r.licenseNotes(),r.maintainerNotes(),Timestamp.from(now));
  for(UUID targetId:r.targetIds().stream().distinct().toList()){
   if(targets.get(targetId)==null)throw bad("Dataset references unknown target: "+targetId);
   jdbc.update("INSERT INTO benchmark_dataset_targets(dataset_id,target_id) VALUES(?,?)",id,targetId);
  }
  return getDataset(key);
 }

 List<Map<String,Object>> listDatasets(){
  List<String> keys=jdbc.query("SELECT dataset_key FROM benchmark_datasets ORDER BY created_at DESC",(rs,n)->rs.getString(1));
  return keys.stream().map(this::getDataset).toList();
 }

 Map<String,Object> getDataset(String key){
  List<Map<String,Object>> rows=jdbc.query("""
   SELECT id,dataset_key,name,version,source_type,description,platforms,capability_classes,source_repository,
    source_revision,artifact_manifest_sha256,ground_truth_available,license_identifier,redistribution_status,
    license_notes,maintainer_notes,created_at FROM benchmark_datasets WHERE dataset_key=?
   """,(rs,n)->{
    Map<String,Object> m=new LinkedHashMap<>();
    m.put("id",rs.getObject("id",UUID.class).toString());m.put("datasetId",rs.getString("dataset_key"));
    m.put("name",rs.getString("name"));m.put("version",rs.getString("version"));m.put("sourceType",rs.getString("source_type"));
    m.put("description",rs.getString("description"));m.put("platforms",split(rs.getString("platforms")));
    m.put("capabilityClasses",split(rs.getString("capability_classes")));m.put("sourceRepository",rs.getString("source_repository"));
    m.put("sourceRevision",rs.getString("source_revision"));m.put("artifactManifestSha256",rs.getString("artifact_manifest_sha256"));
    m.put("groundTruthAvailable",rs.getBoolean("ground_truth_available"));
    m.put("license",Map.of("identifier",rs.getString("license_identifier"),"redistributionStatus",rs.getString("redistribution_status")));
    m.put("licenseNotes",rs.getString("license_notes"));m.put("maintainerNotes",rs.getString("maintainer_notes"));
    m.put("createdAt",rs.getTimestamp("created_at").toInstant().toString());return m;
   },key);
  if(rows.isEmpty())throw bad("Benchmark dataset not found.");
  Map<String,Object> result=rows.get(0);UUID datasetId=UUID.fromString((String)result.get("id"));
  List<Map<String,Object>> datasetTargets=jdbc.query("""
   SELECT t.id,t.display_name,t.original_filename,t.sha256,t.size_bytes FROM benchmark_dataset_targets dt
   JOIN targets t ON t.id=dt.target_id WHERE dt.dataset_id=? ORDER BY t.display_name
   """,(rs,n)->Map.of("targetId",rs.getObject("id",UUID.class).toString(),"displayName",rs.getString("display_name"),
    "filename",rs.getString("original_filename"),"sha256",rs.getString("sha256"),"sizeBytes",rs.getLong("size_bytes")),datasetId);
  result.put("targets",datasetTargets);return result;
 }

 @Transactional
 Map<String,Object> addGroundTruth(String datasetKey,UUID targetId,GroundTruthRequest r)throws Exception{
  Map<String,Object> dataset=getDataset(datasetKey);UUID datasetId=UUID.fromString((String)dataset.get("id"));
  Boolean belongs=jdbc.query("SELECT EXISTS(SELECT 1 FROM benchmark_dataset_targets WHERE dataset_id=? AND target_id=?)",
   rs->rs.next()&&rs.getBoolean(1),datasetId,targetId);
  if(!belongs)throw bad("Ground-truth target is not part of this dataset.");
  text(r.capabilityClass(),"Capability class");text(r.itemType(),"Item type");text(r.expectedValue(),"Expected value");
  if(!GT_STATES.contains(r.validationStatus()))throw bad("Invalid validation status.");
  String canonical=canon(r.canonicalKey()==null||r.canonicalKey().isBlank()?r.itemType()+":"+r.expectedValue():r.canonicalKey());
  Map<String,Object> sourceReference=r.sourceReference()==null?Map.of():r.sourceReference();
  if("verified".equals(r.validationStatus())){
   if(r.reviewer()==null||r.reviewer().isBlank())throw bad("Verified ground-truth items require a reviewer.");
   boolean hasReference=List.of("source_path","source_revision","source_sha256").stream()
    .anyMatch(k->sourceReference.get(k) instanceof String v&&!v.isBlank());
   if(!hasReference)throw bad("Verified ground-truth items require a source path, revision or SHA-256 reference.");
  }
  Object sourceHash=sourceReference.get("source_sha256");
  if(sourceHash instanceof String s&&!s.isBlank()&&!s.matches("(?i)^[a-f0-9]{64}$"))throw bad("source_sha256 must be a SHA-256 hex digest.");
  String source=mapper.writeValueAsString(sourceReference);UUID id=UUID.randomUUID();
  List<String> owasp=(r.owaspMappings()==null?List.<String>of():r.owaspMappings()).stream()
    .map(String::trim).filter(v->!v.isBlank()).distinct().toList();
  if(owasp.stream().anyMatch(v->v.length()>100||!v.matches("^[A-Za-z0-9._-]+$")))throw bad("OWASP mapping tags must be short identifiers (letters, digits, dot, underscore, hyphen).");
  jdbc.update("""
   INSERT INTO benchmark_ground_truth(id,dataset_id,target_id,capability_class,item_type,expected_value,
    canonical_key,validation_status,source_reference,reviewer,owasp_mappings,reviewed_at,notes)
   VALUES(?,?,?,?,?,?,?, ?,?::jsonb,?,?,?,?)
   """,id,datasetId,targetId,r.capabilityClass(),r.itemType(),r.expectedValue(),canonical,r.validationStatus(),
    source,r.reviewer(),csv(owasp),"verified".equals(r.validationStatus())?Timestamp.from(Instant.now()):null,r.notes());
  if("verified".equals(r.validationStatus()))jdbc.update("UPDATE benchmark_datasets SET ground_truth_available=TRUE WHERE id=?",datasetId);
  return Map.of("groundTruthItemId",id.toString(),"datasetId",datasetKey,"targetId",targetId.toString(),
    "capabilityClass",r.capabilityClass(),"itemType",r.itemType(),"expectedValue",r.expectedValue(),
    "canonicalKey",canonical,"validationStatus",r.validationStatus(),"owaspMappings",owasp,"createdAt",Instant.now().toString());
 }

 List<Map<String,Object>> listGroundTruth(String datasetKey){
  UUID datasetId=UUID.fromString((String)getDataset(datasetKey).get("id"));
  return jdbc.query("""
   SELECT id,target_id,capability_class,item_type,expected_value,canonical_key,validation_status,
    source_reference::text AS source_reference,reviewer,owasp_mappings,notes,created_at
   FROM benchmark_ground_truth WHERE dataset_id=? ORDER BY target_id,capability_class,canonical_key
   """,(rs,n)->{
    Map<String,Object> m=new LinkedHashMap<>();m.put("groundTruthItemId",rs.getObject("id",UUID.class).toString());
    m.put("targetId",rs.getObject("target_id",UUID.class).toString());m.put("capabilityClass",rs.getString("capability_class"));
    m.put("itemType",rs.getString("item_type"));m.put("expectedValue",rs.getString("expected_value"));
    m.put("canonicalKey",rs.getString("canonical_key"));m.put("validationStatus",rs.getString("validation_status"));
    m.put("sourceReference",parseMap(rs.getString("source_reference")));m.put("reviewer",rs.getString("reviewer"));
    m.put("owaspMappings",split(rs.getString("owasp_mappings")));m.put("notes",rs.getString("notes"));m.put("createdAt",rs.getTimestamp("created_at").toInstant().toString());return m;
   },datasetId);
 }

 List<Map<String,Object>> listProfiles(){
  return jdbc.query("SELECT profile_key,name,platform,capability_classes,engine_ids,default_repetitions,default_concurrency,is_builtin FROM benchmark_profiles ORDER BY is_builtin DESC,name",
   (rs,n)->profileMap(rs));
 }

 @Transactional
 Map<String,Object> createProfile(ProfileRequest r){
  text(r.profileKey(),"Profile key");text(r.name(),"Profile name");
  if(!r.profileKey().matches("^[a-z0-9][a-z0-9-]{2,127}$"))throw bad("Profile key must be lowercase kebab-case.");
  if(!"android".equals(r.platform()))throw bad("Phase 2 v1 supports Android profiles only.");
  validateEngines(r.engineIds());
  if(r.capabilityClasses()==null||r.capabilityClasses().isEmpty())throw bad("Profile requires capability classes.");
  int reps=r.defaultRepetitions()==null?3:r.defaultRepetitions();int concurrency=r.defaultConcurrency()==null?1:r.defaultConcurrency();
  if(reps<1||reps>50)throw bad("Repetitions must be between 1 and 50.");
  if(concurrency!=1)throw bad("Phase 2 v1 enforces sequential concurrency=1.");
  jdbc.update("INSERT INTO benchmark_profiles(profile_key,name,platform,capability_classes,engine_ids,default_repetitions,default_concurrency,is_builtin) VALUES(?,?,?,?,?,?,?,FALSE)",
   r.profileKey(),r.name(),r.platform(),csv(r.capabilityClasses()),csv(r.engineIds()),reps,concurrency);
  return getProfile(r.profileKey());
 }

 Map<String,Object> getProfile(String key){
  List<Map<String,Object>> rows=jdbc.query("SELECT profile_key,name,platform,capability_classes,engine_ids,default_repetitions,default_concurrency,is_builtin FROM benchmark_profiles WHERE profile_key=?",
   (rs,n)->profileMap(rs),key);
  if(rows.isEmpty())throw bad("Benchmark profile not found.");return rows.get(0);
 }

 @Transactional
 Map<String,Object> createExperiment(ExperimentRequest r)throws Exception{
  text(r.name(),"Experiment name");Map<String,Object> dataset=getDataset(r.datasetId());
  Map<String,Object> profile=getProfile(r.profileKey()==null||r.profileKey().isBlank()?"android-static-core":r.profileKey());
  if(!"android".equals(profile.get("platform")))throw bad("Only Android benchmark profiles execute in Phase 2.");
  UUID datasetUuid=UUID.fromString((String)dataset.get("id"));
  List<UUID> targetIds=(r.targetIds()==null||r.targetIds().isEmpty())
   ?((List<Map<String,Object>>)dataset.get("targets")).stream().map(t->UUID.fromString((String)t.get("targetId"))).toList()
   :r.targetIds().stream().distinct().toList();
  if(targetIds.isEmpty())throw bad("Experiment needs at least one target.");
  Set<String> included=((List<Map<String,Object>>)dataset.get("targets")).stream().map(t->(String)t.get("targetId")).collect(Collectors.toSet());
  for(UUID id:targetIds)if(!included.contains(id.toString()))throw bad("Every experiment target must belong to the dataset.");
  List<String> engineIds=(r.engineIds()==null||r.engineIds().isEmpty())?split((String)profile.get("engineIds")):r.engineIds().stream().distinct().sorted().toList();
  validateEngines(engineIds);
  int repetitions=r.repetitions()==null?((Number)profile.get("defaultRepetitions")).intValue():r.repetitions();
  int concurrency=r.concurrency()==null?1:r.concurrency();String cache=r.cachePolicy()==null||r.cachePolicy().isBlank()?"not_controlled":r.cachePolicy();
  if(repetitions<1||repetitions>50)throw bad("Repetitions must be between 1 and 50.");
  if(concurrency!=1)throw bad("Phase 2 v1 only supports sequential concurrency=1.");
  if(!CACHE_POLICIES.contains(cache))throw bad("Invalid cache policy.");
  if((long)targetIds.size()*engineIds.size()*repetitions>250)throw bad("Experiment is limited to 250 engine attempts.");
  Map<String,String> hashes=new TreeMap<>();
  long compatiblePairs=0;
  for(UUID id:targetIds){
   TargetResponse t=targets.get(id);if(t==null)throw bad("Unknown target: "+id);
   hashes.put(id.toString(),t.sha256());
   String format=TargetService.extension(t.originalFilename());
   for(String engineId:engineIds)if(engines.supports(engineId,format))compatiblePairs++;
  }
  if(compatiblePairs==0)throw bad("No selected engine supports the chosen target formats. Choose a compatible profile.");
  String manifest=mapper.writeValueAsString(Map.of("datasetId",r.datasetId(),"targets",hashes,"engineIds",engineIds,
    "repetitions",repetitions,"cachePolicy",cache,"methodologyVersion","1.1.0"));
  UUID experimentId=UUID.randomUUID();String key="experiment-"+experimentId.toString().substring(0,8);
  jdbc.update("""
   INSERT INTO benchmark_experiments(id,experiment_key,name,dataset_id,profile_key,status,input_manifest_sha256,
    methodology_version,repetitions,concurrency,cache_policy,engine_ids,target_ids,notes,created_at)
   VALUES(?,?,?,?,?,'queued',?,'1.1.0',?,1,?,?,?,?,?)
   """,experimentId,key,r.name().trim(),datasetUuid,profile.get("profileKey"),sha256(manifest),repetitions,cache,
    csv(engineIds),csv(targetIds.stream().map(UUID::toString).toList()),r.notes(),Timestamp.from(Instant.now()));
  for(UUID targetId:targetIds){
   TargetResponse target=targets.get(targetId);String format=TargetService.extension(target.originalFilename());
   for(String engineId:engineIds){
    boolean compatible=engines.supports(engineId,format);
    for(int repetition=1;repetition<=repetitions;repetition++){
     UUID attemptId=UUID.randomUUID();
     if(!compatible){
      jdbc.update("INSERT INTO benchmark_attempts(id,experiment_id,target_id,engine_id,repetition,input_sha256,status,finished_at,error_summary) VALUES(?,?,?,?,?,?,'incompatible',NOW(),?)",
       attemptId,experimentId,targetId,engineId,repetition,target.sha256(),engineId+" does not support ."+format+"; excluded from accuracy scoring.");
      continue;
     }
     RunCreatedResponse created=runs.create(targetId,new RunRequest(List.of(engineId)));
     RunResponse run=runs.get(created.id());UUID executionId=run.executions().get(0).id();
     jdbc.update("INSERT INTO benchmark_attempts(id,experiment_id,target_id,engine_id,repetition,input_sha256,status,run_id,execution_id) VALUES(?,?,?,?,?,?,'queued',?,?)",
      attemptId,experimentId,targetId,engineId,repetition,target.sha256(),created.id(),executionId);
    }
   }
  }
  refreshExperiment(experimentId);
  return getExperiment(key);
 }

 void recordWorkerData(UUID executionId,WorkerBenchmarkData payload)throws Exception{
  List<UUID> ids=jdbc.query("SELECT id FROM benchmark_attempts WHERE execution_id=?",(rs,n)->rs.getObject(1,UUID.class),executionId);
  if(ids.isEmpty())return;
  UUID attemptId=ids.get(0);
  String expected=jdbc.query("SELECT input_sha256 FROM benchmark_attempts WHERE id=?",rs->rs.next()?rs.getString(1):null,attemptId);
  if(payload.inputSha256()==null||!payload.inputSha256().equalsIgnoreCase(expected))throw bad("Worker payload input hash did not match benchmark attempt.");
  List<Map<String,Object>> observations=payload.observations()==null?List.of():payload.observations();
  if(observations.size()>25000)throw bad("Worker output exceeded 25,000 normalized observations.");
  jdbc.update("DELETE FROM benchmark_observations WHERE attempt_id=?",attemptId);
  String outputDir=jdbc.query("SELECT output_directory FROM engine_executions WHERE id=?",rs->rs.next()?rs.getString(1):null,executionId);
  for(Map<String,Object> o:observations){
   String path=req(o,"evidence_path",2048),hash=req(o,"evidence_sha256",64);
   if(path.startsWith("/")||path.contains("\\")||Arrays.asList(path.split("/")).contains(".."))throw bad("Observation evidence path is unsafe.");
   if(!hash.matches("(?i)^[a-f0-9]{64}$"))throw bad("Observation evidence SHA-256 is invalid.");
   Path evidence=workspace.resolve(outputDir+"/"+path);
   try {
    Path realRoot=workspace.resolve("").toRealPath();
    Path realEvidence=evidence.toRealPath();
    if(!realEvidence.startsWith(realRoot)||Files.isSymbolicLink(evidence)||!Files.isRegularFile(realEvidence,LinkOption.NOFOLLOW_LINKS))throw bad("Observation evidence file is missing or unsafe.");
    if(!sha256File(realEvidence).equalsIgnoreCase(hash))throw bad("Observation evidence SHA-256 does not match the stored file.");
   } catch(java.io.IOException ex){throw bad("Could not verify observation evidence file.");}
   String capability=req(o,"capability_class",100),type=req(o,"item_type",48),title=req(o,"title",300);
   String value=req(o,"observed_value",8000),canonical=canon(req(o,"canonical_key",1000));
   String confidence=String.valueOf(o.getOrDefault("confidence","unknown"));
   if(!Set.of("low","medium","high","unknown").contains(confidence))confidence="unknown";
   jdbc.update("""
    INSERT INTO benchmark_observations(id,attempt_id,execution_id,capability_class,item_type,title,observed_value,
     canonical_key,evidence_path,evidence_sha256,confidence,attributes)
    VALUES(?,?,?,?,?,?,?,?,?,?,?,?::jsonb)
    """,UUID.randomUUID(),attemptId,executionId,capability,type,title,value,canonical,outputDir+"/"+path,hash,
     confidence,mapper.writeValueAsString(o.getOrDefault("attributes",Map.of())));
  }
  Map<String,Object> metrics=new LinkedHashMap<>(payload.metrics()==null?Map.of():payload.metrics());
  metrics.put("limitations",payload.limitations()==null?List.of():payload.limitations());
  jdbc.update("UPDATE benchmark_attempts SET worker_metrics=?::jsonb,output_bytes=?,output_file_count=?,observation_count=? WHERE id=?",
   mapper.writeValueAsString(metrics),num(metrics.get("output_bytes")),num(metrics.get("output_file_count")),observations.size(),attemptId);
 }

 void executionStarted(UUID executionId){
  jdbc.update("UPDATE benchmark_attempts SET status='running',started_at=COALESCE(started_at,NOW()) WHERE execution_id=? AND status='queued'",executionId);
  List<UUID> exp=jdbc.query("SELECT experiment_id FROM benchmark_attempts WHERE execution_id=?",(rs,n)->rs.getObject(1,UUID.class),executionId);
  if(!exp.isEmpty())refreshExperiment(exp.get(0));
 }

 void finalizeExecution(UUID executionId){
  List<Map<String,Object>> rows=jdbc.query("""
   SELECT a.id,a.experiment_id,a.target_id,a.engine_id,a.repetition,e.status AS execution_status,
    e.duration_ms,e.output_bytes FROM benchmark_attempts a JOIN engine_executions e ON e.id=a.execution_id
   WHERE a.execution_id=?
   """,(rs,n)->{
    Map<String,Object> m=new LinkedHashMap<>();m.put("attemptId",rs.getObject("id",UUID.class));
    m.put("experimentId",rs.getObject("experiment_id",UUID.class));m.put("targetId",rs.getObject("target_id",UUID.class));
    m.put("engineId",rs.getString("engine_id"));m.put("repetition",rs.getInt("repetition"));
    m.put("executionStatus",rs.getString("execution_status"));m.put("durationMs",rs.getObject("duration_ms"));
    m.put("outputBytes",rs.getObject("output_bytes"));return m;
   },executionId);
  if(rows.isEmpty())return;
  Map<String,Object> a=rows.get(0);UUID attempt=(UUID)a.get("attemptId");
  jdbc.update("UPDATE benchmark_attempts SET status=?,started_at=COALESCE(started_at,NOW()),finished_at=NOW() WHERE id=?",
   a.get("executionStatus"),attempt);
  createResult(a,attempt,executionId);refreshExperiment((UUID)a.get("experimentId"));
 }

 private void createResult(Map<String,Object> a,UUID attempt,UUID executionId){
  UUID exp=(UUID)a.get("experimentId"),target=(UUID)a.get("targetId");
  String engine=(String)a.get("engineId");
  UUID dataset=jdbc.query("SELECT dataset_id FROM benchmark_experiments WHERE id=?",rs->rs.next()?rs.getObject(1,UUID.class):null,exp);
  List<String> caps=new ArrayList<>(CAPS.getOrDefault(engine,Set.of()));
  List<Map<String,Object>> gt=List.of();
  if(!caps.isEmpty()){
   String in=String.join(",",Collections.nCopies(caps.size(),"?"));List<Object> args=new ArrayList<>(List.of(dataset,target));args.addAll(caps);
   gt=jdbc.query("SELECT canonical_key,expected_value,capability_class FROM benchmark_ground_truth WHERE dataset_id=? AND target_id=? AND validation_status='verified' AND capability_class IN ("+in+")",
    (rs,n)->Map.of("canonicalKey",rs.getString(1),"expectedValue",rs.getString(2),"capabilityClass",rs.getString(3)),args.toArray());
  }
  List<Map<String,Object>> obs=jdbc.query("SELECT canonical_key,evidence_path,evidence_sha256 FROM benchmark_observations WHERE attempt_id=?",
   (rs,n)->Map.of("canonicalKey",rs.getString(1),"evidencePath",rs.getString(2),"evidenceSha256",rs.getString(3)),attempt);
  boolean scoringEligible="succeeded".equals(a.get("executionStatus"))||"partial".equals(a.get("executionStatus"));
  List<String> expectedKeys=scoringEligible?gt.stream().map(g->(String)g.get("canonicalKey")).toList():List.of();
  List<Map<String,Object>> comparableObservations=filterComparableObservations(gt,obs);
  BenchmarkScore score=BenchmarkScorer.score(expectedKeys,comparableObservations);
  boolean hasGt=score.accuracyAvailable();
  String metricsRaw=jdbc.query("SELECT worker_metrics::text FROM benchmark_attempts WHERE id=?",rs->rs.next()?rs.getString(1):"{}",attempt);
  Map<String,Object> metrics=parseMap(metricsRaw);
  String toolVersion=jdbc.query("SELECT tool_version FROM engine_executions WHERE id=?",rs->rs.next()?rs.getString(1):null,executionId);
  String adapterVersion=jdbc.query("SELECT adapter_version FROM engine_executions WHERE id=?",rs->rs.next()?rs.getString(1):null,executionId);
  String note=!scoringEligible?"Accuracy metrics are unavailable because this engine attempt did not complete successfully.":
   hasGt?"Scored only against verified ground truth for capabilities supported by this engine.":
   "Accuracy metrics are unavailable: no verified capability-compatible ground truth exists.";
  jdbc.update("""
   INSERT INTO benchmark_results(id,experiment_id,attempt_id,target_id,engine_id,tool_version,adapter_version,repetition,status,duration_ms,
    cpu_time_ms,peak_rss_bytes,output_bytes,output_file_count,observation_count,ground_truth_count,true_positive,
    false_positive,false_negative,precision,recall,f1,coverage,duplicate_rate,evidence_completeness,
    matched_items,missed_items,false_positive_items,notes)
   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
   ON CONFLICT(attempt_id) DO NOTHING
   """,UUID.randomUUID(),exp,attempt,target,engine,toolVersion,adapterVersion,a.get("repetition"),a.get("executionStatus"),
   a.get("durationMs"),longOrNull(metrics.get("cpu_time_ms")),longOrNull(metrics.get("peak_rss_bytes")),
   a.get("outputBytes"),intOrNull(metrics.get("output_file_count")),obs.size(),
   score.groundTruthCount(),score.truePositive(),score.falsePositive(),score.falseNegative(),
   score.precision(),score.recall(),score.f1(),score.coverage(),score.duplicateRate(),score.evidenceCompleteness(),
   json(score.matchedItems()),json(score.missedItems()),json(score.falsePositiveItems()),note);
 }

 private void refreshExperiment(UUID id){
  List<String> status=jdbc.query("SELECT status FROM benchmark_attempts WHERE experiment_id=?",(rs,n)->rs.getString(1),id);
  if(status.isEmpty())return;
  if(status.stream().anyMatch(s->!TERMINAL.contains(s))){
   String active=status.stream().anyMatch("running"::equals)?"running":"queued";
   jdbc.update("UPDATE benchmark_experiments SET status=?,started_at=CASE WHEN ?='running' THEN COALESCE(started_at,NOW()) ELSE started_at END WHERE id=?",active,active,id);return;
  }
  long success=status.stream().filter("succeeded"::equals).count(),incompatible=status.stream().filter("incompatible"::equals).count();
  String overall=success+incompatible==status.size()?"completed":success==0&&incompatible==0?"failed":"partial";
  jdbc.update("UPDATE benchmark_experiments SET status=?,started_at=COALESCE(started_at,NOW()),finished_at=NOW() WHERE id=?",overall,id);
 }

 Map<String,Object> listExperiments(){
  List<String> keys=jdbc.query("SELECT experiment_key FROM benchmark_experiments ORDER BY created_at DESC",(rs,n)->rs.getString(1));
  return Map.of("experiments",keys.stream().map(this::getExperiment).toList());
 }

 Map<String,Object> getExperiment(String key){
  List<Map<String,Object>> rows=jdbc.query("""
   SELECT e.id,e.experiment_key,e.name,e.status,e.input_manifest_sha256,e.methodology_version,e.repetitions,
    e.concurrency,e.cache_policy,e.engine_ids,e.target_ids,e.notes,e.created_at,e.started_at,e.finished_at,
    d.dataset_key,d.name AS dataset_name,p.profile_key,p.name AS profile_name
   FROM benchmark_experiments e JOIN benchmark_datasets d ON d.id=e.dataset_id
   JOIN benchmark_profiles p ON p.profile_key=e.profile_key WHERE e.experiment_key=?
   """,(rs,n)->{
    Map<String,Object> m=new LinkedHashMap<>();m.put("id",rs.getObject("id",UUID.class).toString());
    m.put("experimentId",rs.getString("experiment_key"));m.put("name",rs.getString("name"));m.put("status",rs.getString("status"));
    m.put("inputManifestSha256",rs.getString("input_manifest_sha256"));m.put("methodologyVersion",rs.getString("methodology_version"));
    m.put("repetitions",rs.getInt("repetitions"));m.put("concurrency",rs.getInt("concurrency"));m.put("cachePolicy",rs.getString("cache_policy"));
    m.put("engineIds",split(rs.getString("engine_ids")));m.put("targetIds",split(rs.getString("target_ids")));
    m.put("notes",rs.getString("notes"));m.put("dataset",Map.of("datasetId",rs.getString("dataset_key"),"name",rs.getString("dataset_name")));
    m.put("profile",Map.of("profileKey",rs.getString("profile_key"),"name",rs.getString("profile_name")));
    m.put("createdAt",rs.getTimestamp("created_at").toInstant().toString());
    m.put("startedAt",rs.getTimestamp("started_at")==null?null:rs.getTimestamp("started_at").toInstant().toString());
    m.put("finishedAt",rs.getTimestamp("finished_at")==null?null:rs.getTimestamp("finished_at").toInstant().toString());return m;
   },key);
  if(rows.isEmpty())throw bad("Benchmark experiment not found.");
  Map<String,Object> result=rows.get(0);UUID id=UUID.fromString((String)result.get("id"));
  List<Map<String,Object>> attempts=jdbc.query("""
   SELECT a.id,a.target_id,a.engine_id,a.repetition,a.status,a.run_id,a.execution_id,a.error_summary,
    a.worker_metrics::text AS worker_metrics,br.tool_version,br.adapter_version,br.duration_ms,br.cpu_time_ms,br.peak_rss_bytes,br.output_bytes,br.output_file_count,br.observation_count,
    br.ground_truth_count,br.true_positive,br.false_positive,br.false_negative,br.precision,br.recall,br.f1,
    br.coverage,br.duplicate_rate,br.evidence_completeness,br.notes
   FROM benchmark_attempts a LEFT JOIN benchmark_results br ON br.attempt_id=a.id
   WHERE a.experiment_id=? ORDER BY a.target_id,a.engine_id,a.repetition
   """,(rs,n)->{
    Map<String,Object> m=new LinkedHashMap<>();m.put("attemptId",rs.getObject("id",UUID.class).toString());
    m.put("targetId",rs.getObject("target_id",UUID.class).toString());m.put("engineId",rs.getString("engine_id"));
    m.put("repetition",rs.getInt("repetition"));m.put("status",rs.getString("status"));
    m.put("runId",rs.getObject("run_id")==null?null:rs.getObject("run_id",UUID.class).toString());
    m.put("executionId",rs.getObject("execution_id")==null?null:rs.getObject("execution_id",UUID.class).toString());
    m.put("errorSummary",rs.getString("error_summary"));m.put("toolVersion",rs.getString("tool_version"));
    m.put("adapterVersion",rs.getString("adapter_version"));m.put("workerMetrics",parseMap(rs.getString("worker_metrics")));
    for(String f:List.of("duration_ms","cpu_time_ms","peak_rss_bytes","output_bytes","output_file_count","observation_count",
     "ground_truth_count","true_positive","false_positive","false_negative","precision","recall","f1","coverage",
     "duplicate_rate","evidence_completeness","notes"))m.put(camel(f),rs.getObject(f));
    return m;
   },id);
  result.put("attempts",attempts);result.put("summary",summary(id));return result;
 }

 private Map<String,Object> summary(UUID id){
  List<Map<String,Object>> perEngine=jdbc.query("""
   SELECT engine_id,COUNT(*) AS attempts,COUNT(*) FILTER(WHERE status='succeeded') AS succeeded,
    COUNT(*) FILTER(WHERE status IN ('failed','timed_out','cancelled')) AS failed,
    string_agg(DISTINCT tool_version,', ' ORDER BY tool_version) AS tool_versions,
    string_agg(DISTINCT adapter_version,', ' ORDER BY adapter_version) AS adapter_versions,
    percentile_cont(0.5) WITHIN GROUP(ORDER BY duration_ms) AS median_duration_ms,
    percentile_cont(0.5) WITHIN GROUP(ORDER BY cpu_time_ms) AS median_cpu_time_ms,
    percentile_cont(0.5) WITHIN GROUP(ORDER BY peak_rss_bytes) AS median_peak_rss_bytes,
    percentile_cont(0.5) WITHIN GROUP(ORDER BY output_bytes) AS median_output_bytes,
    AVG(precision) AS mean_precision,AVG(recall) AS mean_recall,AVG(f1) AS mean_f1,
    AVG(coverage) AS mean_coverage,AVG(duplicate_rate) AS mean_duplicate_rate,
    AVG(evidence_completeness) AS mean_evidence_completeness
   FROM benchmark_results WHERE experiment_id=? GROUP BY engine_id ORDER BY engine_id
   """,(rs,n)->{
    Map<String,Object> m=new LinkedHashMap<>();m.put("engineId",rs.getString("engine_id"));
    m.put("attempts",rs.getLong("attempts"));m.put("succeeded",rs.getLong("succeeded"));m.put("failed",rs.getLong("failed"));
    m.put("toolVersions",rs.getString("tool_versions"));m.put("adapterVersions",rs.getString("adapter_versions"));
    for(String f:List.of("median_duration_ms","median_cpu_time_ms","median_peak_rss_bytes","median_output_bytes","mean_precision","mean_recall","mean_f1",
     "mean_coverage","mean_duplicate_rate","mean_evidence_completeness"))m.put(camel(f),rs.getObject(f));
    return m;
   },id);
  List<Map<String,Object>> all=jdbc.query("""
   SELECT canonical_key,COUNT(DISTINCT engine_id) AS engine_count,string_agg(DISTINCT engine_id,',' ORDER BY engine_id) AS engines
   FROM benchmark_observations o JOIN benchmark_attempts a ON a.id=o.attempt_id
   WHERE a.experiment_id=? GROUP BY canonical_key ORDER BY canonical_key
   """,(rs,n)->Map.of("canonicalKey",rs.getString("canonical_key"),"engineCount",rs.getInt("engine_count"),"engines",split(rs.getString("engines"))),id);
  List<String> owaspMappings=jdbc.query("""
   SELECT DISTINCT trim(tags.tag) FROM benchmark_ground_truth gt
   JOIN benchmark_experiments e ON e.dataset_id=gt.dataset_id
   CROSS JOIN LATERAL unnest(string_to_array(gt.owasp_mappings,',')) AS tags(tag)
   WHERE e.id=? AND gt.validation_status='verified' AND trim(tags.tag)<>''
   ORDER BY trim(tags.tag)
   """,(rs,n)->rs.getString(1),id);
  List<Map<String,Object>> unique=all.stream().filter(x->((Number)x.get("engineCount")).intValue()==1).toList();
  List<Map<String,Object>> shared=all.stream().filter(x->((Number)x.get("engineCount")).intValue()>1).toList();
  return Map.of("engines",perEngine,"uniqueRecoveries",unique,"sharedRecoveries",shared,"owaspMappings",owaspMappings);
 }

 Map<String,Object> reportJson(String key){return getExperiment(key);}

 List<Map<String,Object>> listObservations(String key,String engineId,int limit){
  Map<String,Object> experiment=getExperiment(key);
  UUID exp=UUID.fromString((String)experiment.get("id"));
  int bounded=Math.max(1,Math.min(limit,5000));
  if(engineId==null||engineId.isBlank()){
   return jdbc.query("""
    SELECT o.id,o.attempt_id,o.execution_id,a.run_id,a.target_id,a.engine_id,a.repetition,o.capability_class,
     o.item_type,o.title,o.observed_value,o.canonical_key,o.evidence_path,o.evidence_sha256,o.confidence,o.attributes::text AS attributes
    FROM benchmark_observations o JOIN benchmark_attempts a ON a.id=o.attempt_id
    WHERE a.experiment_id=? ORDER BY a.engine_id,a.repetition,o.canonical_key LIMIT ?
    """,(rs,n)->observationMap(rs),exp,bounded);
  }
  return jdbc.query("""
    SELECT o.id,o.attempt_id,o.execution_id,a.run_id,a.target_id,a.engine_id,a.repetition,o.capability_class,
     o.item_type,o.title,o.observed_value,o.canonical_key,o.evidence_path,o.evidence_sha256,o.confidence,o.attributes::text AS attributes
    FROM benchmark_observations o JOIN benchmark_attempts a ON a.id=o.attempt_id
    WHERE a.experiment_id=? AND a.engine_id=? ORDER BY a.repetition,o.canonical_key LIMIT ?
    """,(rs,n)->observationMap(rs),exp,engineId,bounded);
 }

 private Map<String,Object> observationMap(java.sql.ResultSet rs)throws java.sql.SQLException{
  Map<String,Object> m=new LinkedHashMap<>();
  m.put("observationId",rs.getObject("id",UUID.class).toString());m.put("attemptId",rs.getObject("attempt_id",UUID.class).toString());
  m.put("executionId",rs.getObject("execution_id",UUID.class).toString());
  String targetId=rs.getObject("target_id",UUID.class).toString();m.put("targetId",targetId);
  m.put("engineId",rs.getString("engine_id"));m.put("repetition",rs.getInt("repetition"));
  m.put("capabilityClass",rs.getString("capability_class"));m.put("itemType",rs.getString("item_type"));
  m.put("title",rs.getString("title"));m.put("observedValue",rs.getString("observed_value"));
  m.put("canonicalKey",rs.getString("canonical_key"));m.put("evidencePath",rs.getString("evidence_path"));
  String runRoot="android/"+targetId+"/run-"+rs.getObject("run_id",UUID.class);
  String fullEvidence=rs.getString("evidence_path");
  m.put("runFilePath",fullEvidence.startsWith(runRoot+"/")?fullEvidence.substring(runRoot.length()+1):null);
  m.put("evidenceSha256",rs.getString("evidence_sha256"));m.put("confidence",rs.getString("confidence"));
  m.put("attributes",parseMap(rs.getString("attributes")));return m;
 }

 String reportMarkdown(String key){
  Map<String,Object> e=getExperiment(key);StringBuilder s=new StringBuilder();
  s.append("# ReverseLens Benchmark Report\n\n**Experiment:** ").append(e.get("name")).append("\n\n");
  s.append("**ID:** ").append(key).append("  \n**Status:** ").append(e.get("status")).append("  \n");
  s.append("**Dataset:** ").append(((Map<?,?>)e.get("dataset")).get("datasetId")).append("  \n");
  s.append("**Input manifest SHA-256:** ").append(e.get("inputManifestSha256")).append("\n\n");
  s.append("## Methodology\n\nRepetitions: ").append(e.get("repetitions")).append("; concurrency: 1; cache policy: ")
   .append(e.get("cachePolicy")).append("; methodology version: ").append(e.get("methodologyVersion")).append(".\n\n");
  s.append("## Engine scorecard\n\n| Engine | Tool versions | Adapter versions | Attempts | Succeeded | Median wall ms | Median CPU ms | Median peak RSS bytes | Median output bytes | Precision | Recall | F1 | Coverage |\n");
  s.append("|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n");
  Map<?,?> summary=(Map<?,?>)e.get("summary");
  for(Object o:(List<?>)summary.get("engines")){
   Map<?,?> row=(Map<?,?>)o;s.append("| ").append(row.get("engineId")).append(" | ").append(na(row.get("toolVersions"))).append(" | ")
    .append(na(row.get("adapterVersions"))).append(" | ").append(row.get("attempts")).append(" | ")
    .append(row.get("succeeded")).append(" | ").append(na(row.get("medianDurationMs"))).append(" | ")
    .append(na(row.get("medianCpuTimeMs"))).append(" | ").append(na(row.get("medianPeakRssBytes"))).append(" | ")
    .append(na(row.get("medianOutputBytes"))).append(" | ").append(na(row.get("meanPrecision"))).append(" | ")
    .append(na(row.get("meanRecall"))).append(" | ").append(na(row.get("meanF1"))).append(" | ")
    .append(na(row.get("meanCoverage"))).append(" |\n");
  }
  s.append("\nN/A means no verified capability-compatible ground truth was available; missing metrics are not zero.\n\n");
  s.append("## Maintainer-provided OWASP mappings\n\n");
  Object owaspValue=summary.get("owaspMappings");
  List<?> owasp=owaspValue instanceof List<?> values?values:List.of();
  for(Object tag:owasp)s.append("- ").append(tag).append("\n");
  if(owasp.isEmpty())s.append("No OWASP mappings were supplied on verified ground-truth labels.\n");
  s.append("\n## Unique recoveries\n\n");
  for(Object o:(List<?>)summary.get("uniqueRecoveries")){Map<?,?> row=(Map<?,?>)o;s.append("- ").append(row.get("canonicalKey")).append(" — ").append(row.get("engines")).append("\n");}
  s.append("\n## Attempts\n\n| Target | Engine | Tool | Adapter | Repetition | Status | Wall ms | CPU ms | Peak RSS bytes | Output bytes | TP | FP | FN |\n|---|---|---:|---|---:|---:|---:|---:|---:|\n");
  for(Object o:(List<?>)e.get("attempts")){Map<?,?> row=(Map<?,?>)o;
   Map<?,?> wm=row.get("workerMetrics") instanceof Map<?,?> metrics?metrics:Map.of();
   s.append("| ").append(row.get("targetId")).append(" | ").append(row.get("engineId")).append(" | ")
   .append(na(row.get("toolVersion"))).append(" | ").append(na(row.get("adapterVersion"))).append(" | ")
   .append(row.get("repetition")).append(" | ").append(row.get("status")).append(" | ").append(na(row.get("durationMs"))).append(" | ")
   .append(na(wm.get("cpu_time_ms"))).append(" | ")
   .append(na(wm.get("peak_rss_bytes"))).append(" | ")
   .append(na(row.get("outputBytes"))).append(" | ").append(na(row.get("truePositive"))).append(" | ")
   .append(na(row.get("falsePositive"))).append(" | ").append(na(row.get("falseNegative"))).append(" |\n");}
  s.append("\n## Limitations\n\n- Decompiled/reconstructed output is not guaranteed to match original source.\n");
  s.append("- Accuracy is based only on verified labels for capability classes declared by the engine.\n");
  s.append("- Phase 2 v1 executes sequentially (concurrency=1).\n");
  s.append("- Cache policy is recorded; no operating-system cache flush is claimed.\n");return s.toString();
 }
 String reportHtml(String key){
  return "<!doctype html><html><head><meta charset=\"utf-8\"><title>ReverseLens Benchmark</title><style>body{font:15px system-ui;max-width:1100px;margin:40px auto;padding:0 20px;background:#0b1020;color:#eef4ff}pre{white-space:pre-wrap;background:#131d31;padding:24px;border-radius:12px}</style></head><body><h1>ReverseLens Benchmark Report</h1><pre>"+html(reportMarkdown(key))+"</pre></body></html>";
 }

 static List<Map<String,Object>> filterComparableObservations(List<Map<String,Object>> groundTruth,List<Map<String,Object>> observations){
  Set<String> labeled=groundTruth.stream().map(g->(String)g.get("capabilityClass")).filter(Objects::nonNull).collect(Collectors.toSet());
  return observations.stream().filter(o->labeled.contains((String)o.get("capabilityClass"))).toList();
 }
 static Set<String> capabilitiesFor(String engine){return CAPS.getOrDefault(engine,Set.of());}
 private void validateEngines(List<String> ids){
  if(ids==null||ids.isEmpty())throw bad("At least one integrated engine is required.");
  for(String id:ids)if(!engines.exists(id))throw bad("Engine is not integrated in this build: "+id);
 }
 private static String sha256File(Path path)throws java.io.IOException{
  try{
   java.security.MessageDigest digest=java.security.MessageDigest.getInstance("SHA-256");
   try(java.io.InputStream in=Files.newInputStream(path)){
    byte[] buffer=new byte[1024*1024];int n;
    while((n=in.read(buffer))!=-1)digest.update(buffer,0,n);
   }
   return HexFormat.of().formatHex(digest.digest());
  }catch(java.security.NoSuchAlgorithmException ex){throw new IllegalStateException("SHA-256 is unavailable.",ex);}
 }
 private static Map<String,Object> profileMap(java.sql.ResultSet rs)throws java.sql.SQLException{
  Map<String,Object> m=new LinkedHashMap<>();m.put("profileKey",rs.getString("profile_key"));m.put("name",rs.getString("name"));
  m.put("platform",rs.getString("platform"));m.put("capabilityClasses",split(rs.getString("capability_classes")));
  m.put("engineIds",split(rs.getString("engine_ids")));m.put("defaultRepetitions",rs.getInt("default_repetitions"));
  m.put("defaultConcurrency",rs.getInt("default_concurrency"));m.put("builtIn",rs.getBoolean("is_builtin"));return m;
 }
 private static String req(Map<String,Object> m,String key,int max){Object o=m.get(key);if(!(o instanceof String v)||v.isBlank()||v.length()>max)throw bad("Observation field "+key+" is required (max "+max+").");return v;}
 private static String canon(String s){return s.trim().toLowerCase(Locale.ROOT).replaceAll("\\s+"," ");}
 private static String csv(List<String> s){return String.join(",",s);}
 private static List<String> split(String s){return s==null||s.isBlank()?List.of():Arrays.stream(s.split(",")).filter(x->!x.isBlank()).toList();}
 private static void text(String s,String label){if(s==null||s.isBlank())throw bad(label+" is required.");}
 private static IllegalArgumentException bad(String s){return new IllegalArgumentException(s);}
 private static long num(Object v){return v instanceof Number n?Math.max(0,n.longValue()):0;}
 private static Long longOrNull(Object v){return v instanceof Number n?Math.max(0,n.longValue()):null;}
 private static Integer intOrNull(Object v){return v instanceof Number n?(int)Math.max(0,n.longValue()):null;}
 private static String json(Object v){try{return new ObjectMapper().writeValueAsString(v);}catch(Exception e){return "[]";}}
 private Map<String,Object> parseMap(String s){try{return mapper.readValue(s,new TypeReference<>(){});}catch(Exception e){return Map.of();}}
 private static String camel(String s){StringBuilder b=new StringBuilder();boolean up=false;for(char c:s.toCharArray()){if(c=='_')up=true;else{b.append(up?Character.toUpperCase(c):c);up=false;}}return b.toString();}
 private static String na(Object o){return o==null?"N/A":String.valueOf(o);}
 private static String sha256(String s)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8)));}
 private static String html(String s){return s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace("\"","&quot;").replace("'","&#39;");}
}
