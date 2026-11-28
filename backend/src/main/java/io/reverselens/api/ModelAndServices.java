package io.reverselens.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.web.multipart.MultipartFile;

import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.*;
import java.util.zip.ZipFile;

record EngineDefinition(String engineId, String name, String version, List<String> supportedFormats,
                         String capability, String description, String integrationStatus) {}
record TargetResponse(UUID id, String targetType, String displayName, String identifier, String originalFilename,
                      String sha256, long sizeBytes, String authorizationBasis, Instant createdAt) {}
record RunRequest(List<String> engineIds) {}
record RunCreatedResponse(UUID id, UUID targetId, String status, List<String> engineIds, Instant createdAt) {}
record ExecutionResponse(UUID id, String engineId, String status, String outputDirectory, String toolVersion,
                         Integer exitCode, Long durationMs, Long outputBytes, String errorSummary) {}
record RunResponse(UUID id, UUID targetId, String status, List<String> engineIds, String inputSha256,
                   Instant createdAt, Instant startedAt, Instant finishedAt, List<ExecutionResponse> executions) {}
record OutputFile(String path, long sizeBytes) {}
record WorkerUpdate(String status, String toolVersion, Integer exitCode, Long durationMs,
                    Long outputBytes, String errorSummary) {}

@Component
class EngineCatalog {
    private final Map<String, EngineDefinition> engines = Map.ofEntries(
      Map.entry("jadx", new EngineDefinition("jadx","JADX","1.5.7",List.of("apk"),"dex-to-source","DEX to Java-like source reconstruction.","integrated")),
      Map.entry("apktool", new EngineDefinition("apktool","Apktool","3.0.3",List.of("apk"),"resources-and-smali","Decode Android resources, manifest and Smali.","integrated")),
      Map.entry("androguard", new EngineDefinition("androguard","Androguard","4.1.4",List.of("apk"),"apk-metadata-and-dex","Programmatic APK/DEX metadata and class inspection.","integrated")),
      Map.entry("apkid", new EngineDefinition("apkid","APKiD","3.2.0",List.of("apk"),"packer-fingerprinting","Identify supported compilers, packers and protectors.","integrated")),
      Map.entry("bundletool", new EngineDefinition("bundletool","bundletool","1.18.3",List.of("aab","apks"),"app-bundle-inspection","Validate bundles and inspect split inventories.","integrated")),
      Map.entry("apkeditor", new EngineDefinition("apkeditor","APKEditor","1.4.9",List.of("apk","apks"),"apk-resource-decoding","Decode APK resources and manifest XML; APKS analysis uses the selected base split.","integrated")),
      Map.entry("apkleaks", new EngineDefinition("apkleaks","APKLeaks","2.6.3",List.of("apk","apks"),"uri-and-string-triage","Extract URI and secret-pattern candidates; findings require manual validation.","integrated")),
      Map.entry("hermes-dec", new EngineDefinition("hermes-dec","Hermes Decompiler","0.1.8",List.of("apk","apks"),"hermes-bytecode","Disassemble and partially reconstruct a verified Hermes HBC bundle.","optional")),
      Map.entry("blutter", new EngineDefinition("blutter","Blutter","pre-provisioned",List.of("apk","apks"),"flutter-aot","Analyze supported Android ARM64 Flutter libapp.so artifacts.","optional")),
      Map.entry("ghidra", new EngineDefinition("ghidra","Ghidra","12.2",List.of("apk","apks"),"native-pseudocode-and-call-graph","Headless native ELF analysis, pseudocode and static call references.","optional")),
      Map.entry("mobsf", new EngineDefinition("mobsf","MobSF","self-hosted",List.of("apk","apks"),"mobile-static-analysis","Submit to a configured private/self-hosted MobSF API.","optional")),
      Map.entry("exodus-standalone", new EngineDefinition("exodus-standalone","Exodus Standalone","1.5.0",List.of("apk","apks"),"tracker-signature-matching","Local tracker-signature matching; not runtime tracking confirmation.","optional"))
    );
    List<EngineDefinition> all() {
      return engines.values().stream().sorted(Comparator.comparing(EngineDefinition::engineId)).toList();
    }
    boolean exists(String id) { return engines.containsKey(id); }
    boolean supports(String id,String format) {
      return Optional.ofNullable(engines.get(id)).map(e -> e.supportedFormats().contains(format)).orElse(false);
    }
    Set<String> defaults(String format) {
      return switch(format) {
        case "apk" -> Set.of("jadx","apktool","androguard","apkid");
        case "aab","apks" -> Set.of("bundletool");
        default -> Set.of();
      };
    }
}

@Service
class WorkspaceService {
    private final Path root;
    WorkspaceService(@Value("${reverselens.workspace-root}") String configured) throws IOException {
        root=Path.of(configured).toAbsolutePath().normalize(); Files.createDirectories(root);
    }
    Path resolve(String relative) {
        Path value=root.resolve(relative).normalize();
        if (!value.startsWith(root)) throw new IllegalArgumentException("Workspace path escaped its root");
        return value;
    }
    String relative(Path path) {
        Path value=path.toAbsolutePath().normalize();
        if(!value.startsWith(root)) throw new IllegalArgumentException("Path is outside workspace");
        return root.relativize(value).toString().replace('\\','/');
    }
    Path upload(UUID id,String filename) throws IOException {
        Path dir=resolve("uploads/android/"+id); Files.createDirectories(dir); return dir.resolve(filename);
    }
    Path newRun(UUID target,UUID run,Path source,String filename) throws IOException {
        Path dir=resolve("android/"+target+"/run-"+run);
        for(String name:List.of("input","engines","normalized","benchmark","reports")) Files.createDirectories(dir.resolve(name));
        Files.copy(source,dir.resolve("input").resolve(filename),StandardCopyOption.REPLACE_EXISTING);
        return dir;
    }
    Path runPath(UUID target,UUID run) { return resolve("android/"+target+"/run-"+run); }
  }

@Service
class TargetService {
    private final JdbcTemplate jdbc; private final WorkspaceService workspace; private final long maximum;
    TargetService(JdbcTemplate jdbc,WorkspaceService workspace,@Value("${reverselens.upload-max-bytes}") long maximum){
      this.jdbc=jdbc;this.workspace=workspace;this.maximum=maximum;
    }
    TargetResponse upload(MultipartFile file,String identifier,String basis,boolean confirmed) throws IOException {
      if(!confirmed) throw new IllegalArgumentException("Confirm that you have the right to analyze this artifact.");
      if(!Set.of("owner_or_developer","written_permission","local_training_lab","lawful_possession_or_access").contains(basis))
        throw new IllegalArgumentException("A supported authorization basis is required.");
      if(file==null||file.isEmpty()||file.getSize()>maximum) throw new IllegalArgumentException("Upload must be non-empty and at most 250 MB.");
      String original=file.getOriginalFilename()==null?"artifact.apk":file.getOriginalFilename();
      String filename=Path.of(original.replace('\\','/')).getFileName().toString().replaceAll("[^A-Za-z0-9._-]","_");
      String format=extension(filename);
      if(!Set.of("apk","aab","apks").contains(format)) throw new IllegalArgumentException("Only APK, AAB and APKS are supported.");
      UUID id=UUID.randomUUID(); Path destination=workspace.upload(id,filename); MessageDigest digest=sha();
      long total=0;
      try(InputStream in=new java.security.DigestInputStream(file.getInputStream(),digest); OutputStream out=Files.newOutputStream(destination)){
        byte[] buffer=new byte[1024*1024]; int n;
        while((n=in.read(buffer))!=-1){ total+=n;if(total>maximum) throw new IllegalArgumentException("Upload exceeded size limit.");out.write(buffer,0,n);}
      }catch(Exception ex){Files.deleteIfExists(destination);throw ex;}
      String hash=HexFormat.of().formatHex(digest.digest());
      try{validateArchive(destination,format);}catch(RuntimeException ex){Files.deleteIfExists(destination);throw ex;}
      String name=(identifier==null||identifier.isBlank())?strip(filename):identifier.trim();
      Instant now=Instant.now();
      jdbc.update("INSERT INTO targets(id,target_type,display_name,identifier,original_filename,sha256,size_bytes,storage_path,authorization_basis,authorization_confirmed,created_at) VALUES(?,'android_artifact',?,?,?,?,?,?,?,TRUE,?)",
        id,name,name,filename,hash,total,workspace.relative(destination),basis,Timestamp.from(now));
      return new TargetResponse(id,"android_artifact",name,name,filename,hash,total,basis,now);
    }
    TargetResponse get(UUID id){
      List<TargetResponse> rows=jdbc.query("SELECT * FROM targets WHERE id=?",(rs,n)->new TargetResponse(
        rs.getObject("id",UUID.class),rs.getString("target_type"),rs.getString("display_name"),rs.getString("identifier"),
        rs.getString("original_filename"),rs.getString("sha256"),rs.getLong("size_bytes"),rs.getString("authorization_basis"),
        rs.getTimestamp("created_at").toInstant()),id);
      return rows.stream().findFirst().orElse(null);
    }
    List<TargetResponse> list(){
      return jdbc.query("SELECT * FROM targets ORDER BY created_at DESC LIMIT 100",(rs,n)->new TargetResponse(
        rs.getObject("id",UUID.class),rs.getString("target_type"),rs.getString("display_name"),rs.getString("identifier"),
        rs.getString("original_filename"),rs.getString("sha256"),rs.getLong("size_bytes"),rs.getString("authorization_basis"),
        rs.getTimestamp("created_at").toInstant()));
    }
    Path input(UUID id){
      String path=jdbc.query("SELECT storage_path FROM targets WHERE id=?",rs->rs.next()?rs.getString(1):null,id);
      if(path==null) throw new IllegalArgumentException("Target not found.");
      return workspace.resolve(path);
    }
    static String extension(String name){int dot=name.lastIndexOf('.');return dot<0?"":name.substring(dot+1).toLowerCase(Locale.ROOT);}
    private static String strip(String name){int dot=name.lastIndexOf('.');return dot>0?name.substring(0,dot):name;}
    private static MessageDigest sha(){try{return MessageDigest.getInstance("SHA-256");}catch(Exception e){throw new IllegalStateException(e);}}
    private static void validateArchive(Path path,String fmt){
      try(ZipFile zip=new ZipFile(path.toFile())){
        if(zip.size()>100_000) throw new IllegalArgumentException("Archive has too many entries.");
        boolean valid=switch(fmt){
          case "apk" -> zip.getEntry("AndroidManifest.xml")!=null;
          case "aab" -> zip.getEntry("BundleConfig.pb")!=null&&zip.getEntry("base/manifest/AndroidManifest.xml")!=null;
          case "apks" -> zip.getEntry("toc.pb")!=null;
          default -> false;
        };
        if(!valid) throw new IllegalArgumentException("Archive does not look like a valid "+fmt.toUpperCase(Locale.ROOT)+" package.");
        var entries=zip.entries();
        while(entries.hasMoreElements()){
          String entry=entries.nextElement().getName().replace('\\','/');
          if(entry.startsWith("/")||entry.matches("^[A-Za-z]:.*")||Arrays.asList(entry.split("/")).contains(".."))
            throw new IllegalArgumentException("Archive contains an unsafe path.");
        }
      }catch(IOException e){throw new IllegalArgumentException("Could not read Android package archive.",e);}
    }
}

@Service
class RunService {
    private static final Set<String> TERMINAL=Set.of("succeeded","partial","failed","timed_out","cancelled","incompatible");
    private final JdbcTemplate jdbc;private final TargetService targets;private final WorkspaceService workspace;
    private final EngineCatalog catalog;private final StringRedisTemplate redis;private final ObjectMapper mapper;private final String queue;
    RunService(JdbcTemplate jdbc,TargetService targets,WorkspaceService workspace,EngineCatalog catalog,
       StringRedisTemplate redis,ObjectMapper mapper,@Value("${reverselens.execution-queue}") String queue){
      this.jdbc=jdbc;this.targets=targets;this.workspace=workspace;this.catalog=catalog;this.redis=redis;this.mapper=mapper;this.queue=queue;
    }
    @Transactional
    RunCreatedResponse create(UUID targetId,RunRequest request) throws Exception {
      TargetResponse target=targets.get(targetId);if(target==null) throw new IllegalArgumentException("Target not found.");
      String fmt=TargetService.extension(target.originalFilename());
      List<String> chosen=request==null||request.engineIds()==null||request.engineIds().isEmpty()
        ?catalog.defaults(fmt).stream().sorted().toList():request.engineIds().stream().distinct().sorted().toList();
      if(chosen.isEmpty()) throw new IllegalArgumentException("No compatible engines for this package.");
      for(String engine:chosen){if(!catalog.exists(engine))throw new IllegalArgumentException("Unknown engine: "+engine);
        if(!catalog.supports(engine,fmt))throw new IllegalArgumentException(engine+" does not support ."+fmt+".");}
      UUID runId=UUID.randomUUID();Instant now=Instant.now();Path runPath=workspace.newRun(targetId,runId,targets.input(targetId),target.originalFilename());
      String relative=workspace.relative(runPath);
      jdbc.update("INSERT INTO analysis_runs(id,target_id,status,selection_mode,selected_engine_ids,input_sha256,workspace_path,created_at) VALUES(?,?,'queued',?,?,?,?,?)",
        runId,targetId,chosen.size()==1?"single":"selected_subset",String.join(",",chosen),target.sha256(),relative,Timestamp.from(now));
      List<String> jobs=new ArrayList<>();
      for(String engine:chosen){
        UUID execution=UUID.randomUUID();String out=relative+"/engines/"+engine;
        jdbc.update("INSERT INTO engine_executions(id,run_id,engine_id,status,output_directory,adapter_version,created_at) VALUES(?,?,?,'queued',?,'0.2.0',?)",
          execution,runId,engine,out,Timestamp.from(now));
        Map<String,Object> payload=new LinkedHashMap<>();payload.put("runId",runId.toString());payload.put("targetId",targetId.toString());
        payload.put("executionId",execution.toString());payload.put("engineId",engine);payload.put("inputFormat",fmt);
        payload.put("inputPath",relative+"/input/"+target.originalFilename());payload.put("inputSha256",target.sha256());payload.put("outputDirectory",out);
        jobs.add(mapper.writeValueAsString(payload));
      }
      Runnable enqueue=()->jobs.forEach(job->redis.opsForList().leftPush(queue,job));
      if(TransactionSynchronizationManager.isSynchronizationActive())TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization(){@Override public void afterCommit(){enqueue.run();}});
      else enqueue.run();
      return new RunCreatedResponse(runId,targetId,"queued",chosen,now);
    }
    void update(UUID executionId,WorkerUpdate u){
      if(!Set.of("running","succeeded","partial","failed","timed_out","cancelled","incompatible").contains(u.status()))throw new IllegalArgumentException("Invalid execution state.");
      int n;
      if("running".equals(u.status())) n=jdbc.update("UPDATE engine_executions SET status='running',tool_version=?,started_at=NOW() WHERE id=? AND status='queued'",u.toolVersion(),executionId);
      else n=jdbc.update("UPDATE engine_executions SET status=?,tool_version=COALESCE(?,tool_version),exit_code=?,duration_ms=?,output_bytes=?,error_summary=?,finished_at=NOW() WHERE id=? AND status IN ('queued','running')",
        u.status(),u.toolVersion(),u.exitCode(),u.durationMs(),u.outputBytes(),truncate(u.errorSummary()),executionId);
      if(n==0)throw new IllegalArgumentException("Execution not found or already terminal.");
      UUID runId=jdbc.query("SELECT run_id FROM engine_executions WHERE id=?",rs->rs.next()?rs.getObject(1,UUID.class):null,executionId);
      refresh(runId);
    }
    private void refresh(UUID runId){
      List<String> states=jdbc.query("SELECT status FROM engine_executions WHERE run_id=?",(rs,n)->rs.getString(1),runId);
      if(states.stream().anyMatch("running"::equals))jdbc.update("UPDATE analysis_runs SET status='running',started_at=COALESCE(started_at,NOW()) WHERE id=?",runId);
      else if(!states.isEmpty()&&states.stream().allMatch(TERMINAL::contains)){
        jdbc.update("UPDATE analysis_runs SET status=?,started_at=COALESCE(started_at,NOW()),finished_at=NOW() WHERE id=?",
          states.stream().allMatch("succeeded"::equals)?"succeeded":"partial",runId);
        writeManifest(runId);
      }
    }
    private void writeManifest(UUID id){
      try{
        RunResponse run=get(id);if(run==null)return;Path root=workspace.runPath(run.targetId(),run.id());
        Map<String,Object> data=new LinkedHashMap<>();data.put("schema_version","1.0.0");data.put("run_id",id.toString());
        data.put("target_id",run.targetId().toString());data.put("input_sha256",run.inputSha256());data.put("status",run.status());data.put("executions",run.executions());
        Files.writeString(root.resolve("run-manifest.json"),mapper.writerWithDefaultPrettyPrinter().writeValueAsString(data));
      }catch(Exception e){System.err.println("Could not write run manifest: "+e.getMessage());}
    }
    RunResponse get(UUID id){
      List<RunResponse> rows=jdbc.query("SELECT * FROM analysis_runs WHERE id=?", (rs,n)->{
        UUID runId=rs.getObject("id",UUID.class);
        List<ExecutionResponse> ex=jdbc.query("SELECT * FROM engine_executions WHERE run_id=? ORDER BY created_at,engine_id",
          (er,k)->new ExecutionResponse(er.getObject("id",UUID.class),er.getString("engine_id"),er.getString("status"),
          er.getString("output_directory"),er.getString("tool_version"),(Integer)er.getObject("exit_code"),
          (Long)er.getObject("duration_ms"),(Long)er.getObject("output_bytes"),er.getString("error_summary")),runId);
        return new RunResponse(runId,rs.getObject("target_id",UUID.class),rs.getString("status"),
          Arrays.stream(rs.getString("selected_engine_ids").split(",")).filter(s->!s.isBlank()).toList(),
          rs.getString("input_sha256"),rs.getTimestamp("created_at").toInstant(),
          rs.getTimestamp("started_at")==null?null:rs.getTimestamp("started_at").toInstant(),
          rs.getTimestamp("finished_at")==null?null:rs.getTimestamp("finished_at").toInstant(),ex);
      },id);
      return rows.stream().findFirst().orElse(null);
    }
    List<RunResponse> list(UUID target){return jdbc.query("SELECT id FROM analysis_runs WHERE target_id=? ORDER BY created_at DESC LIMIT 100",
      (rs,n)->rs.getObject(1,UUID.class),target).stream().map(this::get).filter(Objects::nonNull).toList();}
    Path root(UUID runId){String value=jdbc.query("SELECT workspace_path FROM analysis_runs WHERE id=?",rs->rs.next()?rs.getString(1):null,runId);
      if(value==null)throw new IllegalArgumentException("Run not found.");return workspace.resolve(value);}
    List<OutputFile> files(UUID runId)throws IOException{
      Path root=root(runId);try(var paths=Files.walk(root)){return paths.filter(p -> Files.isRegularFile(p, LinkOption.NOFOLLOW_LINKS) && !Files.isSymbolicLink(p))
        .map(p->new OutputFile(workspace.relative(p).substring(workspace.relative(root).length()+1),size(p)))
        .sorted(Comparator.comparing(OutputFile::path)).toList();}
    }
    Path file(UUID runId,String relative){
      if(relative==null||relative.isBlank()||relative.startsWith("/")||relative.contains("\\\\")||Arrays.asList(relative.split("/")).contains(".."))throw new IllegalArgumentException("Invalid relative file path.");
      Path root=root(runId).toAbsolutePath().normalize();Path value=root.resolve(relative).normalize();
      try { Path realRoot=root.toRealPath(); Path realFile=value.toRealPath();
        if(!realFile.startsWith(realRoot)||!Files.isRegularFile(realFile,LinkOption.NOFOLLOW_LINKS))throw new IllegalArgumentException("Output file not found.");
        return realFile;
      } catch(IOException e){throw new IllegalArgumentException("Output file not found.");}
    }
    private static long size(Path p){try{return Files.size(p);}catch(IOException e){return 0;}}
    private static String truncate(String s){return s==null?null:s.substring(0,Math.min(4000,s.length()));}
}
