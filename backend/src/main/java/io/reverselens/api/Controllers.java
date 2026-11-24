package io.reverselens.api;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.FileSystemResource;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.*;

@RestController
@RequestMapping("/api/v1/engines")
class EngineController {
  private final EngineCatalog catalog; EngineController(EngineCatalog c){catalog=c;}
  @GetMapping List<EngineDefinition> list(){return catalog.all();}
}

@RestController
@RequestMapping("/api/v1/targets")
class TargetController {
  private final TargetService targets;private final RunService runs;
  TargetController(TargetService t,RunService r){targets=t;runs=r;}
  @GetMapping List<TargetResponse> list(){return targets.list();}
  @PostMapping(value="/android",consumes=MediaType.MULTIPART_FORM_DATA_VALUE)
  @ResponseStatus(HttpStatus.CREATED)
  TargetResponse upload(@RequestPart("file") MultipartFile file,@RequestParam(required=false)String identifier,
      @RequestParam String authorizationBasis,@RequestParam boolean authorizationConfirmed)throws Exception{
    return targets.upload(file,identifier,authorizationBasis,authorizationConfirmed);
  }
  @GetMapping("/{id}") TargetResponse get(@PathVariable UUID id){
    TargetResponse value=targets.get(id);if(value==null)throw new IllegalArgumentException("Target not found.");return value;
  }
  @PostMapping("/{id}/runs") @ResponseStatus(HttpStatus.CREATED)
  RunCreatedResponse create(@PathVariable UUID id,@RequestBody(required=false)RunRequest request)throws Exception{return runs.create(id,request);}
  @GetMapping("/{id}/runs") List<RunResponse> listRuns(@PathVariable UUID id){return runs.list(id);}
}

@RestController
@RequestMapping("/api/v1/runs")
class RunController {
  private final RunService runs;RunController(RunService r){runs=r;}
  @GetMapping("/{id}") RunResponse get(@PathVariable UUID id){
    RunResponse value=runs.get(id);if(value==null)throw new IllegalArgumentException("Run not found.");return value;
  }
  @GetMapping("/{id}/files") List<OutputFile> files(@PathVariable UUID id)throws Exception{
    if(runs.get(id)==null)throw new IllegalArgumentException("Run not found.");return runs.files(id);
  }
  @GetMapping("/{id}/file") ResponseEntity<FileSystemResource> download(@PathVariable UUID id,@RequestParam String path){
    Path file=runs.file(id,path);
    return ResponseEntity.ok().contentType(MediaType.APPLICATION_OCTET_STREAM)
      .header(HttpHeaders.CONTENT_DISPOSITION,"attachment; filename=\""+file.getFileName().toString().replace("\"","")+"\"")
      .body(new FileSystemResource(file));
  }
}

@RestController
@RequestMapping("/internal/v1/worker/executions")
class WorkerController {
  private final RunService runs;private final BenchmarkService benchmarks;private final String token;
  WorkerController(RunService r,BenchmarkService b,@Value("${reverselens.worker-token}")String token){runs=r;benchmarks=b;this.token=token;}
  @PutMapping("/{id}") void update(@PathVariable UUID id,@RequestHeader("X-ReverseLens-Worker-Token")String supplied,@RequestBody WorkerUpdate body){
    if(!MessageDigest.isEqual(token.getBytes(StandardCharsets.UTF_8),supplied.getBytes(StandardCharsets.UTF_8)))
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,"Worker token rejected");
    runs.update(id,body);
    if("running".equals(body.status()))benchmarks.executionStarted(id);
    else benchmarks.finalizeExecution(id);
  }
}

@RestControllerAdvice
class ApiErrors {
  @ExceptionHandler(IllegalArgumentException.class)
  ResponseEntity<Map<String,Object>> badRequest(IllegalArgumentException e){return ResponseEntity.badRequest().body(Map.of("status",400,"error","Bad Request","message",e.getMessage()==null?"Invalid request":e.getMessage()));}
  @ExceptionHandler(Exception.class)
  ResponseEntity<Map<String,Object>> failed(Exception e){return ResponseEntity.status(500).body(Map.of("status",500,"error","Internal Server Error","message","Request could not be completed. See server logs."));}
}
