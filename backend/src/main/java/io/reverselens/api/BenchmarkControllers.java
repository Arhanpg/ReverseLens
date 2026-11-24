package io.reverselens.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

@RestController
@RequestMapping("/api/v1/benchmarks")
class BenchmarkController {
    private final BenchmarkService service;
    BenchmarkController(BenchmarkService service) { this.service=service; }

    @GetMapping("/datasets")
    List<Map<String,Object>> datasets() { return service.listDatasets(); }

    @PostMapping("/datasets")
    @ResponseStatus(HttpStatus.CREATED)
    Map<String,Object> createDataset(@RequestBody DatasetRequest request) throws Exception {
        return service.createDataset(request);
    }

    @GetMapping("/datasets/{datasetId}")
    Map<String,Object> getDataset(@PathVariable String datasetId) { return service.getDataset(datasetId); }

    @PostMapping("/datasets/{datasetId}/ground-truth")
    @ResponseStatus(HttpStatus.CREATED)
    Map<String,Object> addGroundTruth(@PathVariable String datasetId, @RequestParam UUID targetId,
                                      @RequestBody GroundTruthRequest request) throws Exception {
        return service.addGroundTruth(datasetId,targetId,request);
    }

    @GetMapping("/datasets/{datasetId}/ground-truth")
    List<Map<String,Object>> groundTruth(@PathVariable String datasetId) { return service.listGroundTruth(datasetId); }

    @GetMapping("/profiles")
    List<Map<String,Object>> profiles() { return service.listProfiles(); }

    @PostMapping("/profiles")
    @ResponseStatus(HttpStatus.CREATED)
    Map<String,Object> createProfile(@RequestBody ProfileRequest request) { return service.createProfile(request); }

    @GetMapping("/profiles/{profileKey}")
    Map<String,Object> profile(@PathVariable String profileKey) { return service.getProfile(profileKey); }

    @PostMapping("/experiments")
    @ResponseStatus(HttpStatus.CREATED)
    Map<String,Object> createExperiment(@RequestBody ExperimentRequest request) throws Exception {
        return service.createExperiment(request);
    }

    @GetMapping("/experiments")
    Map<String,Object> experiments() { return service.listExperiments(); }

    @GetMapping("/experiments/{experimentId}")
    Map<String,Object> experiment(@PathVariable String experimentId) { return service.getExperiment(experimentId); }

    @GetMapping("/experiments/{experimentId}/observations")
    List<Map<String,Object>> observations(@PathVariable String experimentId,
            @RequestParam(required=false) String engineId,
            @RequestParam(defaultValue="1000") int limit) {
        return service.listObservations(experimentId,engineId,limit);
    }

    @GetMapping(value="/experiments/{experimentId}/report", produces="application/json")
    Map<String,Object> reportJson(@PathVariable String experimentId) { return service.reportJson(experimentId); }

    @GetMapping(value="/experiments/{experimentId}/report", params="format=markdown", produces="text/markdown")
    ResponseEntity<String> reportMarkdown(@PathVariable String experimentId) {
        return ResponseEntity.ok().contentType(MediaType.parseMediaType("text/markdown; charset=UTF-8"))
                .body(service.reportMarkdown(experimentId));
    }

    @GetMapping(value="/experiments/{experimentId}/report", params="format=html", produces="text/html")
    ResponseEntity<String> reportHtml(@PathVariable String experimentId) {
        return ResponseEntity.ok().contentType(MediaType.TEXT_HTML).body(service.reportHtml(experimentId));
    }
}

@RestController
@RequestMapping("/internal/v1/worker/executions")
class BenchmarkWorkerController {
    private final BenchmarkService benchmarks;
    private final String token;
    BenchmarkWorkerController(BenchmarkService benchmarks,
            @Value("${reverselens.worker-token}") String token) {
        this.benchmarks=benchmarks; this.token=token;
    }

    @PostMapping("/{executionId}/benchmark-data")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    void record(@PathVariable UUID executionId,
                @RequestHeader("X-ReverseLens-Worker-Token") String supplied,
                @RequestBody WorkerBenchmarkData payload) throws Exception {
        if(!MessageDigest.isEqual(token.getBytes(StandardCharsets.UTF_8),supplied.getBytes(StandardCharsets.UTF_8)))
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,"Worker token rejected");
        benchmarks.recordWorkerData(executionId,payload);
    }
}
