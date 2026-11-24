"use client";

import { FormEvent, useEffect, useMemo, useState } from "react";

const API = process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8080/api/v1";
type Target = { id: string; displayName: string; originalFilename: string; sha256: string; sizeBytes: number };
type DatasetTarget = { targetId: string; displayName: string; filename: string; sha256: string; sizeBytes: number };
type Dataset = { datasetId: string; name: string; targets: DatasetTarget[] };
type Profile = { profileKey: string; name: string; platform: string; engineIds: string[]; defaultRepetitions: number; builtIn: boolean };
type Attempt = { attemptId: string; targetId: string; engineId: string; repetition: number; status: string; toolVersion?: string; adapterVersion?: string; durationMs?: number; cpuTimeMs?: number; peakRssBytes?: number; outputBytes?: number; precision?: number | null; recall?: number | null; f1?: number | null; coverage?: number | null; observationCount?: number; runId?: string; workerMetrics?: Record<string, unknown> };
type Observation = { observationId: string; runId: string; runFilePath?: string; engineId: string; repetition: number; capabilityClass: string; itemType: string; title: string; observedValue: string; canonicalKey: string; evidencePath: string; evidenceSha256: string; confidence: string };
type Experiment = { id: string; experimentId: string; name: string; status: string; repetitions: number; cachePolicy: string; attempts: Attempt[]; summary: { engines: { engineId: string; toolVersions?: string; adapterVersions?: string; attempts: number; succeeded: number; medianDurationMs: number | null; medianCpuTimeMs: number | null; medianPeakRssBytes: number | null; medianOutputBytes: number | null; meanPrecision: number | null; meanRecall: number | null; meanF1: number | null; meanCoverage: number | null }[]; uniqueRecoveries: { canonicalKey: string; engines: string[] }[]; sharedRecoveries: { canonicalKey: string; engines: string[] }[]; owaspMappings?: string[] } };
type ApiError = { message?: string };

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(API + path, init);
  if (!response.ok) {
    const body = await response.json().catch(() => ({} as ApiError));
    throw new Error((body as ApiError).message || `Request failed (${response.status})`);
  }
  if (response.status === 204) return undefined as T;
  return response.json();
}
function nice(value: number | null | undefined, suffix = ""): string {
  return value == null ? "N/A" : `${Number(value).toLocaleString(undefined, { maximumFractionDigits: 3 })}${suffix}`;
}

export default function BenchmarksPage() {
  const [targets,setTargets]=useState<Target[]>([]);
  const [datasets,setDatasets]=useState<Dataset[]>([]);
  const [profiles,setProfiles]=useState<Profile[]>([]);
  const [experiments,setExperiments]=useState<Experiment[]>([]);
  const [selected,setSelected]=useState("");
  const [selectedDataset,setSelectedDataset]=useState("");
  const [groundTruthTargetId,setGroundTruthTargetId]=useState("");
  const [detail,setDetail]=useState<Experiment|null>(null);
  const [observations,setObservations]=useState<Observation[]>([]);
  const [observationEngine,setObservationEngine]=useState("");
  const [datasetName,setDatasetName]=useState("My Android benchmark set");
  const [datasetKey,setDatasetKey]=useState("my-android-benchmark");
  const [datasetTarget,setDatasetTarget]=useState("");
  const [license,setLicense]=useState("Not reviewed — local authorized samples");
  const [redistribution,setRedistribution]=useState("not_reviewed");
  const [datasetSource,setDatasetSource]=useState("authorized_exploratory");
  const [groundTruthCapability,setGroundTruthCapability]=useState("apk_parsing");
  const [groundTruthType,setGroundTruthType]=useState("permission");
  const [groundTruthValue,setGroundTruthValue]=useState("");
  const [groundTruthKey,setGroundTruthKey]=useState("");
  const [groundTruthStatus,setGroundTruthStatus]=useState("unreviewed");
  const [reviewer,setReviewer]=useState("");
  const [groundTruthSourcePath,setGroundTruthSourcePath]=useState("");
  const [groundTruthSourceRevision,setGroundTruthSourceRevision]=useState("");
  const [groundTruthSourceSha,setGroundTruthSourceSha]=useState("");
  const [owaspTags,setOwaspTags]=useState("");
  const [profileKey,setProfileKey]=useState("android-static-core");
  const [experimentName,setExperimentName]=useState("Android static engine comparison");
  const [repetitions,setRepetitions]=useState(3);
  const [cachePolicy,setCachePolicy]=useState("not_controlled");
  const [busy,setBusy]=useState(false);
  const [message,setMessage]=useState("");
  const [error,setError]=useState("");

  async function refresh() {
    const [targetList,datasetList,profileList,experimentList]=await Promise.all([
      api<Target[]>("/targets"),
      api<Dataset[]>("/benchmarks/datasets"),
      api<Profile[]>("/benchmarks/profiles"),
      api<{experiments: Experiment[]}>("/benchmarks/experiments")
    ]);
    setTargets(targetList);setDatasets(datasetList);setProfiles(profileList);setExperiments(experimentList.experiments);
    if(!datasetTarget&&targetList.length)setDatasetTarget(targetList[0].id);
    if(!selectedDataset&&datasetList.length)setSelectedDataset(datasetList[0].datasetId);
    const currentDataset=datasetList.find(d=>d.datasetId===selectedDataset)||datasetList[0];
    if(currentDataset?.targets.length&&!groundTruthTargetId)setGroundTruthTargetId(currentDataset.targets[0].targetId);
    if(!selected&&experimentList.experiments.length)setSelected(experimentList.experiments[0].experimentId);
  }
  async function loadExperiment(id:string) {
    if(!id){setDetail(null);setObservations([]);return;}
    setDetail(await api<Experiment>(`/benchmarks/experiments/${id}`));
    await loadObservations(id);
  }
  async function loadObservations(id:string) {
    if(!id){setObservations([]);return;}
    const query=new URLSearchParams({limit:"1000"});
    if(observationEngine)query.set("engineId",observationEngine);
    setObservations(await api<Observation[]>(`/benchmarks/experiments/${id}/observations?${query.toString()}`));
  }
  useEffect(()=>{refresh().catch(e=>setError(e.message));},[]);
  useEffect(()=>{loadExperiment(selected).catch(e=>setError(e.message));},[selected]);
  useEffect(()=>{if(selected)loadObservations(selected).catch(e=>setError(e.message));},[observationEngine]);

  async function createDataset(event:FormEvent) {
    event.preventDefault();if(!datasetTarget)return;
    setBusy(true);setError("");setMessage("");
    try {
      const created=await api<Dataset>("/benchmarks/datasets",{method:"POST",headers:{"Content-Type":"application/json"},
        body:JSON.stringify({datasetId:datasetKey,name:datasetName,version:"1.0.0",sourceType:datasetSource,
          description:"Local benchmark dataset. Use only targets you are authorized to analyze.",
          platforms:["android"],capabilityClasses:["apk_parsing","dex_analysis","dex_to_source","android_resources","manifest","smali","packer_detection"],
          targetIds:[datasetTarget],groundTruthAvailable:false,
          licenseIdentifier:license,redistributionStatus:redistribution})});
      await refresh();setSelectedDataset(created.datasetId);setMessage(`Dataset ${created.datasetId} created.`);
    } catch(e){setError(e instanceof Error?e.message:"Dataset creation failed");}
    finally{setBusy(false);}
  }

  async function addGroundTruth(event:FormEvent) {
    event.preventDefault();const dataset=datasets.find(d=>d.datasetId===selectedDataset);if(!dataset||!groundTruthValue.trim()||!groundTruthTargetId)return;
    const targetId=groundTruthTargetId;
    setBusy(true);setError("");setMessage("");
    try {
      await api(`/benchmarks/datasets/${dataset.datasetId}/ground-truth?targetId=${targetId}`,{
        method:"POST",headers:{"Content-Type":"application/json"},
        body:JSON.stringify({capabilityClass:groundTruthCapability,itemType:groundTruthType,
          expectedValue:groundTruthValue,canonicalKey:groundTruthKey||null,
          validationStatus:groundTruthStatus,reviewer:reviewer||null,owaspMappings:owaspTags.split(",").map(v=>v.trim()).filter(Boolean),
          sourceReference:{source_path:groundTruthSourcePath||null,source_revision:groundTruthSourceRevision||null,source_sha256:groundTruthSourceSha||null},
          notes:"Label supplied by dataset maintainer; validate before using for accuracy scoring."})
      });
      setGroundTruthValue("");setGroundTruthKey("");setOwaspTags("");
      await refresh();setMessage("Ground-truth label added. Only labels marked verified contribute to accuracy scores.");
    } catch(e){setError(e instanceof Error?e.message:"Ground-truth import failed");}
    finally{setBusy(false);}
  }

  async function createExperiment(event:FormEvent) {
    event.preventDefault();const dataset=datasets.find(d=>d.datasetId===selectedDataset);if(!dataset)return;
    setBusy(true);setError("");setMessage("");
    try {
      const created=await api<Experiment>("/benchmarks/experiments",{method:"POST",headers:{"Content-Type":"application/json"},
        body:JSON.stringify({name:experimentName,datasetId:dataset.datasetId,profileKey,
          repetitions,concurrency:1,cachePolicy})});
      await refresh();setSelected(created.experimentId);setMessage(`Experiment ${created.experimentId} queued. Each repetition is an independent engine run.`);
    } catch(e){setError(e instanceof Error?e.message:"Experiment creation failed");}
    finally{setBusy(false);}
  }

  const currentDataset=datasets.find(d=>d.datasetId===selectedDataset);
  const canRun=Boolean(currentDataset&&currentDataset.targets.length);
  const runningCount=useMemo(()=>experiments.filter(e=>["queued","running"].includes(e.status)).length,[experiments]);

  return <main>
    <header>
      <div><div className="pill">Phase 2 · Benchmark engine</div><h1>Benchmark Lab</h1>
        <p>Compare compatible analyzers across repeated runs, verified labels, and evidence-linked recoveries.</p></div>
      <div className="row"><a href="/" className="muted">Analysis workbench</a><button onClick={()=>refresh().catch(e=>setError(e.message))}>Refresh</button></div>
    </header>
    {message&&<p className="success">{message}</p>}{error&&<p className="error">{error}</p>}
    <div className="grid">
      <section className="panel stack">
        <div><h2>1. Register benchmark dataset</h2><p className="muted">Attach uploaded, authorized targets and record licensing/provenance.</p></div>
        <form className="stack" onSubmit={createDataset}>
          <label>Existing dataset for labels and experiments<select value={selectedDataset} onChange={e=>{setSelectedDataset(e.target.value);const d=datasets.find(x=>x.datasetId===e.target.value);setGroundTruthTargetId(d?.targets[0]?.targetId||"");}}>
            <option value="">Choose a dataset</option>{datasets.map(d=><option key={d.datasetId} value={d.datasetId}>{d.name} · {d.targets.length} target(s)</option>)}
          </select></label>
          <label>Dataset name<input value={datasetName} onChange={e=>setDatasetName(e.target.value)} required/></label>
          <label>Dataset key<input value={datasetKey} onChange={e=>setDatasetKey(e.target.value)} required/></label>
          <label>New dataset target<select value={datasetTarget} onChange={e=>setDatasetTarget(e.target.value)} required>
            <option value="">Choose an uploaded APK target</option>
            {targets.map(t=><option key={t.id} value={t.id}>{t.displayName} · {t.originalFilename}</option>)}
          </select></label>
          <label>Dataset source<select value={datasetSource} onChange={e=>setDatasetSource(e.target.value)}>
            <option value="authorized_exploratory">Authorized exploratory</option><option value="source_known">Source-known</option>
            <option value="open_source_with_known_revision">Open source with known revision</option>
            <option value="owasp_training">OWASP training target</option><option value="fictional_example">Fictional example</option>
          </select></label>
          <label>License / rights basis<input value={license} onChange={e=>setLicense(e.target.value)} required/></label>
          <label>Redistribution review<select value={redistribution} onChange={e=>setRedistribution(e.target.value)}>
            <option value="not_reviewed">Not reviewed</option><option value="conditional">Conditional</option>
            <option value="allowed">Allowed</option><option value="not_allowed">Not allowed</option>
          </select></label>
          <button disabled={busy||!datasetTarget}>Create another dataset</button>
        </form>
        <div className="divider"/>
        <div><h2>2. Add ground-truth labels</h2><p className="muted">Only labels explicitly marked verified affect precision, recall and F1.</p></div>
        <form className="stack" onSubmit={addGroundTruth}>
          <label>Dataset<select value={selectedDataset} onChange={e=>{setSelectedDataset(e.target.value);const d=datasets.find(x=>x.datasetId===e.target.value);setGroundTruthTargetId(d?.targets[0]?.targetId||"");}}>
            {datasets.map(d=><option key={d.datasetId} value={d.datasetId}>{d.name}</option>)}
          </select></label>
          <label>Target<select value={groundTruthTargetId} onChange={e=>setGroundTruthTargetId(e.target.value)}>
            {(currentDataset?.targets||[]).map(t=><option key={t.targetId} value={t.targetId}>{t.displayName} · {t.filename}</option>)}
          </select></label>
          <label>Capability class<select value={groundTruthCapability} onChange={e=>setGroundTruthCapability(e.target.value)}>
            <option value="apk_parsing">APK parsing</option><option value="manifest">Manifest</option>
            <option value="android_resources">Android resources</option><option value="dex_analysis">DEX analysis</option>
            <option value="dex_to_source">DEX to source</option><option value="smali">Smali</option>
            <option value="packer_detection">Packer detection</option><option value="compiler_detection">Compiler detection</option>
          </select></label>
          <label>Item type<select value={groundTruthType} onChange={e=>setGroundTruthType(e.target.value)}>
            <option value="permission">Permission</option><option value="manifest_component">Manifest component</option>
            <option value="class">Class</option><option value="method">Method</option><option value="resource">Resource</option>
            <option value="other">Other</option>
          </select></label>
          <label>Expected value<input value={groundTruthValue} onChange={e=>setGroundTruthValue(e.target.value)} placeholder="android.permission.INTERNET" required/></label>
          <label>Canonical key (optional)<input value={groundTruthKey} onChange={e=>setGroundTruthKey(e.target.value)} placeholder="permission:android.permission.internet"/></label>
          <label>Review status<select value={groundTruthStatus} onChange={e=>setGroundTruthStatus(e.target.value)}>
            <option value="unreviewed">Unreviewed</option><option value="reviewed">Reviewed</option><option value="verified">Verified</option>
            <option value="disputed">Disputed</option><option value="not_applicable">Not applicable</option>
          </select></label>
          <label>Reviewer<input value={reviewer} onChange={e=>setReviewer(e.target.value)} placeholder="Maintainer or reviewer"/></label>
          <label>Ground-truth source path<input value={groundTruthSourcePath} onChange={e=>setGroundTruthSourcePath(e.target.value)} placeholder="source/AndroidManifest.xml or analysis reference"/></label>
          <label>Source revision<input value={groundTruthSourceRevision} onChange={e=>setGroundTruthSourceRevision(e.target.value)} placeholder="Git commit / dataset revision"/></label>
          <label>Source SHA-256<input value={groundTruthSourceSha} onChange={e=>setGroundTruthSourceSha(e.target.value)} placeholder="Optional 64-character digest"/></label>
          <label>OWASP mapping tags (comma-separated, optional)<input value={owaspTags} onChange={e=>setOwaspTags(e.target.value)} placeholder="MASVS-STORAGE-1, MASTG-TEST-0001"/></label>
          <button disabled={busy||!canRun||!groundTruthValue.trim()||!groundTruthTargetId||(groundTruthStatus==="verified"&&(!reviewer.trim()||(!groundTruthSourcePath.trim()&&!groundTruthSourceRevision.trim()&&!groundTruthSourceSha.trim())))}>Add ground-truth item</button>
        </form>
        <p className="notice">The UI currently associates new labels with the first target in the dataset. Manage multi-target ground truth through the API.</p>
      </section>
      <section className="panel stack">
        <div><h2>3. Configure experiment</h2><p className="muted">One engine execution per target and repetition. Phase 2 v1 enforces sequential concurrency.</p></div>
        <form className="stack" onSubmit={createExperiment}>
          <label>Dataset<select value={selectedDataset} onChange={e=>setSelectedDataset(e.target.value)}>{datasets.map(d=><option key={d.datasetId} value={d.datasetId}>{d.name}</option>)}</select></label>
          <label>Experiment name<input value={experimentName} onChange={e=>setExperimentName(e.target.value)} required/></label>
          <label>Engine profile<select value={profileKey} onChange={e=>setProfileKey(e.target.value)}>
            {profiles.map(p=><option key={p.profileKey} value={p.profileKey}>{p.name} · {p.engineIds.join(", ")}</option>)}
          </select></label>
          <label>Repetitions<select value={repetitions} onChange={e=>setRepetitions(Number(e.target.value))}>
            {[1,2,3,5,10].map(n=><option key={n} value={n}>{n}</option>)}
          </select></label>
          <label>Cache policy (recorded, not OS-controlled)<select value={cachePolicy} onChange={e=>setCachePolicy(e.target.value)}>
            <option value="not_controlled">Not controlled</option><option value="cold_each_run">Cold each run (declared)</option>
            <option value="warm_each_run">Warm each run (declared)</option><option value="mixed">Mixed</option>
          </select></label>
          <label>Concurrency<input value="1 · enforced for repeatability" disabled/></label>
          <button disabled={busy||!canRun}>Create and queue experiment</button>
        </form>
        <div className="item">
          <div className="row"><h2>Experiment history</h2><span className="pill">{runningCount} active</span></div>
          {!experiments.length&&<p className="muted">No benchmark experiments created yet.</p>}
          {experiments.map(e=><button key={e.experimentId} className="experiment-button" onClick={()=>setSelected(e.experimentId)}>
            <span><strong>{e.name}</strong><br/><small>{e.experimentId} · {e.repetitions} repetitions</small></span>
            <span className="pill">{e.status}</span>
          </button>)}
        </div>
      </section>
    </div>
    {detail&&<section className="panel stack" style={{marginTop:18}}>
      <div className="row" style={{justifyContent:"space-between"}}>
        <div><div className="pill">Result dossier</div><h2>{detail.name}</h2><p className="muted">{detail.experimentId} · {detail.status} · SHA-256 {detail.id}</p></div>
        <div className="row"><a href={`${API}/benchmarks/experiments/${detail.experimentId}/report?format=markdown`} target="_blank" rel="noreferrer">Markdown</a>
          <a href={`${API}/benchmarks/experiments/${detail.experimentId}/report?format=html`} target="_blank" rel="noreferrer">HTML</a>
          <a href={`${API}/benchmarks/experiments/${detail.experimentId}/report`} target="_blank" rel="noreferrer">JSON</a>
        </div>
      </div>
      <h2>Per-engine scorecard</h2>
      <div className="table-wrap"><table><thead><tr><th>Engine</th><th>Tool versions</th><th>Adapter versions</th><th>Attempts</th><th>Success</th><th>Median wall ms</th><th>CPU ms</th><th>Peak RSS bytes</th><th>Output bytes</th><th>Precision</th><th>Recall</th><th>F1</th><th>Coverage</th></tr></thead>
        <tbody>{detail.summary.engines.map(row=><tr key={row.engineId}><td>{row.engineId}</td><td>{row.toolVersions||"—"}</td><td>{row.adapterVersions||"—"}</td><td>{row.attempts}</td><td>{row.succeeded}</td>
          <td>{nice(row.medianDurationMs)}</td><td>{nice(row.medianCpuTimeMs)}</td><td>{nice(row.medianPeakRssBytes)}</td>
          <td>{nice(row.medianOutputBytes)}</td><td>{nice(row.meanPrecision)}</td><td>{nice(row.meanRecall)}</td><td>{nice(row.meanF1)}</td><td>{nice(row.meanCoverage)}</td></tr>)}</tbody></table></div>
      <p className="notice">N/A indicates no verified capability-compatible ground truth, not a zero score.</p>
      <div className="grid">
        <div><h2>Unique recoveries</h2>{detail.summary.uniqueRecoveries.slice(0,100).map(x=><div className="result-line" key={x.canonicalKey}><code>{x.canonicalKey}</code><small>{x.engines.join(", ")}</small></div>)}</div>
        <div><h2>Shared recoveries</h2>{detail.summary.sharedRecoveries.slice(0,100).map(x=><div className="result-line" key={x.canonicalKey}><code>{x.canonicalKey}</code><small>{x.engines.join(", ")}</small></div>)}</div>
      </div>
      <h2>Normalized evidence observations</h2>
      <div className="row"><label style={{maxWidth:260}}>Filter by engine<select value={observationEngine} onChange={e=>setObservationEngine(e.target.value)}>
        <option value="">All engines</option>{detail.attempts.map(a=>a.engineId).filter((v,i,a)=>a.indexOf(v)===i).map(id=><option key={id} value={id}>{id}</option>)}
      </select></label><span className="muted">{observations.length} observation(s), limited to 1,000 per query</span></div>
      <div className="table-wrap"><table><thead><tr><th>Engine</th><th>Capability</th><th>Type</th><th>Normalized value</th><th>Confidence</th><th>Evidence</th></tr></thead>
        <tbody>{observations.map(o=><tr key={o.observationId}><td>{o.engineId} · r{o.repetition}</td><td>{o.capabilityClass}</td><td>{o.itemType}</td>
          <td><code>{o.canonicalKey}</code></td><td>{o.confidence}</td><td>{o.runFilePath?
            <a href={`${API}/runs/${o.runId}/file?path=${encodeURIComponent(o.runFilePath)}`} target="_blank" rel="noreferrer">Open raw evidence</a>:
            <span title={o.evidencePath}>Path only</span>}</td></tr>)}</tbody></table></div>
      {detail.summary.owaspMappings?.length?<p className="muted">Maintainer-provided OWASP tags on verified labels: {detail.summary.owaspMappings.join(", ")}</p>:<p className="muted">No OWASP mappings were supplied for verified ground-truth labels.</p>}
      <h2>Execution attempts</h2>
      <div className="table-wrap"><table><thead><tr><th>Target</th><th>Engine</th><th>Tool / Adapter</th><th>Run #</th><th>Status</th><th>Wall ms</th><th>Output bytes</th><th>Observations</th></tr></thead>
        <tbody>{detail.attempts.map(a=><tr key={a.attemptId}><td>{a.targetId.slice(0,8)}</td><td>{a.engineId}</td><td>{a.toolVersion||"—"} / {a.adapterVersion||"—"}</td><td>{a.repetition}</td><td>{a.status}</td><td>{nice(a.durationMs)}</td><td>{nice(a.outputBytes)}</td><td>{a.observationCount??"—"}</td></tr>)}</tbody></table></div>
    </section>}
  </main>;
}
