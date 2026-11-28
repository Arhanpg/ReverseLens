"use client";

import { FormEvent, useEffect, useMemo, useState } from "react";

type Engine = { engineId: string; name: string; version: string; supportedFormats: string[]; description: string };
type Target = { id: string; displayName: string; originalFilename: string; sha256: string; sizeBytes: number; authorizationBasis: string; createdAt: string };
type Execution = { id: string; engineId: string; status: string; toolVersion?: string; durationMs?: number; outputBytes?: number; errorSummary?: string };
type Run = { id: string; targetId: string; status: string; inputSha256: string; createdAt: string; executions: Execution[] };
const API = process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8080/api/v1";

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(API + path, init);
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.message || `Request failed (${response.status})`);
  }
  return response.json();
}
function bytes(value: number): string {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / 1024 / 1024).toFixed(1)} MB`;
}

export default function Home() {
  const [engines,setEngines]=useState<Engine[]>([]);
  const [targets,setTargets]=useState<Target[]>([]);
  const [targetId,setTargetId]=useState("");
  const [runs,setRuns]=useState<Run[]>([]);
  const [chosen,setChosen]=useState<string[]>([]);
  const [file,setFile]=useState<File|null>(null);
  const [basis,setBasis]=useState("local_training_lab");
  const [confirmed,setConfirmed]=useState(false);
  const [busy,setBusy]=useState(false);
  const [message,setMessage]=useState("");
  const [error,setError]=useState("");
  const format=useMemo(()=>file?.name.split(".").pop()?.toLowerCase()||"",[file]);

  async function refresh() {
    const [e,t]=await Promise.all([api<Engine[]>("/engines"),api<Target[]>("/targets")]);
    setEngines(e);setTargets(t);if(!targetId&&t.length)setTargetId(t[0].id);
  }
  async function loadRuns(id:string){setRuns(id?await api<Run[]>(`/targets/${id}/runs`):[]);}
  useEffect(()=>{refresh().catch(e=>setError(e.message));},[]);
  useEffect(()=>{loadRuns(targetId).catch(e=>setError(e.message));},[targetId]);
  const compatible=engines.filter(e=>!format||e.supportedFormats.includes(format));

  async function upload(event:FormEvent) {
    event.preventDefault();if(!file||!confirmed)return;
    setBusy(true);setError("");setMessage("");
    try {
      const form=new FormData();form.append("file",file);form.append("authorizationBasis",basis);form.append("authorizationConfirmed","true");
      const target=await api<Target>("/targets/android",{method:"POST",body:form});
      await refresh();setTargetId(target.id);setFile(null);setConfirmed(false);
      setMessage(`Uploaded ${target.originalFilename}; SHA-256 recorded.`);
    } catch(e){setError(e instanceof Error?e.message:"Upload failed");}
    finally{setBusy(false);}
  }
  async function startRun() {
    if(!targetId)return;setBusy(true);setError("");setMessage("");
    try {
      const created=await api<{id:string}>(`/targets/${targetId}/runs`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({engineIds:chosen})});
      await loadRuns(targetId);setMessage(`Analysis queued: ${created.id}`);
    } catch(e){setError(e instanceof Error?e.message:"Could not start analysis");}
    finally{setBusy(false);}
  }
  return <main>
    <header><div><div className="pill">Phase 1 · Android static MVP</div><h1>ReverseLens</h1><p>Run independent analyzers against artifacts you own or are authorized to assess.</p></div><div className="row"><a href="/web" className="muted">Web Lab</a><a href="/benchmarks" className="muted">Benchmark Lab</a><button type="button" onClick={()=>refresh().catch(e=>setError(e.message))}>Refresh</button></div></header>
    {message&&<p className="success">{message}</p>}{error&&<p className="error">{error}</p>}
    <div className="grid">
      <section className="panel stack">
        <div><h2>1. Upload Android artifact</h2><p className="muted">APK, AAB and APKS · maximum 250 MB · stored in local workspace.</p></div>
        <form className="stack" onSubmit={upload}>
          <label>Package file<input type="file" accept=".apk,.aab,.apks" onChange={e=>setFile(e.target.files?.[0]||null)}/></label>
          <label>Authorization basis<select value={basis} onChange={e=>setBasis(e.target.value)}>
            <option value="local_training_lab">Local training lab</option><option value="owner_or_developer">I own or develop this app</option>
            <option value="written_permission">Written permission</option><option value="lawful_possession_or_access">Lawful possession / access</option>
          </select></label>
          <label className="engine"><input type="checkbox" checked={confirmed} onChange={e=>setConfirmed(e.target.checked)}/>I confirm I have the right to analyze this artifact.</label>
          <button disabled={busy||!file||!confirmed}>{busy?"Working…":"Upload and hash artifact"}</button>
        </form>
        <div className="item"><h2>2. Choose target</h2>
          <select value={targetId} onChange={e=>setTargetId(e.target.value)}><option value="">Select uploaded target</option>
            {targets.map(t=><option key={t.id} value={t.id}>{t.displayName} · {t.originalFilename}</option>)}
          </select>
          {targets.find(t=>t.id===targetId)&&<pre>{`SHA-256: ${targets.find(t=>t.id===targetId)?.sha256}\nSize: ${bytes(targets.find(t=>t.id===targetId)?.sizeBytes||0)}`}</pre>}
        </div>
        <div className="item stack">
          <div><h2>3. Select engines</h2><p className="muted">Leave all unchecked to use the default engine profile.</p></div>
          <div className="engines">{compatible.map(e=><label className="engine" key={e.engineId}>
            <input type="checkbox" checked={chosen.includes(e.engineId)} onChange={event=>setChosen(old=>event.target.checked?[...old,e.engineId]:old.filter(x=>x!==e.engineId))}/>
            <span>{e.name}<br/><span className="muted">v{e.version}</span></span>
          </label>)}</div>
          <button disabled={busy||!targetId} onClick={startRun}>Start independent analysis jobs</button>
          <p className="notice">Static analysis only. AAB/APKS are handled by bundletool in this phase; web capture and dynamic analysis are later phases.</p>
        </div>
      </section>
      <section className="panel">
        <div className="row" style={{justifyContent:"space-between"}}><div><h2>Analysis runs</h2><p className="muted">Each engine has separate raw output, logs and metadata.</p></div>
          <button onClick={()=>loadRuns(targetId).catch(e=>setError(e.message))}>Reload</button></div>
        {!runs.length&&<p className="muted">No runs for this target yet.</p>}
        {runs.map(run=><div className="item" key={run.id}>
          <div className="row"><strong>{run.id.slice(0,8)}</strong><span className="pill">{run.status}</span></div>
          <p className="muted">{new Date(run.createdAt).toLocaleString()} · {run.executions.length} engines</p>
          {run.executions.map(x=><div className="item" key={x.id}><div className="row"><strong>{x.engineId}</strong><span className="pill">{x.status}</span></div>
            <p className="muted">{x.toolVersion||"Waiting"} · {x.durationMs??"—"} ms · {x.outputBytes?bytes(x.outputBytes):"—"}</p>
            {x.errorSummary&&<p className="error">{x.errorSummary}</p>}
          </div>)}
          <a href={`${API}/runs/${run.id}/files`} target="_blank" rel="noreferrer" className="muted">Open file inventory API</a>
        </div>)}
      </section>
    </div>
    <p className="muted" style={{marginTop:22}}>ReverseLens examines client artifacts. It does not recover server-side source code. Decompiled output is reconstructed, not guaranteed to match original source.</p>
  </main>;
}
