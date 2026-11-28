"use client";

import { FormEvent, useCallback, useEffect, useMemo, useState } from "react";

type WebTarget = {
  id: string; displayName: string; url: string; authorizationBasis: string;
  authorizationExpiresAt: string; allowedHosts: string[]; allowedPathPrefixes: string[];
  allowedPorts: number[]; maxRequests: number; maxPages: number;
  maxSavedJavaScriptBytes: number; maxDurationSeconds: number; localLab: boolean;
  status: string; createdAt: string;
};
type Capture = {
  id: string; webTargetId: string; status: string; workspacePath: string;
  manifest: Record<string, unknown>; errorSummary?: string; createdAt: string;
  startedAt?: string; finishedAt?: string;
};
const API = process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8080/api/v1";

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(API + path, init);
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.message || "Request failed (" + response.status + ")");
  }
  return response.json();
}
function defaultExpiry() {
  const value = new Date(Date.now() + 24 * 60 * 60 * 1000);
  value.setMinutes(value.getMinutes() - value.getTimezoneOffset());
  return value.toISOString().slice(0, 16);
}

export default function WebCapturePage() {
  const [targets, setTargets] = useState<WebTarget[]>([]);
  const [selectedId, setSelectedId] = useState("");
  const [captures, setCaptures] = useState<Capture[]>([]);
  const [displayName, setDisplayName] = useState("");
  const [url, setUrl] = useState("");
  const [pathPrefix, setPathPrefix] = useState("/");
  const [basis, setBasis] = useState("owner_or_developer");
  const [authorizationReference, setAuthorizationReference] = useState("");
  const [expiresAt, setExpiresAt] = useState(defaultExpiry);
  const [confirmed, setConfirmed] = useState(false);
  const [localLab, setLocalLab] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  const selected = useMemo(() => targets.find((item) => item.id === selectedId), [targets, selectedId]);

  const refreshTargets = useCallback(async () => {
    const values = await api<WebTarget[]>("/web-targets");
    setTargets(values);
    if (!selectedId && values.length) setSelectedId(values[0].id);
  }, [selectedId]);

  const refreshCaptures = useCallback(async () => {
    if (!selectedId) { setCaptures([]); return; }
    setCaptures(await api<Capture[]>("/web-targets/" + selectedId + "/captures"));
  }, [selectedId]);

  useEffect(() => {
    refreshTargets().catch((reason) => setError(reason instanceof Error ? reason.message : "Could not load web targets"));
  }, [refreshTargets]);

  useEffect(() => {
    refreshCaptures().catch((reason) => setError(reason instanceof Error ? reason.message : "Could not load captures"));
    const handle = window.setInterval(() => { refreshCaptures().catch(() => undefined); }, 3000);
    return () => window.clearInterval(handle);
  }, [refreshCaptures]);

  async function registerTarget(event: FormEvent) {
    event.preventDefault(); setBusy(true); setError(""); setMessage("");
    try {
      const parsed = new URL(url.trim());
      if (!["http:", "https:"].includes(parsed.protocol)) throw new Error("Only HTTP and HTTPS URLs are supported.");
      if (parsed.username || parsed.password || parsed.search || parsed.hash) {
        throw new Error("Remove credentials, query strings and fragments from the target URL.");
      }
      const prefix = pathPrefix.trim() || "/";
      if (!prefix.startsWith("/")) throw new Error("Path prefix must begin with /.");
      const expiry = new Date(expiresAt);
      if (Number.isNaN(expiry.getTime()) || expiry <= new Date()) throw new Error("Authorization expiry must be in the future.");
      const port = parsed.port ? Number(parsed.port) : parsed.protocol === "https:" ? 443 : 80;
      const payload = {
        displayName: displayName.trim() || parsed.hostname, url: parsed.toString(),
        authorizationBasis: localLab ? "local_training_lab" : basis,
        authorizationReference: authorizationReference.trim(), authorizationConfirmed: confirmed,
        authorizationExpiresAt: expiry.toISOString(), allowedHosts: [parsed.hostname],
        allowedPathPrefixes: [prefix], allowedPorts: [port], maxRequests: 80, maxPages: 10,
        maxSavedJavaScriptBytes: 2_000_000, maxDurationSeconds: 120, localLab,
      };
      const created = await api<WebTarget>("/web-targets", {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload),
      });
      await refreshTargets(); setSelectedId(created.id); setMessage("Authorized web target registered. Capture has not started yet.");
      setConfirmed(false);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Target registration failed.");
    } finally { setBusy(false); }
  }

  async function startCapture() {
    if (!selected) return;
    setBusy(true); setError(""); setMessage("");
    try {
      const created = await api<Capture>("/web-targets/" + selected.id + "/captures", { method: "POST" });
      await refreshCaptures(); setMessage("Capture queued: " + created.id);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not queue web capture.");
    } finally { setBusy(false); }
  }

  return (
    <main>
      <header>
        <div>
          <div className="pill">Phase 3 · Web capture</div>
          <h1>ReverseLens Web Lab</h1>
          <p>Register a target with an explicit scope and authorization expiry, then collect passive browser evidence.</p>
        </div>
        <div className="row">
          <a className="muted" href="/">Android workbench</a>
          <button type="button" onClick={() => refreshTargets().then(refreshCaptures).catch((reason) => setError(String(reason)))}>Refresh</button>
        </div>
      </header>
      {message && <p className="success">{message}</p>}
      {error && <p className="error">{error}</p>}
      <div className="grid">
        <section className="panel stack">
          <div><h2>1. Register an authorized web target</h2><p className="muted">Exact hostname, path prefix and TCP port are recorded. Authorization expiry is mandatory.</p></div>
          <form className="stack" onSubmit={registerTarget}>
            <label>Display name<input value={displayName} onChange={(event) => setDisplayName(event.target.value)} placeholder="My local training app" /></label>
            <label>Target URL<input required type="url" value={url} onChange={(event) => setUrl(event.target.value)} placeholder="https://example.com/app" /></label>
            <label>Allowed path prefix<input required value={pathPrefix} onChange={(event) => setPathPrefix(event.target.value)} placeholder="/" /></label>
            <label>Authorization basis
              <select value={localLab ? "local_training_lab" : basis} disabled={localLab} onChange={(event) => setBasis(event.target.value)}>
                <option value="owner_or_developer">I own or develop this site</option>
                <option value="written_permission">Written permission</option>
                <option value="lawful_possession_or_access">Lawful access</option>
                <option value="local_training_lab">Local training lab</option>
              </select>
            </label>
            <label>Authorization reference / scope note<textarea required value={authorizationReference} onChange={(event) => setAuthorizationReference(event.target.value)} rows={3} placeholder="Ticket, written scope, lab name, or authorization record reference" /></label>
            <label>Authorization expires at<input required type="datetime-local" value={expiresAt} onChange={(event) => setExpiresAt(event.target.value)} /></label>
            <label className="engine"><input type="checkbox" checked={localLab} onChange={(event) => setLocalLab(event.target.checked)} />Developer-controlled local training lab (private/loopback exception).</label>
            <label className="engine"><input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} />I confirm I own this target or have explicit permission for this exact scope.</label>
            <button disabled={busy || !url.trim() || !authorizationReference.trim() || !confirmed}>{busy ? "Working…" : "Register authorized target"}</button>
          </form>
          <p className="notice">No login, cookies, credential import, CAPTCHA bypass or state-changing browser requests are supported.</p>
        </section>
        <section className="panel stack">
          <div><h2>2. Run and inspect captures</h2><p className="muted">Capture requests are limited by the stored authorization expiry and scope.</p></div>
          <label>Registered target
            <select value={selectedId} onChange={(event) => setSelectedId(event.target.value)}>
              <option value="">Select a registered web target</option>
              {targets.map((target) => <option key={target.id} value={target.id}>{target.displayName} · {target.url}</option>)}
            </select>
          </label>
          {selected && <div className="item">
            <strong>{selected.displayName}</strong>
            <pre>{[
              "URL: " + selected.url, "Allowed hosts: " + selected.allowedHosts.join(", "),
              "Allowed paths: " + selected.allowedPathPrefixes.join(", "),
              "Allowed ports: " + selected.allowedPorts.join(", "),
              "Expires: " + new Date(selected.authorizationExpiresAt).toLocaleString(),
              "Mode: " + (selected.localLab ? "Local lab" : "Public host policy"), "Status: " + selected.status,
            ].join("\n")}</pre>
            <button disabled={busy || selected.status !== "active" || new Date(selected.authorizationExpiresAt) <= new Date()} onClick={startCapture}>Queue Playwright capture</button>
          </div>}
          {!selected && <p className="muted">No web targets registered yet.</p>}
          <h2>Capture history</h2>
          {!captures.length && <p className="muted">No captures for this target yet.</p>}
          {captures.map((capture) => <div className="item" key={capture.id}>
            <div className="row"><strong>{capture.id.slice(0, 8)}</strong><span className="pill">{capture.status}</span></div>
            <p className="muted">{new Date(capture.createdAt).toLocaleString()} · {capture.workspacePath}</p>
            {capture.errorSummary && <p className="error">{capture.errorSummary}</p>}
            {capture.manifest && Object.keys(capture.manifest).length > 0 && <pre>{JSON.stringify({
              pages: capture.manifest.pages_captured, requests: capture.manifest.requests_observed,
              graphs: capture.manifest.graphs_created, warnings: capture.manifest.warnings,
            }, null, 2)}</pre>}
          </div>)}
        </section>
      </div>
      <p className="notice" style={{ marginTop: 18 }}>
        Docker Compose starts this worker only with the <code>web-capture</code> profile and keeps it on the internal backend network. It is intended for local lab services reachable on that network; public Internet egress is not enabled. A separately reviewed egress proxy/firewall is required before remote target capture is enabled.
      </p>
    </main>
  );
}
