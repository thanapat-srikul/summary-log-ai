"use client";

import { FormEvent, useCallback, useEffect, useState } from "react";

type Entry = {
  id: string;
  source_name?: string;
  cidr?: string;
  port?: number;
  protocol?: string;
  description: string;
  expires_at?: string;
  state: "active" | "expired";
};
type Source = { id: string; name: string };

async function api(url: string, init?: RequestInit) {
  const response = await fetch(url, {
    ...init,
    headers: {
      ...(init?.body ? { "Content-Type": "application/json" } : {}),
      ...(init?.headers || {}),
    },
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error || "request_failed");
  return body;
}

export default function AllowlistManagement() {
  const [entries, setEntries] = useState<Entry[]>([]);
  const [sources, setSources] = useState<Source[]>([]);
  const [csrf, setCsrf] = useState("");
  const [role, setRole] = useState("viewer");
  const [q, setQ] = useState("");
  const [status, setStatus] = useState("all");
  const [notice, setNotice] = useState("");

  const load = useCallback(async () => {
    try {
      const params = new URLSearchParams({ q, status });
      const [auth, list, sourceData] = await Promise.all([
        api("/api/v1/auth/me"),
        api(`/api/v1/allowlist?${params}`),
        api("/api/v1/sources"),
      ]);
      setCsrf(auth.csrfToken);
      setRole(auth.user.role);
      setEntries(list.entries);
      setSources(sourceData.sources);
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "request_failed");
    }
  }, [q, status]);

  useEffect(() => {
    const timer = window.setTimeout(load, 150);
    return () => window.clearTimeout(timer);
  }, [load]);

  const canWrite = role !== "viewer";
  const mutate = async (url: string, method: string, body?: unknown) => {
    try {
      await api(url, {
        method,
        headers: { "x-csrf-token": csrf },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
      setNotice("Saved successfully");
      await load();
      return true;
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "request_failed");
      return false;
    }
  };

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const form = event.currentTarget;
    const values = Object.fromEntries(new FormData(form));
    const expiresAt = String(values.expiresAt || "");
    const body = {
      ...values,
      expiresAt: expiresAt ? new Date(expiresAt).toISOString() : "",
    };
    if (await mutate("/api/v1/allowlist", "POST", body)) form.reset();
  };

  return (
    <main className="incident-detail-page">
      <header className="incident-detail-top">
        <a href="/app">Back to Dashboard</a>
        <div><strong>Allowlist</strong><span className="status-chip">AND conditions</span></div>
      </header>
      <section className="incident-hero">
        <div>
          <p className="console-kicker">TRUST POLICY</p>
          <h1>Explainable exceptions</h1>
          <p>Fields in the same entry are matched together. An empty Source applies the entry to every Source.</p>
        </div>
      </section>
      {notice && <div className="action-notice success">{notice}</div>}
      {canWrite && (
        <section className="console-panel detail-section">
          <h2>Add Allowlist entry</h2>
          <form className="incident-list-filters" onSubmit={submit}>
            <label>Source<select name="sourceId"><option value="">All Sources</option>{sources.map(source => <option key={source.id} value={source.id}>{source.name}</option>)}</select></label>
            <label>IP / CIDR<input name="cidr" placeholder="192.168.1.10 or 192.168.1.0/24" /></label>
            <label>Port<input name="port" type="number" min="1" max="65535" /></label>
            <label>Protocol<select name="protocol"><option value="">All</option><option>tcp</option><option>udp</option><option>icmp</option></select></label>
            <label>Expires<input name="expiresAt" type="datetime-local" /></label>
            <label>Description<input name="description" required placeholder="Reason for this exception" /></label>
            <button className="primary-action">Add Allowlist</button>
          </form>
        </section>
      )}
      <section className="console-panel detail-section">
        <div className="incident-list-filters allowlist-tools">
          <label>Search<input value={q} onChange={event => setQ(event.target.value)} placeholder="CIDR, Source or description" /></label>
          <label>Status<select value={status} onChange={event => setStatus(event.target.value)}><option value="all">All</option><option value="active">Active</option><option value="expired">Expired</option></select></label>
        </div>
        <div className="table-wrap"><table><thead><tr><th>Status</th><th>Source</th><th>IP / CIDR</th><th>Port</th><th>Protocol</th><th>Expires</th><th>Description</th><th /></tr></thead><tbody>
          {entries.map(entry => <tr key={entry.id}><td><span className={`status-chip allow-${entry.state}`}>{entry.state}</span></td><td>{entry.source_name || "All Sources"}</td><td>{entry.cidr || "—"}</td><td>{entry.port || "—"}</td><td>{entry.protocol || "All"}</td><td>{entry.expires_at ? new Date(entry.expires_at).toLocaleString("th-TH") : "Never"}</td><td>{entry.description}</td><td>{canWrite && <button className="danger-link" onClick={() => window.confirm("Delete this Allowlist entry?") && mutate(`/api/v1/allowlist/${entry.id}`, "DELETE")}>Delete</button>}</td></tr>)}
        </tbody></table>{!entries.length && <div className="empty-state">No Allowlist entries found</div>}</div>
      </section>
    </main>
  );
}
