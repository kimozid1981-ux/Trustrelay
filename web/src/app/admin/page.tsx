"use client";

import { useEffect, useState } from "react";
import { ErrorBox, Shell } from "@/components/Shell";
import { api, ApiError } from "@/lib/api";
import { useSession } from "@/lib/session";

// Administration console. By design it shows accounts, aggregates, health and configuration —
// never the content of customer analyses (the API does not expose it to admins).

type Tab = "overview" | "users" | "sources" | "ai" | "errors" | "security" | "flags" | "config" | "support";

export default function AdminPage() {
  return <Shell staffOnly><Admin /></Shell>;
}

function Admin() {
  const { me, locale } = useSession();
  const fr = locale === "fr";
  const isAdmin = me?.role === "admin";
  const tabs: [Tab, string][] = (
    [
      ["overview", fr ? "Vue d'ensemble" : "Overview"],
      ["users", fr ? "Utilisateurs" : "Users"],
      ["sources", fr ? "Sources de menaces" : "Threat sources"],
      ["ai", fr ? "IA et coûts" : "AI & costs"],
      ["errors", fr ? "Erreurs" : "Errors"],
      ["security", fr ? "Sécurité et abus" : "Security & abuse"],
      ["flags", fr ? "Fonctionnalités" : "Feature flags"],
      ["config", fr ? "Configuration" : "Configuration"],
      ["support", "Support"],
    ] as [Tab, string][]
  ).filter(([k]) => (me?.role === "support" ? k === "support" : me?.role === "security" ? ["overview", "sources", "errors", "security"].includes(k) : true));
  const [tab, setTab] = useState<Tab>(tabs[0][0]);

  if (!me?.mfa_enabled) {
    return <div className="alert info">{fr ? "Activez la double authentification dans Réglages pour accéder à l'administration, puis reconnectez-vous." : "Turn on two-factor authentication in Settings, then sign in again, to use the admin console."}</div>;
  }
  return (
    <div className="stack">
      <h1>{fr ? "Administration" : "Administration"}</h1>
      <p className="small muted">{fr ? "Les administrateurs n'ont pas accès au contenu des analyses des utilisateurs." : "Administrators have no access to the content of users' analyses."}</p>
      <div className="tabs" role="tablist">{tabs.map(([k, label]) => <button key={k} role="tab" aria-selected={tab === k} onClick={() => setTab(k)}>{label}</button>)}</div>
      {tab === "overview" && <Json path="/admin/stats" />}
      {tab === "users" && isAdmin && <Users />}
      {tab === "sources" && <Table path="/admin/threat-sources" />}
      {tab === "ai" && <Json path="/admin/ai-usage" />}
      {tab === "errors" && <Json path="/admin/errors" />}
      {tab === "security" && <><Json path="/admin/abuse" /><h2>{fr ? "Événements de sécurité" : "Security events"}</h2><Table path="/admin/security-events?limit=50" /></>}
      {tab === "flags" && isAdmin && <Flags />}
      {tab === "config" && isAdmin && <Json path="/admin/config" />}
      {tab === "support" && <Tickets />}
    </div>
  );
}

function useLoad<T>(path: string): [T | null, string | null, () => void] {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const load = () => api<T>(path).then(setData).catch((e) => setError(e instanceof ApiError ? e.problem.detail : "error"));
  useEffect(() => { load(); }, [path]); // eslint-disable-line react-hooks/exhaustive-deps
  return [data, error, load];
}

function Json({ path }: { path: string }) {
  const [data, error] = useLoad<Record<string, unknown>>(path);
  if (error) return <ErrorBox error={error} />;
  if (!data) return <p>…</p>;
  return (
    <div className="grid">
      {Object.entries(data).map(([k, v]) => (
        <div key={k} className="card">
          <div className="small muted">{k.replaceAll("_", " ")}</div>
          {typeof v === "object" && v !== null ? <pre className="small" style={{ whiteSpace: "pre-wrap", margin: 0 }}>{JSON.stringify(v, null, 1)}</pre> : <div style={{ fontSize: "1.4rem", fontWeight: 700 }}>{String(v ?? "—")}</div>}
        </div>
      ))}
    </div>
  );
}

function Table({ path }: { path: string }) {
  const [rows, error] = useLoad<Record<string, unknown>[]>(path);
  if (error) return <ErrorBox error={error} />;
  if (!rows) return <p>…</p>;
  if (rows.length === 0) return <p className="muted">—</p>;
  const cols = Object.keys(rows[0]);
  return (
    <div className="table-wrap card"><table>
      <thead><tr>{cols.map((c) => <th key={c}>{c}</th>)}</tr></thead>
      <tbody>{rows.map((r, i) => <tr key={i}>{cols.map((c) => <td key={c} className="small">{typeof r[c] === "object" ? JSON.stringify(r[c]) : String(r[c] ?? "")}</td>)}</tr>)}</tbody>
    </table></div>
  );
}

type UserRow = { id: string; email: string; role: string; is_active: boolean; plan: string; mfa_enabled: boolean; created_at: string; last_login_at: string | null };

function Users() {
  const [q, setQ] = useState("");
  const [rows, setRows] = useState<UserRow[]>([]);
  const [error, setError] = useState<string | null>(null);
  const load = () => api<{ items: UserRow[] }>(`/admin/users?q=${encodeURIComponent(q)}`).then((r) => setRows(r.items)).catch((e) => setError(e.problem?.detail ?? "error"));
  useEffect(() => { load(); }, []); // eslint-disable-line react-hooks/exhaustive-deps
  const act = async (fn: () => Promise<unknown>) => { setError(null); try { await fn(); await load(); } catch (e) { setError(e instanceof ApiError ? e.problem.detail : "error"); } };
  return (
    <div className="stack">
      <form className="row" onSubmit={(e) => { e.preventDefault(); load(); }}>
        <input type="text" aria-label="search" placeholder="email…" value={q} onChange={(e) => setQ(e.target.value)} style={{ maxWidth: 320 }} />
        <button type="submit" className="secondary">OK</button>
      </form>
      <ErrorBox error={error} />
      <div className="table-wrap card"><table>
        <thead><tr><th>email</th><th>role</th><th>plan</th><th>MFA</th><th>active</th><th>last login</th></tr></thead>
        <tbody>{rows.map((u) => (
          <tr key={u.id}>
            <td>{u.email}</td>
            <td><select aria-label="role" value={u.role} onChange={(e) => act(() => api(`/admin/users/${u.id}`, { method: "PATCH", body: { role: e.target.value } }))}>
              {["user", "support", "security", "admin"].map((r) => <option key={r}>{r}</option>)}</select></td>
            <td><select aria-label="plan" value={u.plan} onChange={(e) => act(() => api(`/admin/users/${u.id}/subscription`, { method: "PUT", body: { plan: e.target.value } }))}>
              {["free", "plus", "family", "business", "enterprise"].map((p) => <option key={p}>{p}</option>)}</select></td>
            <td>{u.mfa_enabled ? "✓" : "—"}</td>
            <td><input type="checkbox" aria-label="active" checked={u.is_active} onChange={(e) => act(() => api(`/admin/users/${u.id}`, { method: "PATCH", body: { is_active: e.target.checked } }))} /></td>
            <td className="small">{u.last_login_at?.slice(0, 16) ?? "—"}</td>
          </tr>
        ))}</tbody>
      </table></div>
    </div>
  );
}

function Flags() {
  const [flags, error, reload] = useLoad<{ key: string; enabled: boolean; description: string }[]>("/admin/feature-flags");
  if (error) return <ErrorBox error={error} />;
  return (
    <div className="stack">{flags?.map((f) => (
      <label key={f.key} className="check card"><input type="checkbox" checked={f.enabled} onChange={async (e) => { await api(`/admin/feature-flags/${f.key}`, { method: "PUT", body: { enabled: e.target.checked } }); reload(); }} />
        <span><code>{f.key}</code><br /><span className="small muted">{f.description}</span></span></label>
    ))}</div>
  );
}

type Ticket = { id: string; category: string; priority: string; status: string; created_at: string; subject?: string; body?: string; access_grants?: { id: string; analysis_id: string; expires_at: string }[] };

function Tickets() {
  const [rows, error, reload] = useLoad<Ticket[]>("/staff/tickets");
  const [open, setOpen] = useState<Ticket | null>(null);
  if (error) return <ErrorBox error={error} />;
  return (
    <div className="stack">
      <div className="table-wrap card"><table>
        <thead><tr><th>created</th><th>category</th><th>priority</th><th>status</th><th /></tr></thead>
        <tbody>{rows?.map((t) => (
          <tr key={t.id}><td className="small">{t.created_at.slice(0, 16)}</td><td>{t.category}</td><td>{t.priority}</td>
            <td><select aria-label="status" value={t.status} onChange={async (e) => { await api(`/staff/tickets/${t.id}`, { method: "PATCH", body: { status: e.target.value } }); reload(); }}>
              {["open", "pending", "resolved", "closed"].map((s) => <option key={s}>{s}</option>)}</select></td>
            <td><button className="secondary" onClick={async () => setOpen(await api<Ticket>(`/staff/tickets/${t.id}`))}>Open</button></td></tr>
        ))}</tbody>
      </table></div>
      {open && (
        <div className="card stack">
          <h3 style={{ marginTop: 0 }}>{open.subject}</h3>
          <p style={{ whiteSpace: "pre-wrap" }}>{open.body}</p>
          <p className="small muted">Customer-granted analysis access: {open.access_grants?.length ? open.access_grants.map((g) => g.analysis_id).join(", ") : "none"}</p>
        </div>
      )}
    </div>
  );
}
