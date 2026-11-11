"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { Shell } from "@/components/Shell";
import { api, type Analysis } from "@/lib/api";
import { useSession } from "@/lib/session";

export default function HistoryPage() {
  return <Shell><History /></Shell>;
}

function History() {
  const { t, locale } = useSession();
  const h = t.history;
  const [items, setItems] = useState<Analysis[]>([]);
  const [next, setNext] = useState<string | null>(null);
  const [kind, setKind] = useState("");
  const [loaded, setLoaded] = useState(false);

  async function load(before?: string) {
    const q = new URLSearchParams({ limit: "20" });
    if (before) q.set("before", before);
    if (kind) q.set("kind", kind);
    const r = await api<{ items: Analysis[]; next_before: string | null }>(`/analyses?${q}`);
    setItems((prev) => (before ? [...prev, ...r.items] : r.items));
    setNext(r.next_before);
    setLoaded(true);
  }

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [kind, locale]);

  const fmt = (iso: string) => new Date(iso).toLocaleString(locale === "fr" ? "fr-FR" : "en-GB");

  return (
    <div className="stack">
      <div className="row" style={{ justifyContent: "space-between" }}>
        <h1 style={{ margin: 0 }}>{h.title}</h1>
        <div className="row">
          <label htmlFor="kind" className="small" style={{ margin: 0 }}>{h.kind}</label>
          <select id="kind" style={{ width: "auto" }} value={kind} onChange={(e) => setKind(e.target.value)}>
            <option value="">—</option>
            {Object.entries(t.kinds).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
          </select>
          {items.length > 0 && (
            <button className="danger" onClick={async () => {
              if (window.confirm(h.confirmDeleteAll)) { await api("/analyses", { method: "DELETE" }); setItems([]); setNext(null); }
            }}>{h.deleteAll}</button>
          )}
        </div>
      </div>
      {loaded && items.length === 0 && <p className="muted">{h.empty}</p>}
      {items.length > 0 && (
        <div className="table-wrap card">
          <table>
            <thead><tr><th>{h.date}</th><th>{h.kind}</th><th>{h.result}</th><th>{h.note}</th><th /></tr></thead>
            <tbody>
              {items.map((a) => (
                <tr key={a.id}>
                  <td>{fmt(a.created_at)}<div className="small muted">{h.expires} {new Date(a.expires_at).toLocaleDateString(locale)}</div></td>
                  <td>{t.kinds[a.kind]}<div className="small muted" style={{ overflowWrap: "anywhere" }}>{a.label}</div></td>
                  <td><Link href={`/analysis/${a.id}`}>{a.verdict_title ?? a.status}</Link></td>
                  <td className="small">{a.note}</td>
                  <td><button className="secondary" aria-label={t.analysis.delete} onClick={async () => {
                    await api(`/analyses/${a.id}`, { method: "DELETE" });
                    setItems(items.filter((x) => x.id !== a.id));
                  }}>✕</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {next && <button className="secondary" onClick={() => load(next)}>{h.more}</button>}
    </div>
  );
}
