"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { ErrorBox, Shell } from "@/components/Shell";
import { api, ApiError, setAccessToken } from "@/lib/api";
import { useSession } from "@/lib/session";
import type { Locale } from "@/i18n/messages";

type SessionRow = { id: string; client: string; user_agent: string | null; created_at: string; current: boolean };

export default function SettingsPage() {
  return <Shell><Settings /></Shell>;
}

function Settings() {
  const { t, me, reload, locale, setLocale } = useSession();
  const s = t.settings;
  const router = useRouter();
  const [msg, setMsg] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [sessions, setSessions] = useState<SessionRow[]>([]);
  const [pw, setPw] = useState({ current_password: "", new_password: "" });
  const [mfa, setMfa] = useState<{ secret: string; otpauth_uri: string } | null>(null);
  const [mfaCode, setMfaCode] = useState("");
  const [del, setDel] = useState({ password: "", confirm: "" });

  useEffect(() => { api<SessionRow[]>("/me/sessions").then(setSessions).catch(() => {}); }, []);
  if (!me) return null;
  const p = me.preferences;

  const run = async (fn: () => Promise<unknown>, ok = s.saved) => {
    setError(null); setMsg(null);
    try { await fn(); setMsg(ok); } catch (err) { setError(err instanceof ApiError ? err.problem.detail : t.common.error); }
  };
  const savePref = (patch: Record<string, unknown>) => run(async () => { await api("/me/preferences", { method: "PATCH", body: patch }); await reload(); });

  return (
    <div className="stack">
      <h1>{s.title}</h1>
      {msg && <div className="alert info" role="status">{msg}</div>}
      <ErrorBox error={error} />

      <section className="card stack">
        <h2 style={{ marginTop: 0 }}>{s.language}</h2>
        <select aria-label={s.language} value={locale} onChange={(e) => { const l = e.target.value as Locale; setLocale(l); run(() => api("/me", { method: "PATCH", body: { locale: l } })); }}>
          <option value="fr">Français</option><option value="en">English</option>
        </select>
      </section>

      <section className="card stack">
        <h2 style={{ marginTop: 0 }}>{s.privacy}</h2>
        <div><label htmlFor="ret">{s.retention}</label>
          <select id="ret" value={p.retention_days} onChange={(e) => savePref({ retention_days: Number(e.target.value) })}>
            {[0, 30, 90, 365].map((d) => <option key={d} value={d}>{s.retentionOpts[d]}</option>)}
          </select></div>
        <div><label htmlFor="lvl">{s.level}</label>
          <select id="lvl" value={p.explanation_level} onChange={(e) => savePref({ explanation_level: e.target.value })}>
            {Object.entries(s.levels).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
          </select></div>
        <label className="check"><input type="checkbox" checked={p.allow_ai_processing} onChange={(e) => savePref({ allow_ai_processing: e.target.checked })} /> {s.ai}</label>
        <label className="check"><input type="checkbox" checked={p.product_analytics_opt_in} onChange={(e) => savePref({ product_analytics_opt_in: e.target.checked })} /> {s.analytics}</label>
      </section>

      <section className="card stack">
        <h2 style={{ marginTop: 0 }}>{s.notifications}</h2>
        <label className="check"><input type="checkbox" checked={p.notify_analysis_complete} onChange={(e) => savePref({ notify_analysis_complete: e.target.checked })} /> {s.notifyDone}</label>
        <label className="check"><input type="checkbox" checked={p.notify_family_warnings} onChange={(e) => savePref({ notify_family_warnings: e.target.checked })} /> {s.notifyFamily}</label>
      </section>

      <section className="card stack">
        <h2 style={{ marginTop: 0 }}>{s.security}</h2>
        <form className="stack" onSubmit={(e) => { e.preventDefault(); run(async () => { await api("/auth/password", { method: "POST", body: pw }); setPw({ current_password: "", new_password: "" }); }); }}>
          <h3>{s.changePassword}</h3>
          <div><label htmlFor="cpw">{s.current}</label><input id="cpw" type="password" autoComplete="current-password" value={pw.current_password} onChange={(e) => setPw({ ...pw, current_password: e.target.value })} /></div>
          <div><label htmlFor="npw">{s.newPw}</label><input id="npw" type="password" autoComplete="new-password" value={pw.new_password} onChange={(e) => setPw({ ...pw, new_password: e.target.value })} /></div>
          <button type="submit" className="secondary">{s.changePassword}</button>
        </form>
        <div className="stack">
          <h3>{s.mfa}: {me.mfa_enabled ? s.mfaOn : s.mfaOff}</h3>
          {!me.mfa_enabled && !mfa && <button className="secondary" onClick={() => run(async () => setMfa(await api("/auth/mfa/setup", { method: "POST" })), "")}>{s.enableMfa}</button>}
          {mfa && (
            <form className="stack" onSubmit={(e) => { e.preventDefault(); run(async () => {
              const r = await api<{ access_token: string }>("/auth/mfa/enable", { method: "POST", body: { code: mfaCode } });
              setAccessToken(r.access_token); setMfa(null); await reload();
            }); }}>
              <p>{s.mfaScan}</p><code>{mfa.secret}</code>
              <input type="text" inputMode="numeric" aria-label="code" maxLength={6} value={mfaCode} onChange={(e) => setMfaCode(e.target.value)} />
              <button type="submit">{t.common.confirm}</button>
            </form>
          )}
        </div>
        <h3>{s.sessions}</h3>
        <ul>{sessions.map((x) => (
          <li key={x.id} className="row">{x.client} · {x.user_agent?.slice(0, 60) ?? "—"} · {new Date(x.created_at).toLocaleDateString(locale)}
            {!x.current && <button className="secondary" onClick={() => run(async () => { await api(`/me/sessions/${x.id}`, { method: "DELETE" }); setSessions(sessions.filter((y) => y.id !== x.id)); })}>{s.revoke}</button>}
          </li>
        ))}</ul>
      </section>

      <section className="card stack">
        <h2 style={{ marginTop: 0 }}>{s.subscription}</h2>
        <p>{s.plan}: <strong>{me.plan}</strong></p>
        <p className="small muted">{s.subscriptionNote}</p>
      </section>

      <section className="card stack">
        <h2 style={{ marginTop: 0 }}>{s.data}</h2>
        <button className="secondary" onClick={() => run(async () => {
          const res = await api<Response>("/me/export", { raw: true });
          const blob = await res.blob();
          const url = URL.createObjectURL(blob);
          const link = document.createElement("a");
          link.href = url; link.download = "trustrelay-export.json"; link.click();
          URL.revokeObjectURL(url);
        }, "")}>{s.export}</button>
        <form className="stack" onSubmit={(e) => { e.preventDefault(); run(async () => {
          await api("/me/delete", { method: "POST", body: del }); setAccessToken(null); router.replace("/register");
        }); }}>
          <h3>{s.deleteAccount}</h3>
          <p className="small">{s.deleteWarn}</p>
          <div><label htmlFor="dpw">{t.auth.password}</label><input id="dpw" type="password" autoComplete="current-password" value={del.password} onChange={(e) => setDel({ ...del, password: e.target.value })} /></div>
          <div><label htmlFor="dconf">{s.typeDelete}</label><input id="dconf" type="text" value={del.confirm} onChange={(e) => setDel({ ...del, confirm: e.target.value })} /></div>
          <button type="submit" className="danger" disabled={del.confirm !== "DELETE" || !del.password}>{s.deleteAccount}</button>
        </form>
      </section>
    </div>
  );
}
