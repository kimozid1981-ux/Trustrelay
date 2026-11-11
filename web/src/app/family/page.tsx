"use client";

import { useEffect, useState } from "react";
import { ErrorBox, Shell } from "@/components/Shell";
import { api, ApiError } from "@/lib/api";
import { useSession } from "@/lib/session";

type Member = { user_id: string; display_name: string; role: "owner" | "guardian" | "member"; age_band: "child" | "teen" | "adult" | "senior"; receive_warnings: boolean; can_share_warnings: boolean; is_me: boolean };
type Warning = { id: string; shared_by: string | null; kind: string; verdict: string; verdict_title: string; verdict_summary: string; signals: string[]; message: string | null; created_at: string };
type Family = { group: null | { id: string; name: string; my_role: string; members: Member[] }; warnings?: Warning[] };

export default function FamilyPage() {
  return <Shell><FamilyView /></Shell>;
}

function FamilyView() {
  const { t, locale } = useSession();
  const f = t.family;
  const [data, setData] = useState<Family | null>(null);
  const [name, setName] = useState("");
  const [code, setCode] = useState("");
  const [invite, setInvite] = useState<{ code: string; expires_at: string } | null>(null);
  const [inviteAge, setInviteAge] = useState<Member["age_band"]>("adult");
  const [error, setError] = useState<string | null>(null);

  const run = async (fn: () => Promise<unknown>) => {
    setError(null);
    try { await fn(); } catch (err) { setError(err instanceof ApiError ? err.problem.detail : t.common.error); }
  };
  const load = () => api<Family>("/family").then(setData);
  useEffect(() => { load(); }, [locale]); // eslint-disable-line react-hooks/exhaustive-deps

  if (!data) return <p>{t.common.loading}</p>;
  const g = data.group;
  const manage = g && (g.my_role === "owner" || g.my_role === "guardian");

  return (
    <div className="stack">
      <h1>{f.title}</h1>
      <p className="muted">{f.intro}</p>
      <ErrorBox error={error} />
      {!g && (
        <div className="grid">
          <form className="card stack" onSubmit={(e) => { e.preventDefault(); run(async () => setData(await api<Family>("/family", { method: "POST", body: { name } }))); }}>
            <h2 style={{ marginTop: 0 }}>{f.create}</h2>
            <div><label htmlFor="gname">{f.name}</label><input id="gname" type="text" required maxLength={80} value={name} onChange={(e) => setName(e.target.value)} /></div>
            <button type="submit">{f.create}</button>
          </form>
          <form className="card stack" onSubmit={(e) => { e.preventDefault(); run(async () => setData(await api<Family>("/family/join", { method: "POST", body: { code } }))); }}>
            <h2 style={{ marginTop: 0 }}>{f.join}</h2>
            <div><label htmlFor="code">{f.code}</label><input id="code" type="text" required value={code} onChange={(e) => setCode(e.target.value)} autoComplete="off" /></div>
            <button type="submit">{f.join}</button>
          </form>
        </div>
      )}
      {g && (
        <>
          <h2>{g.name} — {f.members}</h2>
          <div className="table-wrap card"><table>
            <thead><tr><th /><th>{locale === "fr" ? "Âge" : "Age"}</th><th>{f.receive}</th><th>{f.canShare}</th><th /></tr></thead>
            <tbody>{g.members.map((m) => (
              <tr key={m.user_id}>
                <td>{m.display_name}{m.is_me ? " ★" : ""}<div className="small muted">{f.role[m.role]} · {f.age[m.age_band]}</div></td>
                <td>
                  {manage && m.role !== "owner" ? (
                    <select aria-label={f.age.adult} value={m.age_band} onChange={(e) => run(async () => setData(await api<Family>(`/family/members/${m.user_id}`, { method: "PATCH", body: { age_band: e.target.value } })))}>
                      {(["child", "teen", "adult", "senior"] as const).map((a) => <option key={a} value={a}>{f.age[a]}</option>)}
                    </select>
                  ) : f.age[m.age_band]}
                </td>
                <td><input type="checkbox" aria-label={f.receive} checked={m.receive_warnings} disabled={!m.is_me && !manage}
                  onChange={(e) => run(async () => setData(await api<Family>(`/family/members/${m.user_id}`, { method: "PATCH", body: { receive_warnings: e.target.checked } })))} /></td>
                <td><input type="checkbox" aria-label={f.canShare} checked={m.can_share_warnings} disabled={!manage || m.role === "owner"}
                  onChange={(e) => run(async () => setData(await api<Family>(`/family/members/${m.user_id}`, { method: "PATCH", body: { can_share_warnings: e.target.checked } })))} /></td>
                <td>{(m.is_me || (manage && m.role !== "owner")) && (
                  <button className="secondary" onClick={() => run(async () => { await api(`/family/members/${m.user_id}`, { method: "DELETE" }); await load(); })}>{m.is_me ? f.leave : f.remove}</button>
                )}</td>
              </tr>
            ))}</tbody>
          </table></div>
          {manage && (
            <div className="card stack">
              <h2 style={{ marginTop: 0 }}>{f.invite}</h2>
              <div className="row">
                <select aria-label="age" style={{ width: "auto" }} value={inviteAge} onChange={(e) => setInviteAge(e.target.value as Member["age_band"])}>
                  {(["child", "teen", "adult", "senior"] as const).map((a) => <option key={a} value={a}>{f.age[a]}</option>)}
                </select>
                <button onClick={() => run(async () => setInvite(await api("/family/invites", { method: "POST", body: { role: "member", age_band: inviteAge } })))}>{f.invite}</button>
              </div>
              {invite && <p>{f.code}: <code style={{ fontSize: "1.2rem" }}>{invite.code}</code></p>}
            </div>
          )}
          <h2>{f.warnings}</h2>
          {(data.warnings ?? []).length === 0 ? <p className="muted">{f.noWarnings}</p> : (
            <div className="stack">{data.warnings!.map((w) => (
              <article key={w.id} className={`verdict v-${w.verdict}`}>
                <h3 style={{ margin: 0 }}>{w.verdict_title} — {t.kinds[w.kind]}</h3>
                <p className="small muted">{w.shared_by} · {new Date(w.created_at).toLocaleString(locale)}</p>
                {w.message && <p><strong>“{w.message}”</strong></p>}
                <p>{w.verdict_summary}</p>
                <ul className="small">{w.signals.map((s, i) => <li key={i}>{s}</li>)}</ul>
              </article>
            ))}</div>
          )}
        </>
      )}
    </div>
  );
}
