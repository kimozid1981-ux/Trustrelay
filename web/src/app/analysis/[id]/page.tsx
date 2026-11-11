"use client";

import { useParams, useRouter } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import { AnalysisView } from "@/components/AnalysisView";
import { ErrorBox, Shell } from "@/components/Shell";
import { api, ApiError, type Analysis } from "@/lib/api";
import { useSession } from "@/lib/session";

export default function AnalysisPage() {
  return <Shell><Detail /></Shell>;
}

function Detail() {
  const { id } = useParams<{ id: string }>();
  const { t, locale } = useSession();
  const router = useRouter();
  const [a, setA] = useState<Analysis | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState("");
  const [shareOpen, setShareOpen] = useState(false);
  const [shareConfirm, setShareConfirm] = useState(false);
  const [shareMsg, setShareMsg] = useState("");
  const [notice, setNotice] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const res = await api<Analysis>(`/analyses/${id}`);
      setA(res);
      setNote(res.note ?? "");
      return res;
    } catch (err) {
      setError(err instanceof ApiError ? err.problem.detail : t.common.error);
      return null;
    }
  }, [id, t]);

  useEffect(() => {
    let timer: ReturnType<typeof setTimeout>;
    let tries = 0;
    const poll = async () => {
      const res = await load();
      if (res && (res.status === "queued" || res.status === "processing") && tries++ < 60) timer = setTimeout(poll, 1500);
    };
    poll();
    return () => clearTimeout(timer);
  }, [load, locale]);

  if (error) return <ErrorBox error={error} />;
  if (!a) return <p aria-busy="true">{t.common.loading}</p>;
  if (a.status !== "completed") {
    return <p role="status" aria-live="polite">{a.status === "failed" ? t.analysis.status.failed : t.analysis.status[a.status]}</p>;
  }

  return (
    <div className="stack">
      <h1>{t.kinds[a.kind]}{a.label ? ` — ${a.label}` : ""}</h1>
      {notice && <div className="alert info" role="status">{notice}</div>}
      <AnalysisView a={a} t={t} locale={locale} />

      <section className="card stack">
        <label htmlFor="note">{t.analysis.note}</label>
        <textarea id="note" style={{ minHeight: 80 }} maxLength={2000} value={note} onChange={(e) => setNote(e.target.value)} />
        <div className="row">
          <button className="secondary" onClick={async () => { await api(`/analyses/${a.id}/note`, { method: "PUT", body: { note: note || null } }); setNotice(t.settings.saved); }}>{t.analysis.saveNote}</button>
          <button className="secondary" onClick={() => setShareOpen(!shareOpen)}>{t.analysis.share}</button>
          <button className="danger" onClick={async () => { await api(`/analyses/${a.id}`, { method: "DELETE" }); router.replace("/history"); }}>{t.analysis.delete}</button>
        </div>
        {shareOpen && (
          <div className="stack">
            <div><label htmlFor="smsg">{t.analysis.shareMsg}</label><input id="smsg" type="text" maxLength={500} value={shareMsg} onChange={(e) => setShareMsg(e.target.value)} /></div>
            <label className="check"><input type="checkbox" checked={shareConfirm} onChange={(e) => setShareConfirm(e.target.checked)} /> {t.analysis.shareConfirm}</label>
            <button disabled={!shareConfirm} onClick={async () => {
              try {
                await api(`/analyses/${a.id}/share`, { method: "POST", body: { confirm: true, message: shareMsg || null } });
                setNotice(t.analysis.shared);
                setShareOpen(false);
              } catch (err) {
                setNotice(err instanceof ApiError ? err.problem.detail : t.common.error);
              }
            }}>{t.common.confirm}</button>
          </div>
        )}
      </section>
    </div>
  );
}
