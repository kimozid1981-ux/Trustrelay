"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useRef, useState, type FormEvent } from "react";
import { ErrorBox, Shell } from "@/components/Shell";
import { api, ApiError, type Analysis } from "@/lib/api";
import { useSession } from "@/lib/session";

type Kind = "url" | "message" | "image" | "qr" | "advert" | "payment";
const KINDS: Kind[] = ["url", "message", "image", "qr", "advert", "payment"];

export default function Dashboard() {
  return <Shell><Scan /></Shell>;
}

function Scan() {
  const { t } = useSession();
  const d = t.dashboard;
  const router = useRouter();
  const [kind, setKind] = useState<Kind>("url");
  const [text, setText] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [recent, setRecent] = useState<Analysis[]>([]);
  const [usage, setUsage] = useState<{ checks_used: number; checks_limit: number | null } | null>(null);

  useEffect(() => {
    api<{ items: Analysis[] }>("/analyses?limit=5").then((r) => setRecent(r.items)).catch(() => {});
    api<{ checks_used: number; checks_limit: number | null }>("/usage").then(setUsage).catch(() => {});
  }, []);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      let upload_id: string | undefined;
      if (file && (kind === "image" || kind === "qr")) {
        const form = new FormData();
        form.append("file", file);
        upload_id = (await api<{ id: string }>("/uploads", { method: "POST", form })).id;
      }
      const res = await api<Analysis>("/analyses", {
        method: "POST",
        body: { kind, text: kind === "image" ? undefined : text || undefined, upload_id },
      });
      router.push(`/analysis/${res.id}`);
    } catch (err) {
      setError(err instanceof ApiError ? err.problem.detail : t.common.error);
      setBusy(false);
    }
  }

  const placeholder = { url: d.urlPh, message: d.messagePh, advert: d.advertPh, payment: d.paymentPh, qr: d.qrPh, image: "" }[kind];
  const canSubmit = kind === "image" ? !!file : kind === "qr" ? !!file || !!text.trim() : !!text.trim();

  return (
    <div className="stack">
      <h1>{d.title}</h1>
      <p className="muted">{t.tagline}</p>
      <form className="card stack" onSubmit={submit}>
        <div className="tabs" role="tablist" aria-label={d.title}>
          {KINDS.map((k) => (
            <button key={k} type="button" role="tab" aria-selected={kind === k} onClick={() => { setKind(k); setFile(null); setError(null); }}>
              {d.tabs[k]}
            </button>
          ))}
        </div>
        <ErrorBox error={error} />
        {kind === "url" && (
          <div><label htmlFor="in">{d.tabs.url}</label><input id="in" type="url" inputMode="url" placeholder={placeholder} value={text} onChange={(e) => setText(e.target.value)} maxLength={4000} /></div>
        )}
        {(kind === "message" || kind === "advert" || kind === "payment") && (
          <div><label htmlFor="in">{d.tabs[kind]}</label><textarea id="in" placeholder={placeholder} value={text} onChange={(e) => setText(e.target.value)} maxLength={20000} /></div>
        )}
        {kind === "qr" && (
          <>
            <div><label htmlFor="in">{d.tabs.qr}</label><input id="in" type="text" placeholder={placeholder} value={text} onChange={(e) => setText(e.target.value)} /></div>
            <QrCamera onResult={(v) => setText(v)} />
          </>
        )}
        {(kind === "image" || kind === "qr") && (
          <div>
            <label htmlFor="file">{kind === "image" ? d.imageUpload : d.qrUpload}</label>
            <input id="file" type="file" accept="image/png,image/jpeg,image/webp" onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
          </div>
        )}
        <p className="small muted">{d.neverShare}</p>
        <div className="row">
          <button type="submit" disabled={busy || !canSubmit}>{busy ? d.analysing : d.submit}</button>
          {usage && <span className="small muted">{d.quota(usage.checks_used, usage.checks_limit)}</span>}
        </div>
      </form>

      <h2>{d.recent}</h2>
      {recent.length === 0 ? <p className="muted">{t.history.empty}</p> : (
        <ul className="stack" style={{ listStyle: "none", padding: 0 }}>
          {recent.map((a) => (
            <li key={a.id} className="card row" style={{ justifyContent: "space-between" }}>
              <span><span className="pill">{t.kinds[a.kind]}</span> {a.label ?? ""}</span>
              <Link href={`/analysis/${a.id}`}>{a.verdict_title ?? a.status}</Link>
            </li>
          ))}
        </ul>
      )}
      <Link href="/history">{d.seeAll}</Link>
    </div>
  );
}

/** Camera QR scanning using the browser's BarcodeDetector when available; decoded text stays on the device. */
function QrCamera({ onResult }: { onResult: (v: string) => void }) {
  const { t } = useSession();
  const video = useRef<HTMLVideoElement>(null);
  const [on, setOn] = useState(false);
  const supported = typeof window !== "undefined" && "BarcodeDetector" in window && !!navigator.mediaDevices;

  useEffect(() => {
    if (!on || !video.current) return;
    let stream: MediaStream | null = null;
    let raf = 0;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const detector = new (window as any).BarcodeDetector({ formats: ["qr_code"] });
    (async () => {
      stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" } });
      video.current!.srcObject = stream;
      await video.current!.play();
      const tick = async () => {
        const codes = await detector.detect(video.current!).catch(() => []);
        if (codes.length) {
          onResult(codes[0].rawValue);
          setOn(false);
          return;
        }
        raf = requestAnimationFrame(tick);
      };
      tick();
    })().catch(() => setOn(false));
    return () => {
      cancelAnimationFrame(raf);
      stream?.getTracks().forEach((tr) => tr.stop());
    };
  }, [on, onResult]);

  if (!supported) return null;
  return (
    <div className="stack">
      <button type="button" className="secondary" onClick={() => setOn(!on)}>{on ? t.dashboard.stopCamera : t.dashboard.camera}</button>
      {on && <video ref={video} muted playsInline style={{ width: "100%", maxWidth: 360, borderRadius: 8 }} />}
    </div>
  );
}
