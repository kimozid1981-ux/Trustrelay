"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { Shell } from "@/components/Shell";
import { api } from "@/lib/api";
import { useSession } from "@/lib/session";
import type { Locale } from "@/i18n/messages";

export default function Onboarding() {
  return <Shell><Steps /></Shell>;
}

function Steps() {
  const { t, locale, setLocale, reload, me } = useSession();
  const router = useRouter();
  const [step, setStep] = useState(0);
  const [retention, setRetention] = useState(me?.preferences.retention_days ?? 90);
  const [allowAi, setAllowAi] = useState(me?.preferences.allow_ai_processing ?? true);
  const o = t.onboarding;

  async function finish() {
    await api("/me/preferences", { method: "PATCH", body: { retention_days: retention, allow_ai_processing: allowAi } });
    await api("/me", { method: "PATCH", body: { locale, onboarding_completed: true } });
    await reload();
    router.replace("/");
  }

  const steps = [
    <div key="0" className="stack">
      <h2>{o.s1t}</h2><p>{o.s1}</p>
      <div><label htmlFor="lang">{o.language}</label>
        <select id="lang" value={locale} onChange={(e) => setLocale(e.target.value as Locale)}>
          <option value="fr">Français</option><option value="en">English</option>
        </select></div>
    </div>,
    <div key="1" className="stack"><h2>{o.s2t}</h2><p>{o.s2}</p></div>,
    <div key="2" className="stack">
      <h2>{o.s3t}</h2><p>{o.s3}</p>
      <div><label htmlFor="ret">{o.retention}</label>
        <select id="ret" value={retention} onChange={(e) => setRetention(Number(e.target.value))}>
          {[0, 30, 90, 365].map((d) => <option key={d} value={d}>{t.settings.retentionOpts[d]}</option>)}
        </select></div>
      <label className="check"><input type="checkbox" checked={allowAi} onChange={(e) => setAllowAi(e.target.checked)} /> {o.s3ai}</label>
    </div>,
    <div key="3" className="stack"><h2>{o.s4t}</h2><ul>{o.s4.map((x) => <li key={x}>{x}</li>)}</ul></div>,
  ];

  return (
    <div className="card stack" style={{ maxWidth: 640, margin: "0 auto" }}>
      <h1>{o.title}</h1>
      <p className="small muted" aria-live="polite">{step + 1} / {steps.length}</p>
      {steps[step]}
      <div className="row">
        {step > 0 && <button className="secondary" onClick={() => setStep(step - 1)}>{o.back}</button>}
        {step < steps.length - 1 ? <button onClick={() => setStep(step + 1)}>{o.next}</button> : <button onClick={finish}>{o.finish}</button>}
      </div>
    </div>
  );
}
