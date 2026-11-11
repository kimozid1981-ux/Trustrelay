"use client";

import type { Analysis } from "@/lib/api";
import type { Messages } from "@/i18n/messages";

export function AnalysisView({ a, t, locale }: { a: Analysis; t: Messages; locale: string }) {
  const s = t.analysis;
  const fmt = (iso: string) => new Date(iso).toLocaleString(locale === "fr" ? "fr-FR" : "en-GB");
  const findings = a.findings ?? [];
  const warnings = findings.filter((f) => f.severity !== "info");
  const context = findings.filter((f) => f.severity === "info");

  return (
    <div className="stack">
      <section className={`verdict v-${a.verdict}`} aria-labelledby="verdict-title">
        <h2 id="verdict-title">{a.verdict_title}</h2>
        <p style={{ margin: 0 }}>{a.verdict_summary}</p>
        <p className="small" style={{ marginBottom: 0 }}><strong>{a.confidence_label}</strong></p>
      </section>

      <section className="card">
        <h2 style={{ marginTop: 0 }}>{s.action}</h2>
        <p>{a.recommended_action?.text}</p>
        {(a.verdict === "known_malicious" || a.verdict === "strong_suspicious") && (
          <a href="/guidance#already-acted">{s.alreadyActed}</a>
        )}
      </section>

      <div className="grid">
        <div className="card"><div className="small muted">{s.organisation}</div><div>{a.identified_organisations?.join(", ") || s.none}</div></div>
        <div className="card"><div className="small muted">{s.domain}</div><div style={{ overflowWrap: "anywhere" }}>{a.identified_domains?.join(", ") || s.none}</div></div>
      </div>

      <section>
        <h2>{s.signals}</h2>
        {warnings.length === 0 && <p className="muted">{s.none}</p>}
        <div className="stack">{[...warnings, ...context].map((f, i) => (
          <article key={`${f.code}-${i}`} className={`finding f-${f.severity}`}>
            <div className="row">
              <span className={`pill sev-${f.severity}`}>{f.confidence_label}</span>
              {f.ai_generated && <span className="pill" title="AI">{s.aiBadge}</span>}
            </div>
            <h3>{f.title}</h3>
            <p style={{ margin: 0 }}>{f.explanation}</p>
            <dl>
              {f.evidence.length > 0 && (<><dt>{s.evidence}</dt><dd>{f.evidence.map((e, j) => <span key={j} className="evidence">{e}</span>).reduce<React.ReactNode[]>((acc, el, j) => (j ? [...acc, " · ", el] : [el]), [])}</dd></>)}
              <dt>{s.source}</dt><dd>{f.source_name}</dd>
              <dt>{s.checkedAt}</dt><dd>{fmt(f.checked_at)}</dd>
              <dt>{s.limitation}</dt><dd>{f.limitation}</dd>
            </dl>
          </article>
        ))}</div>
      </section>

      {(a.missing_information?.length ?? 0) > 0 && (
        <section className="card">
          <h2 style={{ marginTop: 0 }}>{s.missing}</h2>
          <ul>{a.missing_information!.map((m) => <li key={m.code}>{m.text}</li>)}</ul>
        </section>
      )}

      <details className="card">
        <summary>{s.sources}</summary>
        <ul className="small">{a.sources_checked?.map((src, i) => <li key={i}>{src.source} — {src.ok ? s.ok : s.failed}</li>)}</ul>
      </details>

      <p className="small muted">{a.disclaimer}</p>
    </div>
  );
}
