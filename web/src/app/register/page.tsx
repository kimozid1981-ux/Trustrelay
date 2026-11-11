"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";
import { ErrorBox } from "@/components/Shell";
import { api, ApiError } from "@/lib/api";
import { useSession } from "@/lib/session";

export default function RegisterPage() {
  const { t, signIn, locale, setLocale } = useSession();
  const router = useRouter();
  const [form, setForm] = useState({ email: "", password: "", display_name: "", accept_terms: false });
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = await api<{ access_token: string }>("/auth/register", {
        method: "POST",
        body: { ...form, display_name: form.display_name || null, locale, client: "web" },
      });
      await signIn(res.access_token);
      router.replace("/onboarding");
    } catch (err) {
      setError(err instanceof ApiError ? err.problem.detail : t.common.error);
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="auth-box">
      <div className="row" style={{ justifyContent: "space-between" }}>
        <h1>TrustRelay</h1>
        <button type="button" className="secondary" onClick={() => setLocale(locale === "fr" ? "en" : "fr")}>{locale === "fr" ? "English" : "Français"}</button>
      </div>
      <form className="card stack" onSubmit={submit}>
        <h2 style={{ marginTop: 0 }}>{t.auth.register}</h2>
        <ErrorBox error={error} />
        <div><label htmlFor="email">{t.auth.email}</label><input id="email" type="email" autoComplete="email" required value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} /></div>
        <div>
          <label htmlFor="password">{t.auth.password}</label>
          <input id="password" type="password" autoComplete="new-password" minLength={10} required aria-describedby="pw-hint" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
          <p id="pw-hint" className="small muted">{t.auth.passwordHint}</p>
        </div>
        <div><label htmlFor="dn">{t.auth.displayName}</label><input id="dn" type="text" maxLength={80} value={form.display_name} onChange={(e) => setForm({ ...form, display_name: e.target.value })} /></div>
        <label className="check"><input type="checkbox" required checked={form.accept_terms} onChange={(e) => setForm({ ...form, accept_terms: e.target.checked })} /> {t.auth.acceptTerms}</label>
        <button type="submit" disabled={busy || !form.accept_terms}>{t.auth.register}</button>
        <p className="small">{t.auth.haveAccount} <Link href="/login">{t.auth.login}</Link></p>
      </form>
    </main>
  );
}
