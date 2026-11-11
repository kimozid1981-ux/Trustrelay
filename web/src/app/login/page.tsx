"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useState, type FormEvent } from "react";
import { ErrorBox } from "@/components/Shell";
import { api, ApiError } from "@/lib/api";
import { useSession } from "@/lib/session";

function LoginForm() {
  const { t, signIn, locale, setLocale } = useSession();
  const router = useRouter();
  const params = useSearchParams();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const [needTotp, setNeedTotp] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = await api<{ access_token: string }>("/auth/login", {
        method: "POST",
        body: { email, password, client: "web", totp_code: totp || undefined },
      });
      await signIn(res.access_token);
      const next = params.get("next");
      router.replace(next && next.startsWith("/") && !next.startsWith("//") ? next : "/");
    } catch (err) {
      if (err instanceof ApiError && err.problem.code === "mfa_code_required") setNeedTotp(true);
      else setError(err instanceof ApiError ? err.problem.detail : t.common.error);
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
      <p className="muted">{t.tagline}</p>
      <form className="card stack" onSubmit={submit} noValidate>
        <h2 style={{ marginTop: 0 }}>{t.auth.login}</h2>
        <ErrorBox error={error} />
        <div><label htmlFor="email">{t.auth.email}</label><input id="email" type="email" autoComplete="email" required value={email} onChange={(e) => setEmail(e.target.value)} /></div>
        <div><label htmlFor="password">{t.auth.password}</label><input id="password" type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} /></div>
        {needTotp && (
          <div><label htmlFor="totp">{t.auth.totp}</label><input id="totp" type="text" inputMode="numeric" autoComplete="one-time-code" maxLength={6} value={totp} onChange={(e) => setTotp(e.target.value)} autoFocus /></div>
        )}
        <button type="submit" disabled={busy}>{t.auth.login}</button>
        <p className="small">{t.auth.noAccount} <Link href="/register">{t.auth.register}</Link></p>
      </form>
    </main>
  );
}

export default function LoginPage() {
  return <Suspense><LoginForm /></Suspense>;
}
