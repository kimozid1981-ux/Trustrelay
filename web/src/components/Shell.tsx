"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, type ReactNode } from "react";
import { useSession } from "@/lib/session";

/** Authenticated layout: redirects to /login when signed out and to /onboarding until it is completed. */
export function Shell({ children, staffOnly = false }: { children: ReactNode; staffOnly?: boolean }) {
  const { me, ready, t, signOut } = useSession();
  const path = usePathname();
  const router = useRouter();

  useEffect(() => {
    if (!ready) return;
    if (!me) router.replace(`/login?next=${encodeURIComponent(path)}`);
    else if (!me.onboarding_completed && path !== "/onboarding") router.replace("/onboarding");
    else if (staffOnly && me.role === "user") router.replace("/");
  }, [ready, me, path, router, staffOnly]);

  if (!ready || !me) return <main aria-busy="true"><p>{t.common.loading}</p></main>;

  const links: [string, string][] = [
    ["/", t.nav.home],
    ["/history", t.nav.history],
    ["/family", t.nav.family],
    ["/guidance", t.nav.guidance],
    ["/settings", t.nav.settings],
  ];
  if (me.role !== "user") links.push(["/admin", t.nav.admin]);

  return (
    <>
      <a className="skip" href="#content">Skip to content</a>
      <header className="top">
        <div className="inner">
          <Link href="/" className="logo">TrustRelay</Link>
          <nav className="main" aria-label="Main">
            {links.map(([href, label]) => (
              <Link key={href} href={href} aria-current={path === href ? "page" : undefined}>{label}</Link>
            ))}
            <button type="button" onClick={async () => { await signOut(); router.replace("/login"); }}>{t.nav.logout}</button>
          </nav>
        </div>
      </header>
      <main id="content">{children}</main>
    </>
  );
}

export function ErrorBox({ error }: { error: string | null }) {
  if (!error) return null;
  return <div className="alert error" role="alert">{error}</div>;
}
