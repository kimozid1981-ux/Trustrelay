"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { api, setAccessToken, setApiLocale, tryRestoreSession, type Me } from "./api";
import { dictionaries, type Locale, type Messages } from "@/i18n/messages";

type Session = {
  me: Me | null;
  ready: boolean;
  locale: Locale;
  t: Messages;
  setLocale: (l: Locale) => void;
  reload: () => Promise<Me | null>;
  signIn: (accessToken: string) => Promise<Me | null>;
  signOut: () => Promise<void>;
};

const Ctx = createContext<Session | null>(null);

function initialLocale(): Locale {
  if (typeof window === "undefined") return "fr";
  try {
    const saved = window.localStorage.getItem("tr_locale");
    if (saved === "fr" || saved === "en") return saved;
  } catch {
    /* storage unavailable */
  }
  return navigator.language?.toLowerCase().startsWith("en") ? "en" : "fr";
}

export function SessionProvider({ children }: { children: ReactNode }) {
  const [me, setMe] = useState<Me | null>(null);
  const [ready, setReady] = useState(false);
  const [locale, setLocaleState] = useState<Locale>("fr");

  const setLocale = useCallback((l: Locale) => {
    setLocaleState(l);
    setApiLocale(l);
    document.documentElement.lang = l;
    try {
      window.localStorage.setItem("tr_locale", l);
    } catch {
      /* ignore */
    }
  }, []);

  const reload = useCallback(async () => {
    try {
      const m = await api<Me>("/me");
      setMe(m);
      return m;
    } catch {
      setMe(null);
      return null;
    }
  }, []);

  useEffect(() => {
    setLocale(initialLocale());
    (async () => {
      if (await tryRestoreSession()) {
        const m = await reload();
        if (m) setLocale(m.locale);
      }
      setReady(true);
    })();
  }, [reload, setLocale]);

  const signIn = useCallback(
    async (token: string) => {
      setAccessToken(token);
      const m = await reload();
      if (m) setLocale(m.locale);
      return m;
    },
    [reload, setLocale],
  );

  const signOut = useCallback(async () => {
    try {
      await api("/auth/logout", { method: "POST" });
    } catch {
      /* already signed out */
    }
    setAccessToken(null);
    setMe(null);
  }, []);

  const value = useMemo(
    () => ({ me, ready, locale, t: dictionaries[locale], setLocale, reload, signIn, signOut }),
    [me, ready, locale, setLocale, reload, signIn, signOut],
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useSession(): Session {
  const s = useContext(Ctx);
  if (!s) throw new Error("useSession outside SessionProvider");
  return s;
}
