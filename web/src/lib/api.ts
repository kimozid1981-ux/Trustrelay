// Minimal typed API client. The access token lives only in memory; the refresh token is an httpOnly
// cookie the page cannot read. A 401 triggers one silent refresh, then the request is retried once.

export type Problem = { status: number; code: string; detail: string; problems?: string[] };

export class ApiError extends Error {
  constructor(public problem: Problem) {
    super(problem.detail);
  }
}

let accessToken: string | null = null;
let refreshing: Promise<boolean> | null = null;
let locale = "fr";

export function setAccessToken(t: string | null) {
  accessToken = t;
}
export function hasAccessToken() {
  return accessToken !== null;
}
export function setApiLocale(l: string) {
  locale = l;
}

async function refresh(): Promise<boolean> {
  if (!refreshing) {
    refreshing = fetch("/api/v1/auth/refresh", {
      method: "POST",
      credentials: "same-origin",
      headers: { "X-Requested-With": "trustrelay" },
    })
      .then(async (r) => {
        if (!r.ok) return false;
        const body = await r.json();
        accessToken = body.access_token;
        return true;
      })
      .catch(() => false)
      .finally(() => {
        setTimeout(() => (refreshing = null), 0);
      });
  }
  return refreshing;
}

export async function tryRestoreSession(): Promise<boolean> {
  return refresh();
}

type Opts = { method?: string; body?: unknown; form?: FormData; raw?: boolean; retry?: boolean };

export async function api<T = unknown>(path: string, opts: Opts = {}): Promise<T> {
  const headers: Record<string, string> = { "Accept-Language": locale };
  if (accessToken) headers.Authorization = `Bearer ${accessToken}`;
  let body: BodyInit | undefined;
  if (opts.form) body = opts.form;
  else if (opts.body !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(opts.body);
  }
  const res = await fetch(`/api/v1${path}`, { method: opts.method ?? "GET", headers, body, credentials: "same-origin" });
  if (res.status === 401 && opts.retry !== false && !path.startsWith("/auth/")) {
    if (await refresh()) return api<T>(path, { ...opts, retry: false });
  }
  if (!res.ok) {
    let problem: Problem = { status: res.status, code: "http_error", detail: res.statusText };
    try {
      problem = await res.json();
    } catch {
      /* not JSON */
    }
    throw new ApiError(problem);
  }
  if (opts.raw) return res as unknown as T;
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

// ---- Types mirroring the backend (docs/architecture/03-api.md) ----
export type Finding = {
  code: string;
  module: string;
  severity: "known_malicious" | "strong" | "moderate" | "info";
  confidence: "low" | "medium" | "high";
  confidence_label: string;
  source: string;
  source_name: string;
  checked_at: string;
  ai_generated: boolean;
  title: string;
  explanation: string;
  evidence: string[];
  limitation: string;
};

export type Verdict =
  | "known_malicious"
  | "strong_suspicious"
  | "moderate_warning"
  | "insufficient_information"
  | "no_known_warning_signals";

export type Analysis = {
  id: string;
  kind: string;
  status: "queued" | "processing" | "completed" | "failed";
  created_at: string;
  expires_at: string;
  label: string | null;
  note: string | null;
  input?: string | null;
  verdict?: Verdict;
  verdict_title?: string;
  verdict_summary?: string;
  confidence?: string;
  confidence_label?: string;
  recommended_action?: { code: string; text: string };
  identified_organisations?: string[];
  identified_domains?: string[];
  findings?: Finding[];
  missing_information?: { code: string; text: string }[];
  sources_checked?: { source: string; ok: boolean; checked_at: string; detail: string | null }[];
  ai_used?: boolean;
  disclaimer?: string;
};

export type Me = {
  id: string;
  email: string;
  display_name: string | null;
  role: "user" | "support" | "admin" | "security";
  locale: "fr" | "en";
  mfa_enabled: boolean;
  onboarding_completed: boolean;
  plan: string;
  preferences: {
    retention_days: number;
    explanation_level: string;
    notify_analysis_complete: boolean;
    notify_family_warnings: boolean;
    product_analytics_opt_in: boolean;
    allow_ai_processing: boolean;
  };
};
