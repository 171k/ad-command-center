// Thin API client. Cookies carry the session; the CSRF token is read from the
// readable `adcc_csrf` cookie and sent as a header on state-changing requests.

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

function csrfToken(): string {
  const m = document.cookie.match(/(?:^|;\s*)adcc_csrf=([^;]+)/);
  return m ? decodeURIComponent(m[1]) : "";
}

type Opts = { method?: string; body?: unknown; raw?: boolean };

export async function api<T = any>(path: string, opts: Opts = {}): Promise<T> {
  const method = opts.method ?? "GET";
  const headers: Record<string, string> = {};
  const init: RequestInit = { method, credentials: "include", headers };

  if (opts.body !== undefined) {
    headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(opts.body);
  }
  if (method !== "GET" && method !== "HEAD") {
    headers["X-CSRF-Token"] = csrfToken();
  }

  const res = await fetch(path.startsWith("/api") ? path : `/api${path}`, init);
  if (res.status === 204) return undefined as T;

  const text = await res.text();
  let data: any = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = text;
  }
  if (!res.ok) {
    const detail = (data && (data.detail || data.message)) || res.statusText;
    throw new ApiError(res.status, typeof detail === "string" ? detail : JSON.stringify(detail));
  }
  return data as T;
}

export async function upload<T = any>(path: string, form: FormData): Promise<T> {
  // Multipart POST: let the browser set Content-Type (with boundary); do not set it.
  const res = await fetch(path.startsWith("/api") ? path : `/api${path}`, {
    method: "POST",
    credentials: "include",
    headers: { "X-CSRF-Token": csrfToken() },
    body: form,
  });
  const text = await res.text();
  let data: any = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = text;
  }
  if (!res.ok) {
    const detail = (data && (data.detail || data.message)) || res.statusText;
    throw new ApiError(res.status, typeof detail === "string" ? detail : JSON.stringify(detail));
  }
  return data as T;
}

export const get = <T = any>(p: string) => api<T>(p);
export const post = <T = any>(p: string, body?: unknown) => api<T>(p, { method: "POST", body });
export const put = <T = any>(p: string, body?: unknown) => api<T>(p, { method: "PUT", body });
export const del = <T = any>(p: string) => api<T>(p, { method: "DELETE" });
