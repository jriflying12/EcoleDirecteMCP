/**
 * Cookie-aware HTTP client for the EcoleDirecte private API.
 *
 * Manages a simple cookie jar, common headers, the GTK bootstrap dance,
 * and the form-urlencoded `data=` wrapper the API expects.
 */

import { CONTENT_TYPE_FORM } from "../api/constants.js";
import { log } from "../logging.js";

const DEFAULT_USER_AGENT =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36";

const ECOLEDIRECTE_REFERER =
  "https://www.ecoledirecte.com/";

const FETCH_TIMEOUT_MS = 30_000;
const FETCH_MAX_ATTEMPTS = 3;
const FETCH_RETRY_BASE_DELAY_MS = 250;

const RETRYABLE_FETCH_ERROR_CODES = new Set([
  "EAI_AGAIN",
  "ECONNABORTED",
  "ECONNRESET",
  "ENETUNREACH",
  "ETIMEDOUT",
  "UND_ERR_CONNECT_TIMEOUT",
  "UND_ERR_HEADERS_TIMEOUT",
  "UND_ERR_SOCKET",
]);

export class EdHttpClient {
  private cookies = new Map<string, string>();
  private xGtk: string | undefined;
  private xToken: string | undefined;
  private twoFaToken: string | undefined;
  readonly version: string;

  constructor(opts: { version?: string } = {}) {
    this.version = opts.version ?? "4.103.0";
  }

  // ── Cookie jar ───────────────────────────────────────────────

  getCookie(name: string): string | undefined {
    return this.cookies.get(name);
  }

  getCookies(): Record<string, string> {
    return Object.fromEntries(this.cookies);
  }

  setCookie(name: string, value: string): void {
    this.cookies.set(name, value);
  }

  /** Parse `Set-Cookie` header values (simplified; no path/domain handling needed). */
  ingestSetCookieHeaders(headers: Headers): void {
    const raw = headers.getSetCookie?.() ?? [];

    for (const line of raw) {
      const [pair] = line.split(";");
      const eqIdx = pair.indexOf("=");

      if (eqIdx < 1) continue;

      const name = pair.slice(0, eqIdx).trim();
      const value = pair.slice(eqIdx + 1).trim();

      this.cookies.set(name, value);
    }
  }

  /** Hydrate cookie jar from a persisted record (session restore / import). */
  loadCookies(cookies: Record<string, string>): void {
    for (const [k, v] of Object.entries(cookies)) {
      this.cookies.set(k, v);
    }
  }

  // ── GTK ──────────────────────────────────────────────────────

  getGtk(): string | undefined {
    return this.xGtk;
  }

  setGtk(value: string): void {
    this.xGtk = value;
  }

  /** Drop the cached header value so `X-GTK` falls back to the current GTK cookie. */
  clearGtk(): void {
    this.xGtk = undefined;
  }

  // ── Token ────────────────────────────────────────────────────

  getToken(): string | undefined {
    return this.xToken;
  }

  setToken(value: string): void {
    this.xToken = value;
  }

  clearToken(): void {
    this.xToken = undefined;
  }

  getTwoFaToken(): string | undefined {
    return this.twoFaToken;
  }

  setTwoFaToken(value: string): void {
    this.twoFaToken = value;
  }

  clearTwoFaToken(): void {
    this.twoFaToken = undefined;
  }

  // ── Request helpers ──────────────────────────────────────────

  private commonHeaders(
    opts: {
      includeGtk?: boolean;
      includeToken?: boolean;
      includeTwoFaToken?: boolean;
      includeCookies?: boolean;
    } = {},
  ): Record<string, string> {
    const includeGtk =
      opts.includeGtk ?? true;

    const includeToken =
      opts.includeToken ?? true;

    const includeTwoFaToken =
      opts.includeTwoFaToken ?? true;

    const includeCookies = opts.includeCookies ?? true;

    const h: Record<string, string> = {
      "User-Agent": DEFAULT_USER_AGENT,
      Accept: "application/json, text/plain, */*",
      Referer: ECOLEDIRECTE_REFERER,
    };

    if (includeCookies) {
      const cookieStr = this.buildCookieHeader();
      if (cookieStr) h["Cookie"] = cookieStr;
    }

    if (includeGtk) {
      const gtkValue =
        this.xGtk ??
        this.getGtkFromCookie();

      if (gtkValue) {
        h["X-GTK"] = gtkValue;
      }
    }

    if (
      includeToken &&
      this.xToken
    ) {
      h["X-Token"] = this.xToken;
    }

    if (
      includeTwoFaToken &&
      this.twoFaToken
    ) {
      h["2FA-Token"] =
        this.twoFaToken;
    }

    return h;
  }

  /** Angular's XSRF extractor URL-decodes GTK; the Cookie header stays raw. */
  private getGtkFromCookie(): string | undefined {
    const raw = this.cookies.get("GTK");
    if (raw === undefined) return undefined;
    try {
      return decodeURIComponent(raw);
    } catch {
      // Preserve non-encoded cookies containing a literal percent sign.
      return raw;
    }
  }

  private buildCookieHeader(): string {
    return [...this.cookies.entries()]
      .map(([k, v]) => `${k}=${v}`)
      .join("; ");
  }

  private async request(
    url: string,
    init: RequestInit,
  ): Promise<Response> {
    const endpoint = new URL(url);
    const isLogin = endpoint.pathname.endsWith("/login.awp");
    const stage = endpoint.searchParams.get("gtk") === "1" ? "bootstrap" : "login";
    for (
      let attempt = 1;
      attempt <= FETCH_MAX_ATTEMPTS;
      attempt += 1
    ) {
      try {
        if (isLogin) {
          const headers = new Headers(init.headers);
          log("info", "EcoleDirecte auth request", {
            stage,
            attempt,
            method: init.method,
            version: this.version,
            cookiesPresent: headers.has("Cookie"),
            gtkPresent: headers.has("X-GTK"),
            gtkSource: !headers.has("X-GTK") ? "absent" : this.xGtk !== undefined ? "captured" : "cookie",
            gtkCookieEncoded: /%[0-9a-f]{2}/i.test(this.cookies.get("GTK") ?? ""),
          });
        }
        const response = await fetch(url, {
          ...init,
          redirect: "manual",
          signal: AbortSignal.timeout(
            FETCH_TIMEOUT_MS
          ),
        });
        if (isLogin) {
          const code = response.headers.get("X-Code");
          log("info", "EcoleDirecte auth response", {
            stage,
            httpStatus: response.status,
            apiHeaderCode: code !== null && /^\d{3}$/.test(code) ? Number(code) : null,
            gtkHeaderPresent: response.headers.has("X-GTK"),
            sessionTokenPresent: response.headers.has("X-Token"),
            twoFaTokenPresent: response.headers.has("2FA-Token"),
            cookieCount: response.headers.getSetCookie?.().length ?? 0,
          });
        }
        return response;
      } catch (error) {
        if (
          !shouldRetryRequest(error) ||
          attempt >= FETCH_MAX_ATTEMPTS
        ) {
          throw error;
        }

        await wait(
          FETCH_RETRY_BASE_DELAY_MS *
            Math.pow(2, attempt - 1)
        );
      }
    }

    throw new Error(
      "Unreachable request retry state"
    );
  }

  /** Plain GET with cookie + GTK headers. */
  async get(
    url: string,
    opts: {
      includeGtk?: boolean;
      includeToken?: boolean;
      includeTwoFaToken?: boolean;
    } = {},
  ): Promise<Response> {
    return this.request(url, {
      method: "GET",
      headers: this.commonHeaders(opts),
    });
  }

  /**
   * POST with the `data=<json>` form-urlencoded wrapper the API expects.
   * The caller passes a plain object; we JSON-stringify and wrap it.
   */
  async postForm(
    url: string,
    data: Record<string, unknown>,
    opts: {
      includeGtk?: boolean;
      includeToken?: boolean;
      includeTwoFaToken?: boolean;
      includeCookies?: boolean;
      /** Match the observed EcoleDirecte web serializer for login requests. */
      formEncoding?: "standard" | "browser";
    } = {},
  ): Promise<Response> {
    if (new URL(url).pathname.endsWith("/login.awp")) {
      log("info", "EcoleDirecte login payload metadata", {
        usernamePresent: typeof data.identifiant === "string" && data.identifiant.length > 0,
        passwordPresent: typeof data.motdepasse === "string" && data.motdepasse.length > 0,
        factorCount: Array.isArray(data.fa) ? data.fa.length : 0,
        challengePresent: typeof data.cn === "string" && typeof data.cv === "string",
      });
    }
    // The web client's E7/v7 serializer escapes only form separators inside
    // string values, then sends pretty-printed JSON directly after `data=`.
    // Retain standard encoding for callers that do not request browser parity.
    const body = opts.formEncoding === "browser"
      ? `data=${JSON.stringify(data, (_key, value) =>
          typeof value === "string"
            ? value.replaceAll("%", "%25").replaceAll("&", "%26").replaceAll("+", "%2B")
            : value, 4)}`
      : `data=${encodeURIComponent(JSON.stringify(data))}`;

    return this.request(url, {
      method: "POST",
      headers: {
        ...this.commonHeaders(opts),
        "Content-Type":
          CONTENT_TYPE_FORM,
      },
      body,
    });
  }

  /** Extract auth-relevant response headers after a login call. */
  captureAuthHeaders(
    res: Response
  ): void {
    const gtk =
      res.headers.get("X-GTK");

    if (gtk) {
      this.xGtk = gtk;
    }

    const token =
      res.headers.get("X-Token");

    if (token) {
      this.xToken = token;
    }

    const twoFaToken =
      res.headers.get("2FA-Token");

    if (twoFaToken) {
      this.twoFaToken =
        twoFaToken;
    }

    this.ingestSetCookieHeaders(
      res.headers
    );
  }

  /** Reset all auth state (cookies, GTK, token). */
  clearAuth(): void {
    this.cookies.clear();
    this.xGtk = undefined;
    this.xToken = undefined;
    this.twoFaToken = undefined;
  }
}

function shouldRetryRequest(
  error: unknown
): boolean {
  if (!(error instanceof Error)) {
    return false;
  }

  if (
    error.name === "AbortError" ||
    error.name === "TimeoutError"
  ) {
    return true;
  }

  if (
    error.message
      .trim()
      .toLowerCase() ===
    "fetch failed"
  ) {
    return true;
  }

  const code =
    extractErrorCode(error.cause);

  return (
    code !== undefined &&
    RETRYABLE_FETCH_ERROR_CODES.has(
      code
    )
  );
}

function extractErrorCode(
  cause: unknown
): string | undefined {
  if (
    !cause ||
    typeof cause !== "object"
  ) {
    return undefined;
  }

  const record =
    cause as Record<
      string,
      unknown
    >;

  return typeof record.code ===
    "string"
    ? record.code
    : undefined;
}

function wait(
  ms: number
): Promise<void> {
  return new Promise((resolve) =>
    setTimeout(resolve, ms)
  );
}
