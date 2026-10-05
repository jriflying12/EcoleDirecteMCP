import { createHash, randomBytes } from "node:crypto";
import type { Express, Request, Response } from "express";

type Client = {
  clientId: string;
  redirectUris: string[];
};

type AuthorizationCode = {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  expiresAt: number;
};

type AccessToken = {
  expiresAt: number;
};

const clients = new Map<string, Client>();
const authorizationCodes = new Map<string, AuthorizationCode>();
const accessTokens = new Map<string, AccessToken>();

function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

function sha256Base64Url(value: string): string {
  return createHash("sha256").update(value).digest("base64url");
}

function baseUrl(req: Request): string {
  const configured = process.env.MCP_PUBLIC_URL;

  if (configured) {
    return configured.replace(/\/$/, "");
  }

  return `${req.protocol}://${req.get("host")}`;
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

export function registerOAuthRoutes(app: Express): void {
  /*
   * OAuth Authorization Server metadata
   */
  app.get(
    "/.well-known/oauth-authorization-server",
    (req, res) => {
      const base = baseUrl(req);

      res.json({
        issuer: base,
        authorization_endpoint: `${base}/authorize`,
        token_endpoint: `${base}/token`,
        registration_endpoint: `${base}/register`,
        response_types_supported: ["code"],
        grant_types_supported: ["authorization_code"],
        code_challenge_methods_supported: ["S256"],
        token_endpoint_auth_methods_supported: ["none"],
      });
    }
  );

  /*
   * MCP Protected Resource Metadata
   */
  app.get(
    "/.well-known/oauth-protected-resource",
    (req, res) => {
      const base = baseUrl(req);

      res.json({
        resource: `${base}/mcp`,
        authorization_servers: [base],
      });
    }
  );

  /*
   * Dynamic Client Registration.
   *
   * Claude can register its callback URL here.
   */
  app.post("/register", (req, res) => {
    const redirectUris = req.body?.redirect_uris;

    if (
      !Array.isArray(redirectUris) ||
      redirectUris.length === 0 ||
      !redirectUris.every(
        (uri: unknown) =>
          typeof uri === "string" &&
          uri.startsWith("https://")
      )
    ) {
      res.status(400).json({
        error: "invalid_redirect_uri",
      });
      return;
    }

    const clientId = randomToken(24);

    clients.set(clientId, {
      clientId,
      redirectUris,
    });

    res.status(201).json({
      client_id: clientId,
      redirect_uris: redirectUris,
      token_endpoint_auth_method: "none",
      grant_types: ["authorization_code"],
      response_types: ["code"],
    });
  });

  /*
   * Authorization page.
   */
  app.get("/authorize", (req, res) => {
    const clientId = String(req.query.client_id ?? "");
    const redirectUri = String(req.query.redirect_uri ?? "");
    const responseType = String(req.query.response_type ?? "");
    const state = String(req.query.state ?? "");
    const codeChallenge = String(
      req.query.code_challenge ?? ""
    );
    const codeChallengeMethod = String(
      req.query.code_challenge_method ?? ""
    );

    const client = clients.get(clientId);

    if (
      !client ||
      !client.redirectUris.includes(redirectUri) ||
      responseType !== "code" ||
      !codeChallenge ||
      codeChallengeMethod !== "S256"
    ) {
      res.status(400).send("Invalid OAuth request");
      return;
    }

    const hidden = (name: string, value: string) =>
      `<input type="hidden" name="${name}" value="${escapeHtml(
        value
      )}">`;

    res
      .status(200)
      .type("html")
      .send(`
<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta
    name="viewport"
    content="width=device-width, initial-scale=1"
  >
  <title>Autoriser Claude</title>
</head>

<body style="
  font-family: system-ui, sans-serif;
  max-width: 480px;
  margin: 80px auto;
  padding: 24px;
">
  <h1>ÉcoleDirecte MCP</h1>

  <p>
    Claude demande l'autorisation d'accéder à votre
    serveur MCP ÉcoleDirecte.
  </p>

  <form method="post" action="/authorize">
    ${hidden("client_id", clientId)}
    ${hidden("redirect_uri", redirectUri)}
    ${hidden("state", state)}
    ${hidden("code_challenge", codeChallenge)}

    <label for="password">
      Mot de passe MCP
    </label>

    <br><br>

    <input
      id="password"
      name="password"
      type="password"
      required
      autocomplete="current-password"
      style="
        width: 100%;
        box-sizing: border-box;
        padding: 12px;
      "
    >

    <br><br>

    <button
      type="submit"
      style="padding: 12px 18px;"
    >
      Autoriser Claude
    </button>
  </form>
</body>
</html>
      `);
  });

  /*
   * Authorization approval.
   */
  app.post(
    "/authorize",
    expressUrlEncoded(),
    (req, res) => {
      const expectedPassword =
        process.env.MCP_OAUTH_PASSWORD;

      if (
        !expectedPassword ||
        req.body.password !== expectedPassword
      ) {
        res.status(401).send(
          "Mot de passe incorrect."
        );
        return;
      }

      const clientId = String(req.body.client_id ?? "");
      const redirectUri = String(
        req.body.redirect_uri ?? ""
      );
      const state = String(req.body.state ?? "");
      const codeChallenge = String(
        req.body.code_challenge ?? ""
      );

      const client = clients.get(clientId);

      if (
        !client ||
        !client.redirectUris.includes(redirectUri) ||
        !codeChallenge
      ) {
        res.status(400).send(
          "Invalid OAuth request"
        );
        return;
      }

      const code = randomToken();

      authorizationCodes.set(code, {
        clientId,
        redirectUri,
        codeChallenge,
        expiresAt: Date.now() + 5 * 60 * 1000,
      });

      const callback = new URL(redirectUri);

      callback.searchParams.set("code", code);

      if (state) {
        callback.searchParams.set("state", state);
      }

      res.redirect(callback.toString());
    }
  );

  /*
   * Exchange authorization code for access token.
   */
  app.post(
    "/token",
    expressUrlEncoded(),
    (req, res) => {
      const grantType = String(
        req.body.grant_type ?? ""
      );

      const code = String(req.body.code ?? "");
      const clientId = String(
        req.body.client_id ?? ""
      );
      const redirectUri = String(
        req.body.redirect_uri ?? ""
      );
      const codeVerifier = String(
        req.body.code_verifier ?? ""
      );

      if (grantType !== "authorization_code") {
        res.status(400).json({
          error: "unsupported_grant_type",
        });
        return;
      }

      const authorization =
        authorizationCodes.get(code);

      if (
        !authorization ||
        authorization.expiresAt < Date.now() ||
        authorization.clientId !== clientId ||
        authorization.redirectUri !== redirectUri
      ) {
        res.status(400).json({
          error: "invalid_grant",
        });
        return;
      }

      if (
        sha256Base64Url(codeVerifier) !==
        authorization.codeChallenge
      ) {
        res.status(400).json({
          error: "invalid_grant",
        });
        return;
      }

      authorizationCodes.delete(code);

      const accessToken = randomToken();

      accessTokens.set(accessToken, {
        expiresAt:
          Date.now() + 24 * 60 * 60 * 1000,
      });

      res.json({
        access_token: accessToken,
        token_type: "Bearer",
        expires_in: 86400,
      });
    }
  );
}

export function isValidOAuthToken(
  req: Request
): boolean {
  const authorization =
    req.headers.authorization;

  if (
    !authorization ||
    !authorization.startsWith("Bearer ")
  ) {
    return false;
  }

  const token = authorization.slice(7);

  const stored = accessTokens.get(token);

  if (!stored) {
    return false;
  }

  if (stored.expiresAt < Date.now()) {
    accessTokens.delete(token);
    return false;
  }

  return true;
}

/*
 * Kept local so oauth.ts doesn't require another dependency.
 */
function expressUrlEncoded() {
  return (
    req: Request,
    res: Response,
    next: () => void
  ) => {
    let body = "";

    req.setEncoding("utf8");

    req.on("data", (chunk) => {
      body += chunk;
    });

    req.on("end", () => {
      const params =
        new URLSearchParams(body);

      req.body =
        Object.fromEntries(params.entries());

      next();
    });

    req.on("error", () => {
      res.status(400).send("Invalid request");
    });
  };
}
