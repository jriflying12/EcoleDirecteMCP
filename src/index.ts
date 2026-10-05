/**
 * EcoleDirecte MCP Server — Remote HTTP entrypoint.
 */

import express from "express";
import { randomUUID } from "node:crypto";

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";

import { EdHttpClient } from "./ecoledirecte/http/client.js";
import { AuthService } from "./ecoledirecte/auth/service.js";
import { FileAuthStore } from "./ecoledirecte/auth/fileStore.js";
import { EdDataService } from "./ecoledirecte/data/service.js";

import { registerDataTools } from "./server/dataTools.js";
import { registerTools } from "./server/tools.js";

import {
  registerOAuthRoutes,
  isValidOAuthToken,
} from "./server/oauth.js";

import { log } from "./ecoledirecte/logging.js";

async function main(): Promise<void> {
  log("info", "Starting EcoleDirecte Remote MCP server");

  // ---------------------------------------------------------------------------
  // EcoleDirecte
  // ---------------------------------------------------------------------------

  const http = new EdHttpClient();

  const authDir =
    process.env.ECOLEDIRECTE_AUTH_DIR || undefined;

  const store = new FileAuthStore(
    authDir ? { dir: authDir } : undefined
  );

  const auth = new AuthService(http, store);
  const data = new EdDataService(http, auth);

  try {
    const restored = await auth.restore();

    log("info", `Auth restore result: ${restored.status}`);

    if (restored.status === "error") {
      log(
        "warn",
        `Restore ended in error: ${restored.message}`
      );
    }
  } catch (err) {
    log(
      "warn",
      `Session restore failed: ${
        err instanceof Error
          ? err.message
          : String(err)
      }`
    );
  }

  // ---------------------------------------------------------------------------
  // Express
  // ---------------------------------------------------------------------------

  const app = express();

  app.use(express.json());

  // Railway health check
  app.get("/", (_req, res) => {
    res.status(200).json({
      status: "ok",
      service: "ecoledirecte-mcp",
    });
  });

  // ---------------------------------------------------------------------------
  // OAuth
  // ---------------------------------------------------------------------------

  registerOAuthRoutes(app);

  /*
   * Protect the MCP resource with OAuth.
   *
   * When Claude accesses /mcp without a valid access token,
   * advertise the Protected Resource Metadata endpoint so that
   * Claude can discover the OAuth authorization server.
   */
  app.use("/mcp", (req, res, next) => {
    if (!isValidOAuthToken(req)) {
      const baseUrl = (
        process.env.MCP_PUBLIC_URL ||
        `${req.protocol}://${req.get("host")}`
      ).replace(/\/$/, "");

      res.setHeader(
        "WWW-Authenticate",
        `Bearer resource_metadata="${baseUrl}/.well-known/oauth-protected-resource"`
      );

      res.status(401).json({
        error: "Unauthorized",
      });

      return;
    }

    next();
  });

  // ---------------------------------------------------------------------------
  // MCP server factory
  // ---------------------------------------------------------------------------

  function createServer(): McpServer {
    const server = new McpServer({
      name: "ecoledirecte-mcp",
      version: "0.1.0",
    });

    registerTools(server, auth);
    registerDataTools(server, data);

    return server;
  }

  /*
   * Streamable HTTP is sessionful here.
   *
   * Each initialized MCP session keeps its transport so subsequent
   * POST / GET / DELETE requests can use the same session.
   */
  const transports = new Map<
    string,
    StreamableHTTPServerTransport
  >();

  // ---------------------------------------------------------------------------
  // POST /mcp
  // ---------------------------------------------------------------------------

  app.post("/mcp", async (req, res) => {
    try {
      const sessionId =
        req.headers["mcp-session-id"] as
          | string
          | undefined;

      // Existing MCP session
      if (sessionId) {
        const transport =
          transports.get(sessionId);

        if (!transport) {
          res.status(404).json({
            jsonrpc: "2.0",
            error: {
              code: -32001,
              message: "Session not found",
            },
            id: null,
          });

          return;
        }

        await transport.handleRequest(
          req,
          res,
          req.body
        );

        return;
      }

      // A request without a session must be an initialize request.
      if (!isInitializeRequest(req.body)) {
        res.status(400).json({
          jsonrpc: "2.0",
          error: {
            code: -32000,
            message:
              "Bad Request: Session ID required",
          },
          id: null,
        });

        return;
      }

      let transport:
        StreamableHTTPServerTransport;

      transport =
        new StreamableHTTPServerTransport({
          sessionIdGenerator: () =>
            randomUUID(),

          onsessioninitialized: (
            newSessionId
          ) => {
            transports.set(
              newSessionId,
              transport
            );

            log(
              "info",
              `MCP session initialized: ${newSessionId}`
            );
          },
        });

      transport.onclose = () => {
        const id = transport.sessionId;

        if (id) {
          transports.delete(id);

          log(
            "info",
            `MCP session closed: ${id}`
          );
        }
      };

      const server = createServer();

      await server.connect(transport);

      await transport.handleRequest(
        req,
        res,
        req.body
      );
    } catch (err) {
      log(
        "error",
        `MCP POST error: ${
          err instanceof Error
            ? err.message
            : String(err)
        }`
      );

      if (!res.headersSent) {
        res.status(500).json({
          jsonrpc: "2.0",
          error: {
            code: -32603,
            message:
              "Internal server error",
          },
          id: null,
        });
      }
    }
  });

  // ---------------------------------------------------------------------------
  // GET /mcp
  // ---------------------------------------------------------------------------

  app.get("/mcp", async (req, res) => {
    try {
      const sessionId =
        req.headers["mcp-session-id"] as
          | string
          | undefined;

      if (!sessionId) {
        res.status(400).json({
          error:
            "Missing MCP session ID",
        });

        return;
      }

      const transport =
        transports.get(sessionId);

      if (!transport) {
        res.status(404).json({
          error:
            "MCP session not found",
        });

        return;
      }

      await transport.handleRequest(
        req,
        res
      );
    } catch (err) {
      log(
        "error",
        `MCP GET error: ${
          err instanceof Error
            ? err.message
            : String(err)
        }`
      );

      if (!res.headersSent) {
        res.status(500).json({
          error:
            "Internal server error",
        });
      }
    }
  });

  // ---------------------------------------------------------------------------
  // DELETE /mcp
  // ---------------------------------------------------------------------------

  app.delete("/mcp", async (req, res) => {
    try {
      const sessionId =
        req.headers["mcp-session-id"] as
          | string
          | undefined;

      if (!sessionId) {
        res.status(400).json({
          error:
            "Missing MCP session ID",
        });

        return;
      }

      const transport =
        transports.get(sessionId);

      if (!transport) {
        res.status(404).json({
          error:
            "MCP session not found",
        });

        return;
      }

      await transport.handleRequest(
        req,
        res
      );
    } catch (err) {
      log(
        "error",
        `MCP DELETE error: ${
          err instanceof Error
            ? err.message
            : String(err)
        }`
      );

      if (!res.headersSent) {
        res.status(500).json({
          error:
            "Internal server error",
        });
      }
    }
  });

  // ---------------------------------------------------------------------------
  // Start server
  // ---------------------------------------------------------------------------

  const port = Number(
    process.env.PORT || 3000
  );

  app.listen(
    port,
    "0.0.0.0",
    () => {
      log(
        "info",
        `EcoleDirecte MCP listening on port ${port}`
      );
    }
  );
}

main().catch((err) => {
  process.stderr.write(
    `Fatal: ${err}\n`
  );

  process.exit(1);
});
