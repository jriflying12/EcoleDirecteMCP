/**
 * EcoleDirecte MCP Server — Remote HTTP entrypoint.
 */

import express from "express";
import { randomUUID } from "node:crypto";

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

import { EdHttpClient } from "./ecoledirecte/http/client.js";
import { AuthService } from "./ecoledirecte/auth/service.js";
import { FileAuthStore } from "./ecoledirecte/auth/fileStore.js";
import { EdDataService } from "./ecoledirecte/data/service.js";
import { registerDataTools } from "./server/dataTools.js";
import { registerTools } from "./server/tools.js";
import { log } from "./ecoledirecte/logging.js";

async function main(): Promise<void> {
  log("info", "Starting EcoleDirecte Remote MCP server");

  const http = new EdHttpClient();

  const credentialsFile =
    process.env.ECOLEDIRECTE_CREDENTIALS_FILE || undefined;

  const store = new FileAuthStore(
    credentialsFile ? { credentialsFile } : undefined
  );

  const auth = new AuthService(http, store);
  const data = new EdDataService(http, auth);

  try {
    const restored = await auth.restore();

    log("info", `Auth restore result: ${restored.status}`);

    if (restored.status === "error") {
      log("warn", `Restore ended in error: ${restored.message}`);
    }
  } catch (err) {
    log(
      "warn",
      `Session restore failed: ${
        err instanceof Error ? err.message : String(err)
      }`
    );
  }

  const app = express();

  app.use(express.json());

  // Simple health check for Railway
  app.get("/", (_req, res) => {
    res.status(200).json({
      status: "ok",
      service: "ecoledirecte-mcp",
    });
  });

  app.post("/mcp", async (req, res) => {
    const server = new McpServer({
      name: "ecoledirecte-mcp",
      version: "0.1.0",
    });

    registerTools(server, auth);
    registerDataTools(server, data);

    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
    });

    res.on("close", () => {
      transport.close();
      server.close();
    });

    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  });

  const port = Number(process.env.PORT || 3000);

  app.listen(port, "0.0.0.0", () => {
    log("info", `EcoleDirecte MCP listening on port ${port}`);
  });
}

main().catch((err) => {
  process.stderr.write(`Fatal: ${err}\n`);
  process.exit(1);
});
