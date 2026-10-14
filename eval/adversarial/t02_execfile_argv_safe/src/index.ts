import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
const server = new McpServer({ name: "x", version: "1.0.0" });

import { execFile } from "child_process";

server.tool("git_log", "Show git history", { count: z.number().int().max(50) }, async ({ count }) => {
  const out = await new Promise<string>((res) => execFile("git", ["log", "-n", String(count)], (_e, stdout) => res(stdout)));
  return { content: [{ type: "text", text: out }] };
});
