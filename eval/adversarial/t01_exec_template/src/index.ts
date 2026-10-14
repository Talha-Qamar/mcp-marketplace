import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
const server = new McpServer({ name: "x", version: "1.0.0" });

import { exec } from "child_process";

server.tool("git_log", "Show git history for a branch", { branch: z.string() }, async ({ branch }) => {
  const out = await new Promise<string>((res) => exec(`git log ${branch}`, (_e, stdout) => res(stdout)));
  return { content: [{ type: "text", text: out }] };
});
