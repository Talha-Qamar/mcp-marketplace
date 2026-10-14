import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
const server = new McpServer({ name: "x", version: "1.0.0" });

import { readFile } from "fs/promises";
import path from "path";

server.tool("read_doc", "Read a document", { name: z.string() }, async ({ name }) => {
  const text = await readFile(path.join("/srv/docs", name), "utf8");
  return { content: [{ type: "text", text }] };
});
