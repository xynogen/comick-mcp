import { McpServer } from '@modelcontextprotocol/server';
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import { z } from 'zod';
import { apiGet, connect } from './oauth.js';
import { catalogGet, searchSchema } from './catalog.js';

const readOnly = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true };

async function result(request: () => Promise<unknown>) {
  try {
    return { content: [{ type: 'text' as const, text: JSON.stringify(await request()) }] };
  } catch (error) {
    return { isError: true, content: [{ type: 'text' as const, text: error instanceof Error ? error.message : 'Comick request failed.' }] };
  }
}

serveStdio(() => {
  const server = new McpServer({ name: 'comick-mcp', version: '0.1.0' });
  server.registerTool('comick_connect', {
    description: 'Connect the local MCP server to Comick using OAuth PKCE. Requires COMICK_CLIENT_ID, a registered loopback redirect URI, and Linux Secret Service with secret-tool. Call start once to open the system browser, let the user log in and consent there, then call status to check completion. The browser must run on the MCP server machine. Tokens stay in the OS keyring, never in plaintext files or tool results. This is a tool, not automatic OAuth on MCP transport connection.',
    inputSchema: z.object({
      action: z.enum(['start', 'status']).default('start'),
      open_browser: z.boolean().default(true).describe('Try the Linux system browser. If false, open the returned authorization_url manually.'),
    }).strict(),
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
  }, ({ action, open_browser }) => result(() => connect(action, open_browser)));

  server.registerTool('comick_me', {
    description: 'Read the connected Comick public profile. Use comick_connect to log in through the system browser first; never supply passwords, cookies or tokens to tools.',
    inputSchema: z.object({}).strict(),
    annotations: readOnly,
  }, () => result(() => apiGet('/me')));

  server.registerTool('comick_library', {
    description: 'Read one page of the connected manga/anime library. Pass next_cursor unchanged with the same filters to get the next page. Status: 1 reading/watching, 2 completed, 3 on hold, 4 dropped, 5 planned. Progress numbers are strings, not integers.',
    inputSchema: z.object({
      media_type: z.enum(['manga', 'anime']).optional(),
      status: z.number().int().min(1).max(5).optional(),
      limit: z.number().int().min(1).max(100).default(50),
      cursor: z.string().min(1).max(8192).optional(),
    }).strict(),
    annotations: readOnly,
  }, query => result(() => apiGet('/me/library', query)));

  server.registerTool('comick_search', {
    description: 'Search or browse public manga/manhwa/manhua (anime optional), without login. For similar manga: find the source by q, inspect comick_title, then search using a few relevant genre/theme/tag slugs WITHOUT q. Results are filter matches ordered by sort, not similarity scores; explain the shared themes and omit the source itself. Returns one page, with no total count. Keyword ranking can override sorting; an empty page is not an error.',
    inputSchema: searchSchema,
    annotations: readOnly,
  }, query => result(() => catalogGet('/v1.0/search/', query)));

  server.registerTool('comick_filters', {
    description: 'List valid public genre/theme/format slugs or category tag slugs for comick_search. No login needed. Use genres for the genre list, tags for categories.',
    inputSchema: z.object({ kind: z.enum(['genres', 'tags']).default('genres') }).strict(),
    annotations: readOnly,
  }, ({ kind }) => result(() => catalogGet(kind === 'genres' ? '/genre/' : '/category/')));

  server.registerTool('comick_title', {
    description: 'Read public title details including synopsis, genre/theme slugs, category tags and catalog recommendations when present. Use the exact slug or HID returned by search (keep numeric prefixes). For similar manga, pick the relevant themes from this response and use comick_search without a title keyword. No login needed.',
    inputSchema: z.object({
      slug: z.string().min(1).max(200).regex(/^[A-Za-z0-9_-]+$/),
      media_type: z.enum(['manga', 'anime']).default('manga'),
    }).strict(),
    annotations: readOnly,
  }, ({ slug, media_type }) => result(() => catalogGet(`/v1.0/comic/${encodeURIComponent(slug)}/`, { media_type })));

  return server;
}, { onerror: () => console.error('MCP transport error. Check the client connection.') });
