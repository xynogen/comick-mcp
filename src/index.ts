import { McpServer } from '@modelcontextprotocol/server';
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import { z } from 'zod';
import { apiGet, ComickError, connect, disconnect, disconnectOutput } from './oauth.js';
import { chapters, chaptersOutput, chaptersSchema, filters, filtersOutput, libraryEntry, libraryEntryOutput, libraryEntrySchema, search, searchOutput, searchSchema, title, titleOutput, titleSchema } from './catalog.js';

const readOnly = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true };

async function result(request: () => Promise<unknown>) {
  try {
    const value = await request();
    const structuredContent = value as Record<string, unknown>;
    return { structuredContent, content: [{ type: 'text' as const, text: JSON.stringify(value) }] };
  } catch (error) {
    const failure = error instanceof ComickError ? { code: error.code, message: error.message, status: error.status, retry_after: error.retryAfter }
      : error instanceof z.ZodError ? { code: 'invalid_input', message: 'Invalid Comick tool input.' }
      : { code: 'request_failed', message: 'Comick request failed. Check configuration and connection; reconnect if necessary.' };
    return { isError: true, content: [{ type: 'text' as const, text: JSON.stringify({ error: failure }) }] };
  }
}

serveStdio(() => {
  const server = new McpServer({ name: 'comick-mcp', version: '0.1.0' });
  server.registerTool('comick_connect', {
    description: 'Connect this local MCP server to Comick using OAuth PKCE. Requires COMICK_CLIENT_ID, a registered loopback callback, and Windows Credential Manager or Linux Secret Service with secret-tool. Call start once, let the user consent in the browser, then check status. Windows returns a URL to open manually on the server machine. Tokens stay in the OS credential store, never in tool results. This does not authenticate the MCP transport.',
    inputSchema: z.object({
      action: z.enum(['start', 'status']).default('start'),
      open_browser: z.boolean().default(true).describe('Try the Linux system browser. If false, open the returned authorization_url manually.'),
    }).strict(),
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
  }, ({ action, open_browser }) => result(() => connect(action, open_browser)));

  server.registerTool('comick_disconnect', {
    description: 'Disconnect Comick after the user requests it: revoke stored access and refresh tokens, then delete local OS credentials. Warnings distinguish local deletion from incomplete server revocation. Does not remove all app consent; use Comick Connected apps for that.',
    inputSchema: z.object({}).strict(), outputSchema: disconnectOutput,
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
  }, () => result(disconnect));

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

  server.registerTool('comick_library_entry', {
    description: 'Read saved progress, Continue entry, reading/watching status and personal rating for one title HID in the connected library. Requires library:read. Progress numbers are strings and describe saved progress, not the next unread chapter. A 404 does not prove that a title exists or is unfollowed. No library-wide scan or write is performed.',
    inputSchema: libraryEntrySchema, outputSchema: libraryEntryOutput, annotations: readOnly,
  }, query => result(() => libraryEntry(query)));

  server.registerTool('comick_chapters', {
    description: 'List one page of manga chapters for a title HID without login, newest creation first (not highest chapter number). Returns release/update dates, language, groups and chapter numbers as strings. Supply the exact title slug from search for reader links. lang accepts comma-separated codes such as en,id or pt-br. Multiple releases of the same number are distinct; this is not an unread list, final chapter count, image downloader or anime episode tool.',
    inputSchema: chaptersSchema, outputSchema: chaptersOutput, annotations: readOnly,
  }, query => result(() => chapters(query)));

  server.registerTool('comick_search', {
    description: 'Search public manga/manhwa/manhua (anime optional) without login. Default: an index of 5 matches with only HID, slug, title, rating and status; no synopsis or genre lookup. Use filters to narrow candidates, then call comick_title for only 1–2 selected matches. Keep detailed=false unless full metadata for every match is explicitly needed. Do not increase limit or fetch every title by default. For similar manga, search genre/theme slugs WITHOUT q. Filter matches, not similarity scores; one page, no total.',
    inputSchema: searchSchema,
    outputSchema: searchOutput,
    annotations: readOnly,
  }, query => result(() => search(query)));

  server.registerTool('comick_filters', {
    description: 'List valid public genre/theme/format slugs or category tag slugs for comick_search. No login needed. Use genres for the genre list, tags for categories.',
    inputSchema: z.object({ kind: z.enum(['genres', 'tags']).default('genres') }).strict(),
    outputSchema: filtersOutput,
    annotations: readOnly,
  }, ({ kind }) => result(() => filters(kind)));

  server.registerTool('comick_title', {
    description: 'Read compact title details, genres, tags, languages and up to five community recommendations. Use the exact slug or HID from search; supply hid alongside slug for authenticated fallback. If public details are blocked, returns explicitly partial metadata only from a verified matching title. Never starts login automatically. For similar titles, search relevant genre/theme slugs without q; community votes are not similarity scores.',
    inputSchema: titleSchema, outputSchema: titleOutput,
    annotations: readOnly,
  }, query => result(() => title(query)));

  return server;
}, { onerror: () => console.error('MCP transport error. Check the client connection.') });
