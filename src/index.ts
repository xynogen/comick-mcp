#!/usr/bin/env node
import { McpServer } from '@modelcontextprotocol/server';
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import { z } from 'zod';
import { ComickError, connect, disconnect, disconnectOutput } from './oauth.js';
import { chapters, chaptersOutput, chaptersSchema, filters, filtersOutput, filtersSchema, library, libraryOutput, librarySchema, libraryEntry, libraryEntryResult, libraryEntrySchema, me, meOutput, meSchema, search, searchOutput, searchSchema, title, titleResult, titleSchema } from './catalog.js';

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
    description: 'Read connected account ID and username. detailed=true also returns the avatar URL. Login through comick_connect; never supply passwords or tokens.',
    inputSchema: meSchema, outputSchema: meOutput,
    annotations: readOnly,
  }, query => result(() => me(query)));

  server.registerTool('comick_library', {
    description: 'Read a small library index (5 rows): identity, status and saved progress. Fetch comick_library_entry by HID for selected details, or detailed=true for full rows. Pass next_cursor unchanged with the same filters; null ends paging. Status: 1 reading/watching, 2 completed, 3 on hold, 4 dropped, 5 planned.',
    inputSchema: librarySchema, outputSchema: libraryOutput,
    annotations: readOnly,
  }, query => result(() => library(query)));

  server.registerTool('comick_library_entry', {
    description: 'Read one library title HID: saved progress, Continue entry, status and personal rating. detailed=true adds dates and full row metadata. Progress numbers remain strings, not the next unread chapter. A 404 does not prove the title exists or is unfollowed. No write or library scan.',
    inputSchema: libraryEntrySchema, outputSchema: libraryEntryResult, annotations: readOnly,
  }, query => result(() => libraryEntry(query)));

  server.registerTool('comick_chapters', {
    description: 'Read 5 manga chapters per page, newest-created first (not highest number): HID, number, title, language and reader URL. detailed=true adds volume, dates and groups. Supply exact title slug for links; lang accepts en,id or pt-br. Same-number releases remain distinct. Not an unread list or final chapter count.',
    inputSchema: chaptersSchema, outputSchema: chaptersOutput, annotations: readOnly,
  }, query => result(() => chapters(query)));

  server.registerTool('comick_search', {
    description: 'Find titles with a small index: HID, slug and name only (5 by default). Fetch comick_title for a selected slug and HID to read genres, synopsis and related works. detailed=true expands every search result; avoid unless needed. One page, no total.',
    inputSchema: searchSchema,
    outputSchema: searchOutput,
    annotations: readOnly,
  }, query => result(() => search(query)));

  server.registerTool('comick_filters', {
    description: 'Find valid genre/theme/format or tag slugs for search. Match q against name/slug, or browse 5 per page. Use total and has_more to request more pages; no login.',
    inputSchema: filtersSchema,
    outputSchema: filtersOutput,
    annotations: readOnly,
  }, query => result(() => filters(query)));

  server.registerTool('comick_title', {
    description: 'Read one selected title: short synopsis, genres/tags and up to 5 related works. Empty fields are omitted; partial/warnings flag unavailable public data. detailed=true returns full metadata and all available related works/alternative titles; increase synopsis_limit for more text. Supply slug and HID from search for authenticated fallback. Community recommendations are not similarity scores.',
    inputSchema: titleSchema, outputSchema: titleResult,
    annotations: readOnly,
  }, query => result(() => title(query)));

  return server;
}, { onerror: () => console.error('MCP transport error. Check the client connection.') });
