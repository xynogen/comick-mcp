import { McpServer } from '@modelcontextprotocol/server';
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import { z } from 'zod';
import { apiGet } from './oauth.js';

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
  server.registerTool('comick_me', {
    description: 'Read the connected Comick public profile. Login is performed separately with npm run login; never supply passwords, cookies or tokens to this tool.',
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

  return server;
}, { onerror: () => console.error('MCP transport error. Check the client connection.') });
