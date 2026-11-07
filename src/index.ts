#!/usr/bin/env node
import { McpServer } from '@modelcontextprotocol/server';
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import { z } from 'zod';
import { ComickError, connect, disconnect, disconnectOutput } from './oauth.js';
import { library, libraryOutput, librarySchema, libraryEntry, libraryEntryResult, libraryEntrySchema, me, meOutput, meSchema, search, searchOutput, searchSchema, title, titleResult, titleSchema, librarySave, librarySaveSchema, libraryRemove, libraryRemoveSchema, libraryRemoveOutput } from './integration.js';

const readOnly = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true };

function invalidInput(error: z.ZodError, schema?: z.core.JSONSchema.JSONSchema) {
  return {
    code: 'invalid_input',
    message: 'Correct the listed parameters before calling this tool again. No request was executed.',
    retryable: false,
    issues: error.issues.slice(0, 10).map(issue => {
      let field = schema;
      for (const key of issue.path) {
        field = field?.anyOf?.find(option => typeof option === 'object' && option.type !== 'null') as typeof field ?? field;
        const child = typeof key === 'number' ? field?.items : field?.properties?.[String(key)];
        field = child && typeof child === 'object' && !Array.isArray(child) ? child : undefined;
      }
      const nullable = field?.anyOf?.some(option => typeof option === 'object' && option.type === 'null');
      field = field?.anyOf?.find(option => typeof option === 'object' && option.type !== 'null') as typeof field ?? field;
      const expected = field ? Object.fromEntries(Object.entries(field).filter(([key]) =>
        ['type', 'minimum', 'maximum', 'exclusiveMinimum', 'exclusiveMaximum', 'minLength', 'maxLength', 'minItems', 'maxItems', 'pattern', 'enum', 'const', 'items'].includes(key)).concat(nullable ? [['nullable', true]] : [])) : undefined;
      return {
        path: issue.path, code: issue.code, expected,
        message: issue.code === 'unrecognized_keys' ? 'Unknown parameters are not allowed.' : issue.message,
        recommendation: issue.code === 'unrecognized_keys'
          ? 'Remove parameters not listed in the tool input schema.'
          : `Use the listed constraints and tool input schema to correct this parameter: ${issue.message}`,
      };
    }),
    issues_truncated: error.issues.length > 10,
  };
}

function checkedInput<T extends z.ZodType>(schema: T) {
  const jsonSchema = z.toJSONSchema(schema, { io: 'input' });
  return {
    '~standard': {
      ...schema['~standard'],
      validate(value: unknown) {
        const parsed = schema.safeParse(value);
        // SDK validates before handlers; throw JSON here so invalid calls get actionable errors too.
        if (!parsed.success) throw new Error(JSON.stringify({ error: invalidInput(parsed.error, jsonSchema) }));
        return { value: parsed.data };
      },
    },
  };
}

const recovery: Record<string, string> = {
  credentials_busy: 'Wait for current credential access or login to finish, then retry. If queue waits persist, reduce concurrency or adjust COMICK_TOKEN_QUEUE_TIMEOUT_MS. Do not delete an active lock.',
  rate_limited: 'Wait for retry_after when provided; otherwise back off before retrying. Do not retry in parallel.',
  network_error: 'Retry with backoff. If it persists, check connectivity; do not reconnect solely for a network failure.',
  reconnect_required: 'Use comick_connect to reconnect with user consent, then retry. Never resend old authorization codes or refresh tokens.',
  configuration_required: 'Configure COMICK_CLIENT_ID and the registered COMICK_REDIRECT_URI on the server; do not pass credentials as tool parameters.',
  invalid_response: 'The upstream response is invalid. Do not change valid parameters or assume an empty result; retry later.',
  write_permission_required: 'Enable library writes in the Comick app settings, then use comick_connect to reconnect and explicitly allow writes. Existing read-only tokens cannot gain writes by refreshing.',
  write_outcome_unknown: 'Read comick_library_entry for this HID before any retry. The write may already have applied; never claim it failed without changing data. Avoid concurrent writers.',
};

async function result(request: () => Promise<Record<string, unknown>>) {
  try {
    const value = await request();
    const structuredContent = value;
    return { structuredContent, content: [{ type: 'text' as const, text: JSON.stringify(value) }] };
  } catch (error) {
    const failure = error instanceof ComickError ? { code: error.code, message: error.message, status: error.status, retry_after: error.retryAfter,
      recommendation: recovery[error.code] ?? 'Follow the error message and check service availability before retrying; do not repeat the same failing call in a loop.' }
      : error instanceof z.ZodError ? invalidInput(error)
      : { code: 'request_failed', message: 'Comick request failed.', recommendation: 'Check server configuration and connection. Do not reconnect or repeat the call blindly.' };
    return { isError: true, content: [{ type: 'text' as const, text: JSON.stringify({ error: failure }) }] };
  }
}

serveStdio(() => {
  const server = new McpServer({ name: 'comick-mcp', version: '0.1.0' });
  server.registerTool('comick_connect', {
    description: 'Connect to Comick using OAuth PKCE; requests library:read, optional library:write and offline_access. Enable writes in app settings first; each user must explicitly allow writes. Declining writes keeps read-only access. Existing tokens need a new consent flow for writes. Requires COMICK_CLIENT_ID, registered loopback callback and OS credential store. Start once, open authorization_url on the server machine, consent, then check status. Tokens never appear in results. Does not authenticate MCP transport.',
    inputSchema: checkedInput(z.object({
      action: z.enum(['start', 'status']).default('start'),
      open_browser: z.boolean().default(true).describe('Try the Linux system browser. If false, open the returned authorization_url manually.'),
    }).strict()),
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
  }, ({ action, open_browser }) => result(() => connect(action, open_browser)));

  server.registerTool('comick_disconnect', {
    description: 'Disconnect Comick after the user requests it: revoke stored access and refresh tokens, then delete local OS credentials. Warnings distinguish local deletion from incomplete server revocation. Does not remove all app consent; use Comick Connected apps for that.',
    inputSchema: checkedInput(z.object({}).strict()), outputSchema: disconnectOutput,
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
  }, () => result(disconnect));

  server.registerTool('comick_me', {
    description: 'Read connected account ID and username. detailed=true also returns the avatar URL. Login through comick_connect; never supply passwords or tokens.',
    inputSchema: checkedInput(meSchema), outputSchema: meOutput,
    annotations: readOnly,
  }, query => result(() => me(query)));

  server.registerTool('comick_library', {
    description: 'List your library. Call {} for the first 5 entries, with no status filter. Omit cursor on the first call; copy next_cursor unchanged for later pages and stop when null. detailed=true adds full metadata. Status: 1 reading/watching, 2 completed, 3 on hold, 4 dropped, 5 planned.',
    inputSchema: checkedInput(librarySchema), outputSchema: libraryOutput,
    annotations: readOnly,
  }, query => result(() => library(query)));

  server.registerTool('comick_library_entry', {
    description: 'Read one library title HID: saved progress, Continue entry, status and personal rating. detailed=true adds dates and full row metadata. Progress numbers remain strings, not the next unread chapter. A 404 does not prove the title exists or is unfollowed. No write or library scan.',
    inputSchema: checkedInput(libraryEntrySchema), outputSchema: libraryEntryResult, annotations: readOnly,
  }, query => result(() => libraryEntry(query)));

  server.registerTool('comick_library_save', {
    description: 'Save the user-requested manga/anime follow, status, progress or personal rating; requires granted library:write. action=update (default) patches an existing entry and returns 404 if absent; upsert adds/updates and requires status (5 planned/bookmark, 1 reading/watching, 2 completed, 3 on hold, 4 dropped). Omitted fields stay unchanged; progress:null or rating:null clears only that field. Progress accepts either a chapter/episode HID or string number with optional volume; never infer completion or advance automatically. Can intentionally decrease progress. Last accepted update wins: avoid parallel writes; on an unknown outcome read the entry before retrying. Returns the saved entry, detailed=true adds timestamps.',
    inputSchema: checkedInput(librarySaveSchema), outputSchema: libraryEntryResult,
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
  }, query => result(() => librarySave(query)));

  server.registerTool('comick_library_remove', {
    description: 'Unfollow a manga/anime only when explicitly requested. Deletes saved progress, notes, rating and custom-list memberships; written reviews remain. Requires library:write and confirm:true after the user understands the deletion. Repeat removal is safe; 204 confirms removed or already absent. Does not delete the catalog title.',
    inputSchema: checkedInput(libraryRemoveSchema), outputSchema: libraryRemoveOutput,
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
  }, query => result(() => libraryRemove(query)));

  server.registerTool('comick_search', {
    description: 'Search titles and alternative titles through OAuth. Requires login and library:read. Supply query (2–100 characters); returns 5 HID/slug/title results by default, maximum 20. detailed=true adds metadata and external tracker IDs. No genre/group filters or pagination; refine query for more results.',
    inputSchema: checkedInput(searchSchema),
    outputSchema: searchOutput,
    annotations: readOnly,
  }, query => result(() => search(query)));

  server.registerTool('comick_title', {
    description: 'Read title metadata through OAuth using a title HID from comick_search. Requires library:read. detailed=true adds all supported metadata, including external tracker IDs. Does not provide chapters, images, scanlation groups or recommendations.',
    inputSchema: checkedInput(titleSchema), outputSchema: titleResult,
    annotations: readOnly,
  }, query => result(() => title(query)));

  return server;
}, { onerror: () => console.error('MCP transport error. Check the client connection.') });
