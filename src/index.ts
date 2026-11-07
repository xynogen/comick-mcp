#!/usr/bin/env node
import { McpServer } from '@modelcontextprotocol/server';
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import { z } from 'zod';
import { ComickError, connect, disconnect, disconnectOutput } from './oauth.js';
import { chapters, chaptersOutput, chaptersSchema, filters, filtersOutput, filtersSchema, library, libraryOutput, librarySchema, libraryEntry, libraryEntryResult, libraryEntrySchema, me, meOutput, meSchema, search, searchOutput, searchSchema, title, titleResult, titleSchema } from './catalog.js';
import { scanlations, scanlationsOutput, scanlationsSchema, librarySave, librarySaveSchema, libraryRemove, libraryRemoveSchema, libraryRemoveOutput } from './catalog.js';
import { chapterDetail, chapterDetailSchema, chapterDetailOutput, chapterImages, chapterImagesSchema, chapterImagesOutput } from './catalog.js';

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
        recommendation: issue.code === 'unrecognized_keys' ? 'Remove parameters not listed in the tool input schema.'
          : issue.code === 'custom' ? `Adjust this parameter to satisfy: ${issue.message}`
          : field?.type === 'integer' || field?.type === 'number' ? `Set ${issue.path.join('.')} to a JSON ${field.type}${field.minimum !== undefined ? ` >= ${field.minimum}` : ''}${field.maximum !== undefined ? ` and <= ${field.maximum}` : ''}; use an unquoted number, not a string${nullable ? '; null clears this field' : ' or null'}.`
          : issue.code === 'invalid_type' ? `Send a JSON ${issue.expected}; do not quote numbers or booleans, or send a scalar instead of an array.`
          : issue.code === 'invalid_value' ? `Use one of these allowed values: ${issue.values.map(value => JSON.stringify(value)).join(', ')}.`
          : issue.code === 'invalid_format' && ['hid', 'slug'].includes(String(issue.path.at(-1))) ? 'Use the exact HID or slug returned by comick_search, not a URL or path.'
          : issue.code === 'invalid_format' && issue.path[0] === 'lang' ? 'Use language codes such as en, id, pt-br, or en,id; not language names.'
          : `Adjust this parameter to satisfy: ${issue.message}`,
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
  credentials_busy: 'Wait for the current login or refresh to finish, then retry sequentially. Do not start another login or delete an active lock.',
  rate_limited: 'Wait for retry_after when provided; otherwise back off before retrying. Do not retry in parallel.',
  network_error: 'Retry with backoff. If it persists, check connectivity; do not reconnect solely for a network failure.',
  reconnect_required: 'Use comick_connect to reconnect with user consent, then retry. Never resend old authorization codes or refresh tokens.',
  configuration_required: 'Configure COMICK_CLIENT_ID and the registered COMICK_REDIRECT_URI on the server; do not pass credentials as tool parameters.',
  invalid_response: 'The upstream response is invalid. Do not change valid parameters or assume an empty result; retry later.',
  write_permission_required: 'Enable library writes in the Comick app settings, then use comick_connect to reconnect and explicitly allow writes. Existing read-only tokens cannot gain writes by refreshing.',
  write_outcome_unknown: 'Read comick_library_entry for this HID before any retry. The write may already have applied; never claim it failed without changing data. Avoid concurrent writers.',
  scanlations_unavailable: 'Use a web search for the title and scanlation groups, then verify publisher or group pages. Do not fabricate group names, reading links, or treat blocked metadata as no releases.',
};

async function result(request: () => Promise<unknown>) {
  try {
    const value = await request();
    const structuredContent = value as Record<string, unknown>;
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

  server.registerTool('comick_chapters', {
    description: 'List 5 chapter releases per page; entry_type=episode selects anime episodes. Newest-created first, not highest number or next unread. detailed=true adds volume, dates and group names. lang accepts en,id or pt-br. Exact slug adds Comick chapter page URLs for manga only: these are tracking/navigation pages, not verified external reading links. Episodes have no video or reader images. Same-number releases remain distinct.',
    inputSchema: checkedInput(chaptersSchema), outputSchema: chaptersOutput, annotations: readOnly,
  }, query => result(() => chapters(query)));

  server.registerTool('comick_chapter', {
    description: 'Read one chapter/episode HID: parent title, number, language, credits, next/previous pointers, external reference and title-level source links supplied by Comick. External URLs are returned only when the API supplies an HTTP(S) URL; names, slugs and storage keys are never converted into reading links. Availability and access are not verified. image_count=null means unknown/not applicable; zero means no image records in this response. No account or progress changes.',
    inputSchema: checkedInput(chapterDetailSchema), outputSchema: chapterDetailOutput, annotations: readOnly,
  }, query => result(() => chapterDetail(query)));

  server.registerTool('comick_chapter_images', {
    description: 'Read image metadata from the official chapter get_images endpoint, not image bytes or a download archive. Returns 5 records by default, maximum 50; offset/next_offset slice the full upstream response locally, not upstream pagination. Returns storage keys/dimensions and an HTTP(S) URL only if supplied; never invents CDN URLs. Empty arrays do not prove a reading source is unavailable elsewhere. Episodes have no reader images. No account or progress changes.',
    inputSchema: checkedInput(chapterImagesSchema), outputSchema: chapterImagesOutput, annotations: readOnly,
  }, query => result(() => chapterImages(query)));

  server.registerTool('comick_scanlations', {
    description: 'Read credited scanlation groups directly from the Comick chapter API across N newest-created releases (default 10, maximum 50). Returns group slugs, official/inactive flags when available, counts, languages and latest sampled release. Not highest chapter order; no external reading URLs. Blocked API access returns an error, never an empty list.',
    inputSchema: checkedInput(scanlationsSchema), outputSchema: scanlationsOutput, annotations: readOnly,
  }, query => result(() => scanlations(query)));

  server.registerTool('comick_search', {
    description: 'Find titles with query, for example {"query":"One Piece"}. Returns 5 titles with HID and slug by default; detailed=true adds metadata and external tracker IDs when available. Omit query to browse by genre/tag filters. For similar works, use genre/tag slugs and exclude the source HID from results; site ratings are not similarity scores. Use comick_title for selected details. One page, no total.',
    inputSchema: checkedInput(searchSchema),
    outputSchema: searchOutput,
    annotations: readOnly,
  }, query => result(() => search(query)));

  server.registerTool('comick_filters', {
    description: 'Find genre/theme/format or tag slugs for search. Match query against name/slug, or omit it to browse 5 per page. Use total and has_more for paging; no login.',
    inputSchema: checkedInput(filtersSchema),
    outputSchema: filtersOutput,
    annotations: readOnly,
  }, query => result(() => filters(query)));

  server.registerTool('comick_title', {
    description: 'Read one title: synopsis, reusable genre/tag slugs and up to 5 community recommendations. source identifies the main data source; partial flags fallback or missing metadata. missing_fields distinguishes unavailable data from known empty arrays. detailed=true adds full metadata, external_ids for tracker matching (null if unavailable) and recommendations. Supply slug and HID from search for authenticated fallback. Recommendations are not similarity scores.',
    inputSchema: checkedInput(titleSchema), outputSchema: titleResult,
    annotations: readOnly,
  }, query => result(() => title(query)));

  return server;
}, { onerror: () => console.error('MCP transport error. Check the client connection.') });
