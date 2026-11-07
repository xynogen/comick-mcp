import { z } from 'zod';
import { apiRequest } from './api.js';
import { ComickError } from './oauth.js';

const identifier = z.string().min(1).max(200).regex(/^[A-Za-z0-9_-]+$/);
const hid = identifier.max(64);
const mediaType = z.enum(['manga', 'anime']);
const label = z.string().trim().min(1).max(1000);
const externalIds = z.object({
  anilist: z.string().nullable(), myanimelist: z.string().nullable(),
  mangabaka: z.string().nullable(), mangaupdates: z.string().nullable(),
});
const titleMetadata = z.object({
  hid, slug: identifier, title: label, media_type: mediaType,
  description: z.string().nullable().optional(), year: z.number().int().nullable().optional(),
  status: z.number().int().min(1).max(4).nullable().optional(),
  bayesian_rating: z.number().min(0).max(10).nullable().optional(),
  cover_url: z.string().url().nullable().optional(), country: z.string().nullable().optional(),
  translation_status: z.enum(['ongoing', 'completed', 'dropped', 'inactive']).nullable().optional(),
  translation_completed: z.boolean().nullable().optional(),
  last_released_at: z.string().datetime({ offset: true }).nullable().optional(),
  last_released_number: z.string().nullable().optional(), total_units: z.number().int().nonnegative().nullable().optional(),
  titles: z.array(z.object({ title: label, lang: z.string().nullable(), is_default: z.boolean().optional() })).optional(),
  external_ids: externalIds.nullable().optional(), url: z.string().url().optional(),
});
const compactTitle = titleMetadata.pick({ hid: true, slug: true, title: true });
export const titleResult = z.union([titleMetadata, compactTitle.extend({ description: z.string().nullable().optional() })]);
export const searchSchema = z.object({
  query: z.string().trim().min(2).max(100).describe('Title or alternative-title keywords. OAuth login required.'),
  media_type: mediaType.default('manga'),
  limit: z.number().int().min(1).max(20).default(5),
  detailed: z.boolean().default(false).describe('Include the metadata supplied by the OAuth API.'),
}).strict();
export const searchOutput = z.object({
  items: z.array(titleResult).max(20), limit: z.number().int(), returned_count: z.number().int(),
});
export const titleSchema = z.object({
  hid: hid.describe('Title HID returned by comick_search, not a slug or chapter HID.'),
  detailed: z.boolean().default(false).describe('Include description, tracker IDs and other OAuth title metadata.'),
}).strict();

function parse<T>(schema: z.ZodType<T>, value: unknown): T {
  const parsed = schema.safeParse(value);
  if (!parsed.success) throw new ComickError('invalid_response', 'Comick returned invalid integration metadata.');
  return parsed.data;
}

export async function search(input: z.input<typeof searchSchema>) {
  const { query, media_type, limit, detailed } = searchSchema.parse(input);
  const response = parse(z.object({ data: z.array(titleMetadata).max(limit) }),
    await apiRequest('/titles', { query: { q: query, media_type, limit } }));
  if (response.data.some(item => item.media_type !== media_type)) throw new ComickError('invalid_response', 'Comick returned a different media type.');
  return { items: response.data.map(item => detailed ? item : compactTitle.parse(item)), limit, returned_count: response.data.length };
}

export async function title(input: z.input<typeof titleSchema>) {
  const { hid, detailed } = titleSchema.parse(input);
  const response = parse(z.object({ data: titleMetadata }), await apiRequest('/titles/' + encodeURIComponent(hid)));
  if (response.data.hid !== hid) throw new ComickError('invalid_response', 'Comick returned a different title identity.');
  return detailed ? response.data : { ...compactTitle.parse(response.data), description: response.data.description };
}

export const libraryEntrySchema = z.object({ hid, detailed: z.boolean().default(false) }).strict();
const progress = z.object({
  unit: z.enum(['chapter', 'episode']), hid: hid.nullable(), number: z.string().nullable(), volume: z.string().nullable(),
});
export const libraryEntryOutput = z.object({ data: z.object({
  hid, slug: identifier, title: label, media_type: mediaType,
  status: z.number().int().min(1).max(5),
  status_name: z.enum(['reading', 'watching', 'completed', 'on_hold', 'dropped', 'plan_to_read', 'plan_to_watch', 'unknown']),
  progress: progress.nullable(), continue_entry: progress.nullable(),
  rating: z.number().min(1).max(10).nullable(), bayesian_rating: z.number().min(0).max(10).nullable(),
  publication_status: z.number().int().min(1).max(4).nullable(),
  translation_completed: z.boolean().nullable(), last_released_number: z.string().nullable(),
  total_units: z.number().int().nonnegative().nullable(),
  followed_at: z.string().datetime({ offset: true }), updated_at: z.string().datetime({ offset: true }),
  progressed_at: z.string().datetime({ offset: true }).nullable(), last_released_at: z.string().datetime({ offset: true }).nullable(),
  cover_url: z.string().url().nullable().optional(), country: z.string().nullable().optional(),
  translation_status: z.enum(['ongoing', 'completed', 'dropped', 'inactive']).nullable().optional(),
  titles: z.array(z.object({ title: label, lang: z.string().nullable(), is_default: z.boolean().optional() })).optional(),
  url: z.string().url(),
}) });

function hasValidProgress(entry: z.infer<typeof libraryEntryOutput>['data']) {
  const unit = entry.media_type === 'manga' ? 'chapter' : 'episode';
  return [entry.progress, entry.continue_entry].every(value => value === null || value.unit === unit);
}
const compactEntry = libraryEntryOutput.shape.data.pick({
  hid: true, slug: true, title: true, media_type: true, status_name: true,
  progress: true, continue_entry: true, rating: true, last_released_number: true, total_units: true,
});
export const libraryEntryResult = z.object({ data: z.union([libraryEntryOutput.shape.data, compactEntry]) });
export const librarySchema = z.object({
  media_type: mediaType.optional(), status: z.number().int().min(1).max(5).optional(),
  limit: z.number().int().min(1).max(100).default(5),
  cursor: z.string().min(1).max(8192).nullish().describe('Omit or use null for the first page. For later pages, copy next_cursor from the previous response unchanged. Never invent a cursor.'),
  detailed: z.boolean().default(false).describe('Full row metadata; otherwise use comick_library_entry for one selected HID.'),
}).strict();
const libraryIndex = compactEntry.pick({ hid: true, slug: true, title: true, media_type: true, status_name: true, progress: true });
export const libraryOutput = z.object({
  data: z.array(z.union([libraryEntryOutput.shape.data, libraryIndex])).max(100), next_cursor: z.string().nullable(),
});
export async function library(input: z.input<typeof librarySchema>) {
  const { detailed, cursor, ...query } = librarySchema.parse(input);
  const response = parse(z.object({ data: z.array(libraryEntryOutput.shape.data).max(query.limit), next_cursor: z.string().nullable() }), await apiRequest('/me/library', { query: { ...query, cursor: cursor ?? undefined } }));
  if (response.data.some(item => !hasValidProgress(item))) {
    throw new ComickError('invalid_response', 'Comick returned progress for a different media type.');
  }
  if (response.data.some(item => (query.media_type !== undefined && item.media_type !== query.media_type)
    || (query.status !== undefined && item.status !== query.status))) {
    throw new ComickError('invalid_response', 'Comick returned library entries that do not match the requested filters.');
  }
  return parse(libraryOutput, { ...response, data: detailed ? response.data : response.data.map(item => libraryIndex.parse(item)) });
}
export const meSchema = z.object({ detailed: z.boolean().default(false) }).strict();
const profile = z.object({ id: z.string().uuid(), username: z.string().nullable(), avatar_url: z.string().url().nullable() });
export const meOutput = profile.omit({ avatar_url: true }).extend({ avatar_url: z.string().url().nullable().optional() });
export async function me(input: z.input<typeof meSchema>) {
  const { detailed } = meSchema.parse(input);
  const result = parse(profile, await apiRequest('/me'));
  return detailed ? result : { id: result.id, username: result.username };
}

export async function libraryEntry(input: z.input<typeof libraryEntrySchema>) {
  const { hid, detailed } = libraryEntrySchema.parse(input);
  let response: unknown;
  try { response = await apiRequest(`/me/library/${encodeURIComponent(hid)}`); }
  catch (error) {
    if (error instanceof ComickError && error.status === 404) {
      throw new ComickError('library_entry_not_found', 'No library entry was found for this HID, or the integration route is unavailable. This does not prove the title exists or is unfollowed.', 404);
    }
    throw error;
  }
  const result = parse(libraryEntryOutput, response);
  if (result.data.hid !== hid) throw new ComickError('invalid_response', 'Comick returned a different library title identity.');
  if (!hasValidProgress(result.data)) {
    throw new ComickError('invalid_response', 'Comick returned progress for a different media type.');
  }
  return { data: detailed ? result.data : compactEntry.parse(result.data) };
}

const progressWrite = z.object({
  hid: hid.optional().describe('Chapter/episode HID belonging to this title; do not combine with number or volume.'),
  number: z.string().min(1).optional().describe('Saved progress as a string, e.g. "0", "12.5", or "Special". Not a lookup identifier.'),
  volume: z.string().min(1).nullable().optional(),
}).strict().superRefine((value, context) => {
  if ((value.hid === undefined) === (value.number === undefined)) context.addIssue({
    code: 'custom', path: ['number'], message: 'Supply exactly one of progress.hid or progress.number.',
  });
  if (value.volume !== undefined && value.number === undefined) context.addIssue({
    code: 'custom', path: ['volume'], message: 'Use volume only with progress.number, not progress.hid.',
  });
});
export const librarySaveSchema = z.object({
  hid, action: z.enum(['upsert', 'update']).default('update'),
  status: libraryEntryOutput.shape.data.shape.status.optional().describe('1 reading/watching, 2 completed, 3 on hold, 4 dropped, 5 planned. Required for upsert.'),
  progress: progressWrite.nullable().optional().describe('Saved chapter/episode, not next unread. null clears progress; omit to preserve.'),
  rating: z.number().int().min(1).max(10).nullable().optional().describe('Personal series score; null clears it, omit to preserve.'),
  detailed: z.boolean().default(false),
}).strict().superRefine(({ hid: titleHid, action, detailed, ...body }, context) => {
  if (action === 'upsert' && body.status === undefined) context.addIssue({ code: 'custom', path: ['status'], message: 'Supply status for upsert; use 5 for a planned bookmark.' });
  if (Object.values(body).every(value => value === undefined)) context.addIssue({ code: 'custom', path: ['status'], message: 'Supply at least one of status, progress, or rating.' });
  if (Buffer.byteLength(JSON.stringify(body), 'utf8') > 4096) context.addIssue({ code: 'custom', path: ['progress'], message: 'Keep the JSON write body within 4096 UTF-8 bytes.' });
});
export async function librarySave(input: z.input<typeof librarySaveSchema>) {
  const { hid, action, detailed, ...body } = librarySaveSchema.parse(input);
  const raw = await apiRequest(`/me/library/${encodeURIComponent(hid)}`, { method: action === 'upsert' ? 'PUT' : 'PATCH', body });
  const response = libraryEntryOutput.safeParse(raw);
  if (!response.success || response.data.data.hid !== hid || !hasValidProgress(response.data.data)) {
    throw new ComickError('write_outcome_unknown', 'The library write returned success but unverified entry data. Read the entry before retrying; do not assume no change.');
  }
  return { data: detailed ? response.data.data : compactEntry.parse(response.data.data) };
}
export const libraryRemoveSchema = z.object({
  hid, confirm: z.literal(true).describe('Set true only after the user explicitly requests unfollowing and understands saved progress, notes, rating, and custom-list memberships are deleted.'),
}).strict();
export const libraryRemoveOutput = z.object({ hid, status: z.literal('removed_or_already_absent') });
export async function libraryRemove(input: z.input<typeof libraryRemoveSchema>) {
  const { hid } = libraryRemoveSchema.parse(input);
  await apiRequest(`/me/library/${encodeURIComponent(hid)}`, { method: 'DELETE' });
  return libraryRemoveOutput.parse({ hid, status: 'removed_or_already_absent' });
}
