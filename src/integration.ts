import { z } from 'zod';
import { apiRequest } from './api.js';
import { ComickError } from './oauth.js';

const identifier = z.string().min(1).max(200).regex(/^[A-Za-z0-9_-]+$/);
const hid = identifier.max(64);
const mediaType = z.enum(['manga', 'anime']);
const label = z.string().trim().min(1).max(1000);
const rating = z.union([z.number(), z.string().regex(/^\d+(?:\.\d+)?$/).transform(Number)]).pipe(z.number().min(0).max(10)).nullable();
const catalogItem = z.object({
  hid, slug: identifier, title: label, bayesian_rating: rating.optional(), rating: rating.optional(),
  rating_count: z.number().int().nonnegative().nullable().optional(),
});
const summary = z.object({
  hid, slug: identifier, title: label, community_rating: z.number().min(0).max(10).nullable(),
  rating_count: z.number().int().nonnegative().nullable(), url: z.string().url(),
});
function summarize(item: z.infer<typeof catalogItem>) {
  return { hid: item.hid, slug: item.slug, title: item.title, community_rating: item.bayesian_rating ?? item.rating ?? null,
    rating_count: item.rating_count ?? null, url: `https://comick.dev/comic/${item.slug}` };
}
const tagSlug = z.string().min(1).max(200).regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/);
const category = z.object({ title: label, slug: tagSlug, comic_count: z.number().int().nonnegative().nullable() });
const detailLimit = z.union([z.literal(-1), z.number().int().min(1).max(100)]).default(5).describe('Default 5 per list; -1 returns all only when explicitly requested.');
export const tagsSchema = z.object({ query: z.string().trim().min(1).max(100), limit: detailLimit }).strict();
export const tagsOutput = z.object({ tags: z.array(z.object({ name: label, slug: tagSlug, comic_count: z.number().int().nonnegative().nullable() })), matched_count: z.number().int() });
export async function tags(input: z.input<typeof tagsSchema>) {
  const { query, limit } = tagsSchema.parse(input);
  const categories = parse(z.array(category), await apiRequest('/category/', { catalog: true }));
  const text = query.toLowerCase();
  const matches = categories.filter(item => item.title.toLowerCase().includes(text) || item.slug.includes(text))
    .sort((a, b) => Number(b.slug === text || b.title.toLowerCase() === text) - Number(a.slug === text || a.title.toLowerCase() === text) || (b.comic_count ?? -1) - (a.comic_count ?? -1));
  return { tags: matches.slice(0, limit === -1 ? undefined : limit).map(item => ({ name: item.title, slug: item.slug, comic_count: item.comic_count })), matched_count: matches.length };
}
export const searchSchema = z.object({
  query: z.string().trim().min(2).max(100).optional(),
  tags: z.array(tagSlug).max(10).default([]).describe('Exact slugs from comick_tags or comick_title; all included tags must match (AND).'),
  excluded_tags: z.array(tagSlug).max(30).default([]),
  media_type: mediaType.default('manga'), page: z.number().int().min(1).max(50).default(1),
  limit: z.number().int().min(1).max(20).default(5),
  sort: z.enum(['created_at', 'rating', 'follow', 'uploaded']).default('rating'),
}).strict().superRefine((value, context) => {
  if (!value.query && !value.tags.length) context.addIssue({ code: 'custom', path: ['query'], message: 'Supply query or at least one tag slug.' });
  if (value.tags.some(tag => value.excluded_tags.includes(tag))) context.addIssue({ code: 'custom', path: ['excluded_tags'], message: 'A tag cannot be included and excluded.' });
});
export const searchOutput = z.object({ items: z.array(summary).max(20), page: z.number().int(), limit: z.number().int(), returned_count: z.number().int() });
export async function search(input: z.input<typeof searchSchema>) {
  const { query, tags, excluded_tags, ...filters } = searchSchema.parse(input);
  const response = parse(z.array(catalogItem).max(filters.limit), await apiRequest('/v1.0/search/', { catalog: true,
    query: { ...filters, q: query, tags, 'excluded-tags': excluded_tags } }));
  return { items: response.map(summarize), page: filters.page, limit: filters.limit, returned_count: response.length };
}
const comicMetadata = catalogItem.extend({
  desc: z.string().nullable(), media_type: mediaType, year: z.number().int().nullable(), status: z.number().int().min(1).max(4).nullable(),
  mu_comic_categories: z.array(z.object({ mu_categories: category.omit({ comic_count: true }), score: z.number().nullable().optional() })),
  md_comic_md_genres: z.array(z.object({ md_genres: z.object({ name: label, slug: tagSlug, group: z.string().nullable() }) })),
});
export const titleSchema = z.object({ slug: identifier.describe('Exact comic slug returned by comick_search, not a chapter HID.'), limit: detailLimit }).strict();
export const titleResult = summary.extend({
  synopsis: z.string().nullable(), media_type: mediaType, year: z.number().int().nullable(), status: z.number().int().nullable(),
  tags: z.array(z.object({ name: label, slug: tagSlug, score: z.number().nullable() })),
  genres: z.array(z.object({ name: label, slug: tagSlug, group: z.string().nullable() })),
  tag_count: z.number().int().nonnegative(), genre_count: z.number().int().nonnegative(),
});
async function catalogComic(slug: string) {
  const response = parse(z.object({ comic: comicMetadata }), await apiRequest(`/v1.0/comic/${encodeURIComponent(slug)}/`, { catalog: true }));
  if (response.comic.slug !== slug) throw new ComickError('invalid_response', 'Comick returned a different comic slug.');
  return response.comic;
}
export async function title(input: z.input<typeof titleSchema>) {
  const { slug, limit } = titleSchema.parse(input);
  const comic = await catalogComic(slug);
  return { ...summarize(comic), synopsis: comic.desc, media_type: comic.media_type, year: comic.year, status: comic.status,
    tag_count: comic.mu_comic_categories.length, genre_count: comic.md_comic_md_genres.length,
    tags: comic.mu_comic_categories.slice(0, limit === -1 ? undefined : limit).map(item => ({ name: item.mu_categories.title, slug: item.mu_categories.slug, score: item.score ?? null })),
    genres: comic.md_comic_md_genres.slice(0, limit === -1 ? undefined : limit).map(item => item.md_genres) };
}
const httpUrl = z.string().url().refine(value => ['https:', 'http:'].includes(new URL(value).protocol), 'Expected an HTTP(S) URL.');
const sourceLink = z.union([httpUrl, z.object({ url: httpUrl, lang: z.string().nullable().optional() })]);
const readingMetadata = z.object({ comic: z.object({ hid, slug: identifier, links: z.object({
  raw: httpUrl.nullish(), engtl: httpUrl.nullish(), othertl: httpUrl.nullish(),
  urls: z.object({ raw: z.array(sourceLink).optional(), engtl: z.array(sourceLink).optional(), othertl: z.array(sourceLink).optional() }).nullish(),
}).nullish() }) });
export const sourcesSchema = titleSchema.extend({ language: z.string().regex(/^[a-z]{2,3}(?:-[a-z]{2,4})?$/).default('en') }).strict();
export const sourcesOutput = z.object({
  slug: identifier, url: httpUrl, language: z.string(), scope: z.literal('sources_indexed_by_comick'),
  reading_links: z.array(z.object({ url: httpUrl, language: z.string().nullable(), kind: z.enum(['original', 'official_translation']) })),
  groups: z.array(z.object({ title: label, slug: identifier, official: z.boolean(), count: z.number().int().nonnegative() })),
  reading_link_count: z.number().int().nonnegative(), group_count: z.number().int().nonnegative(),
});
export async function sources(input: z.input<typeof sourcesSchema>) {
  const { slug, language, limit } = sourcesSchema.parse(input);
  const { comic } = parse(readingMetadata, await apiRequest(`/v1.0/comic/${encodeURIComponent(slug)}/`, { catalog: true }));
  if (comic.slug !== slug) throw new ComickError('invalid_response', 'Comick returned a different comic slug.');
  const groups = parse(z.object({ groups: sourcesOutput.shape.groups }), await apiRequest(`/v1.0/comic/${encodeURIComponent(comic.hid)}/chapters`,
    { catalog: true, query: { lang: language, groups: 1 } }));
  const reading_links: z.infer<typeof sourcesOutput>['reading_links'] = [];
  for (const key of ['raw', 'engtl', 'othertl'] as const) {
    const values = comic.links?.urls?.[key] ?? (comic.links?.[key] ? [comic.links[key]] : []);
    for (const value of values) {
      const link = typeof value === 'string' ? { url: value, lang: key === 'engtl' ? 'en' : null } : value;
      if (key !== 'raw' && link.lang && link.lang !== language) continue;
      if (!reading_links.some(item => item.url === link.url)) reading_links.push({ url: link.url, language: link.lang ?? null, kind: key === 'raw' ? 'original' : 'official_translation' });
    }
  }
  return { slug, url: `https://comick.dev/comic/${slug}`, language, scope: 'sources_indexed_by_comick' as const,
    reading_link_count: reading_links.length, group_count: groups.groups.length,
    reading_links: reading_links.slice(0, limit === -1 ? undefined : limit), groups: groups.groups.slice(0, limit === -1 ? undefined : limit) };
}
const review = z.object({
  title: z.string().nullable(), content: z.string(), rating,
  created_at: z.string().datetime({ offset: true }), updated_at: z.string().datetime({ offset: true }).nullable(),
  identities: z.object({ traits: z.object({ username: z.string().nullable().optional() }).nullish() }).nullish(),
});
export const readReviewSchema = z.object({
  slug: identifier, media_type: mediaType.default('manga'),
  offset: z.number().int().min(0).max(100000).default(0), limit: z.union([z.literal(-1), z.number().int().min(1).max(20)]).default(5),
}).strict();
export const readReviewOutput = z.object({
  slug: identifier, media_type: mediaType, review_count: z.number().int().nonnegative().nullable(),
  available_count: z.number().int().nonnegative(), offset: z.number().int(), returned_count: z.number().int(), next_offset: z.number().int().nullable(),
  scope: z.literal('reviews_returned_by_comick'),
  reviews: z.array(review.omit({ identities: true }).extend({ author: z.string().nullable() })),
});
export async function readReview(input: z.input<typeof readReviewSchema>) {
  const { slug, media_type, offset, limit } = readReviewSchema.parse(input);
  const { comic } = parse(z.object({ comic: z.object({ slug: identifier, media_type: mediaType,
    review_count: z.number().int().nonnegative().nullable(), reviews: z.array(review) }) }),
    await apiRequest(`/v1.0/comic/${encodeURIComponent(slug)}/`, { catalog: true, query: { media_type } }));
  if (comic.slug !== slug || comic.media_type !== media_type) throw new ComickError('invalid_response', 'Comick returned a different title or media type.');
  const reviews = comic.reviews.slice(offset, limit === -1 ? undefined : offset + limit).map(({ identities, ...item }) => ({ ...item, author: identities?.traits?.username ?? null }));
  return { slug, media_type, review_count: comic.review_count, available_count: comic.reviews.length, offset, returned_count: reviews.length,
    next_offset: offset + reviews.length < comic.reviews.length ? offset + reviews.length : null, scope: 'reviews_returned_by_comick' as const, reviews };
}
const weekday = z.enum(['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday']);
const timezone = z.string().min(1).max(100).refine(value => {
  try { new Intl.DateTimeFormat('en', { timeZone: value }); return true; } catch { return false; }
}, 'Use a valid IANA time zone such as Asia/Jakarta.');
export const animeScheduleSchema = z.object({
  day: z.enum(['today', 'all', ...weekday.options]).default('today').describe('Default today in the requested timezone. Use all explicitly for the whole schedule.'),
  timezone: timezone.default(() => Intl.DateTimeFormat().resolvedOptions().timeZone), query: z.string().trim().min(1).max(100).optional(),
  offset: z.number().int().min(0).max(100000).default(0),
  limit: z.union([z.literal(-1), z.number().int().min(1).max(100)]).default(5).describe('Default 5; -1 returns all matching entries after offset, without removing day/query filters.'),
}).strict();
const scheduleEntry = catalogItem.extend({ schedule: z.object({
  broadcast: z.string(), jstWeekday: weekday, jstTime: z.string().regex(/^\d{2}:\d{2}$/),
  occurrenceAt: z.string().datetime({ offset: true }),
}) });
export const animeScheduleOutput = z.object({
  year: z.number().int(), season: z.string(), generated_at: z.string().datetime({ offset: true }), timezone: z.string(),
  scope: z.literal('current_season_broadcast_metadata'), matched_count: z.number().int(), offset: z.number().int(),
  returned_count: z.number().int(), next_offset: z.number().int().nullable(),
  entries: z.array(summary.omit({ url: true }).extend({
    broadcast: z.string(), jst_weekday: weekday, jst_time: z.string(), occurrence_at: z.string().datetime({ offset: true }),
    local_weekday: weekday, local_time: z.string(),
  })),
});
export async function animeSchedule(input: z.input<typeof animeScheduleSchema>) {
  const { day, timezone, query, offset, limit } = animeScheduleSchema.parse(input);
  const response = parse(z.object({ year: z.number().int(), season: z.string(), generatedAt: z.string().datetime({ offset: true }), entries: z.array(scheduleEntry) }),
    await apiRequest('/anime/schedule', { catalog: true }));
  const dayFormat = new Intl.DateTimeFormat('en-US', { timeZone: timezone, weekday: 'long' });
  const timeFormat = new Intl.DateTimeFormat('en-GB', { timeZone: timezone, year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hourCycle: 'h23' });
  const dateFormat = new Intl.DateTimeFormat('en-CA', { timeZone: timezone, year: 'numeric', month: '2-digit', day: '2-digit' });
  const today = dateFormat.format(Date.now());
  const entries = response.entries.map(item => {
    const { url: _url, ...metadata } = summarize(item);
    const at = new Date(item.schedule.occurrenceAt);
    return { ...metadata, broadcast: item.schedule.broadcast, jst_weekday: item.schedule.jstWeekday, jst_time: item.schedule.jstTime,
      occurrence_at: item.schedule.occurrenceAt, local_weekday: weekday.parse(dayFormat.format(at).toLowerCase()), local_time: timeFormat.format(at) };
  }).filter(item => (day === 'all' || (day === 'today' ? dateFormat.format(new Date(item.occurrence_at)) === today : item.local_weekday === day))
    && (!query || item.title.toLowerCase().includes(query.toLowerCase()) || item.slug.toLowerCase().includes(query.toLowerCase())))
    .sort((a, b) => a.occurrence_at.localeCompare(b.occurrence_at) || a.slug.localeCompare(b.slug));
  const page = entries.slice(offset, limit === -1 ? undefined : offset + limit);
  return { year: response.year, season: response.season, generated_at: response.generatedAt, timezone, scope: 'current_season_broadcast_metadata' as const,
    matched_count: entries.length, offset, returned_count: page.length, next_offset: offset + page.length < entries.length ? offset + page.length : null, entries: page };
}

function parse<T>(schema: z.ZodType<T>, value: unknown): T {
  const parsed = schema.safeParse(value);
  if (!parsed.success) throw new ComickError('invalid_response', 'Comick returned invalid metadata.');
  return parsed.data;
}
const libraryEntrySchema = z.object({ hid, detailed: z.boolean().default(false) }).strict();
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
const statusCode = { reading: 1, completed: 2, on_hold: 3, dropped: 4, planned: 5 } as const;
const libraryStatus = z.enum(['reading', 'completed', 'on_hold', 'dropped', 'planned']);
export const librarySchema = z.object({
  hid: hid.optional().describe('Read one entry. Do not combine with list filters or cursor.'),
  media_type: mediaType.optional(), status: libraryStatus.optional(),
  limit: z.number().int().min(1).max(100).default(5),
  cursor: z.string().min(1).max(8192).nullish().describe('Omit or use null for the first page. For later pages, copy next_cursor from the previous response unchanged. Never invent a cursor.'),
  detailed: z.boolean().default(false).describe('Include timestamps and full metadata.'),
}).strict().superRefine((value, context) => {
  if (value.hid && (value.media_type !== undefined || value.status !== undefined || value.cursor != null || value.limit !== 5)) context.addIssue({ code: 'custom', path: ['hid'], message: 'Use hid alone with optional detailed; list filters and pagination do not apply.' });
});
const libraryIndex = compactEntry.pick({ hid: true, slug: true, title: true, media_type: true, status_name: true, progress: true });
export const libraryOutput = z.object({
  data: z.array(z.union([libraryEntryOutput.shape.data, compactEntry, libraryIndex])).max(100), next_cursor: z.string().nullable(),
});
export async function library(input: z.input<typeof librarySchema>) {
  const { hid: entryHid, detailed, cursor, status, ...filters } = librarySchema.parse(input);
  if (entryHid) return { data: [(await libraryEntry({ hid: entryHid, detailed })).data], next_cursor: null };
  const query = { ...filters, status: status === undefined ? undefined : statusCode[status] };
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

const progressWrite = z.string().min(1).max(4000);
export const librarySaveSchema = z.object({
  hid,
  status: libraryStatus.optional().describe('Required to add an entry; omit to update existing fields only.'),
  progress: progressWrite.nullable().optional().describe('Saved chapter/episode, not next unread. null clears progress; omit to preserve.'),
  rating: z.number().int().min(1).max(10).nullable().optional().describe('Personal series score; null clears it, omit to preserve.'),
  detailed: z.boolean().default(false),
}).strict().superRefine(({ hid: titleHid, detailed, ...body }, context) => {
  if (Object.values(body).every(value => value === undefined)) context.addIssue({ code: 'custom', path: ['status'], message: 'Supply at least one of status, progress, or rating.' });
  if (Buffer.byteLength(JSON.stringify(body), 'utf8') > 4096) context.addIssue({ code: 'custom', path: ['progress'], message: 'Keep the JSON write body within 4096 UTF-8 bytes.' });
});
export async function librarySave(input: z.input<typeof librarySaveSchema>) {
  const { hid, detailed, status, progress, rating } = librarySaveSchema.parse(input);
  const body = { status: status === undefined ? undefined : statusCode[status], progress: typeof progress === 'string' ? { number: progress } : progress, rating };
  const raw = await apiRequest(`/me/library/${encodeURIComponent(hid)}`, { method: status === undefined ? 'PATCH' : 'PUT', body });
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
