import { z } from 'zod';
import { apiRequest, ComickError, hasCredentials } from './oauth.js';

const slugs = (maximum: number) => z.array(z.string().trim().min(1).max(200)).min(1).max(maximum).optional();
const contentRating = z.enum(['safe', 'suggestive', 'erotica', 'pornographic']);

export const searchSchema = z.object({
  query: z.string().trim().min(1).max(200).optional().describe('Title keywords. Omit to browse by filters.'),
  genres: slugs(10).describe('Included genre/theme slugs from comick_filters or comick_title.'),
  excludes: slugs(40).describe('Excluded genre/theme slugs.'),
  tags: slugs(10).describe('Included category slugs from comick_filters or comick_title.'),
  'excluded-tags': slugs(30),
  country: z.array(z.string().regex(/^[a-z]{2}$/)).min(1).max(10).optional().describe('Origin: jp manga, kr manhwa, cn manhua.'),
  demographic: z.array(z.number().int().min(1).max(5)).min(1).max(5).optional().describe('1 shounen, 2 shoujo, 3 seinen, 4 josei, 5 unset.'),
  content_rating: z.array(contentRating).min(1).max(4).optional(),
  excluded_content_rating: z.array(contentRating).min(1).max(4).optional(),
  minimum: z.number().int().nonnegative().optional().describe('Minimum chapter number, or episode count for anime.'),
  maximum: z.number().int().nonnegative().optional(),
  minimum_rating: z.number().min(0).max(10).optional(),
  from: z.number().int().min(1).max(9999).optional().describe('Earliest publication year, inclusive.'),
  to: z.number().int().min(1).max(9999).optional(),
  status: z.number().int().min(1).max(4).optional().describe('Publication: 1 ongoing, 2 completed, 3 cancelled, 4 hiatus.'),
  completed: z.boolean().optional().describe('Completed translation, not original publication status.'),
  sort: z.enum(['view', 'created_at', 'uploaded', 'rating', 'average_rating', 'follow', 'user_follow_count']).default('rating'),
  media_type: z.enum(['manga', 'anime']).default('manga'),
  page: z.number().int().min(1).max(50).default(1),
  limit: z.number().int().min(1).max(50).default(5),
  detailed: z.boolean().default(false).describe('Default returns only title, HID and slug; true returns metadata for every result.'),
  synopsis_limit: z.number().int().min(0).max(2000).default(180).describe('Synopsis excerpt length in detailed mode only; 0 omits synopsis text.'),
}).strict().superRefine((query, context) => {
  for (const [lower, upper] of [['minimum', 'maximum'], ['from', 'to']] as const) {
    if (query[lower] !== undefined && query[upper] !== undefined && query[lower] > query[upper]) {
      context.addIssue({ code: 'custom', path: [upper], message: `${upper} must be at least ${lower}.` });
    }
  }
});

export async function catalogGet(path: string, query: Record<string, string | number | boolean | (string | number)[] | undefined> = {}) {
  const url = new URL(`https://api.comick.dev${path}`);
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined) continue;
    for (const item of Array.isArray(value) ? value : [value]) url.searchParams.append(key, String(item));
  }
  let response: Response;
  try {
    response = await fetch(url, { signal: AbortSignal.timeout(20_000), redirect: 'error', credentials: 'omit' });
  } catch {
    throw new ComickError('network_error', 'Comick catalog network unavailable or request timed out.');
  }
  if (!response.ok) {
    const retryAfter = response.headers.get('retry-after');
    throw new ComickError(response.status === 429 ? 'rate_limited' : 'catalog_error', `Comick catalog returned HTTP ${response.status}${retryAfter ? `; Retry-After: ${retryAfter}` : ''}.`, response.status, retryAfter ?? undefined);
  }
  if (!response.headers.get('content-type')?.toLowerCase().includes('application/json')) {
    throw new ComickError('non_json_response', 'Comick catalog returned non-JSON content; it may be an access-denied or Cloudflare challenge page.');
  }
  try { return await response.json() as unknown; }
  catch { throw new ComickError('invalid_response', 'Comick catalog returned invalid JSON.'); }
}

const identifier = z.string().min(1).max(200).regex(/^[A-Za-z0-9_-]+$/);
const hid = identifier.max(64);
const mediaType = z.enum(['manga', 'anime']);
const label = z.string().trim().min(1).max(1000);
const nullableText = z.string().nullish().transform(value => value?.trim() || null);
const numeric = z.union([z.number(), z.string(), z.null()]).optional().transform(value => {
  if (value == null || (typeof value === 'string' && !value.trim())) return null;
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
});
const genre = z.object({ name: label, slug: identifier, group: z.string().nullable() });
const alternative = z.object({ title: label, lang: nullableText, is_default: z.boolean().optional() });
const person = z.object({ name: label, slug: identifier });
const tag = z.object({ name: label, slug: identifier });
const externalIds = z.object({
  anilist: z.string().nullable(), myanimelist: z.string().nullable(),
  mangabaka: z.string().nullable(), mangaupdates: z.string().nullable(),
});
const rawTitle = z.object({
  hid, slug: identifier, title: label, media_type: mediaType.optional(),
  external_ids: externalIds.nullish(),
  md_titles: z.array(alternative).nullish(), titles: z.array(alternative).nullish(),
  desc: nullableText, description: nullableText,
  genres: z.array(z.number().int().nonnegative()).nullish(),
  bayesian_rating: numeric, rating_count: numeric, status: numeric, year: numeric,
  country: nullableText, last_chapter: numeric, last_released_number: nullableText,
  translation_completed: z.boolean().nullish(),
  content_rating: contentRating.nullish(), violence_rating: z.enum(['none', 'graphic']).nullish(),
  md_comic_md_genres: z.array(z.object({ md_genres: genre.extend({ group: nullableText }) })).nullish(),
  mu_comic_categories: z.array(z.object({ mu_categories: z.object({ title: label, slug: identifier }) })).nullish(),
});
type RawTitle = z.infer<typeof rawTitle>;

const summary = z.object({
  hid, slug: identifier, title: label, media_type: mediaType, url: z.string().url(),
  external_ids: externalIds.nullable(),
  synopsis: z.string().nullable(), synopsis_truncated: z.boolean(),
  genres: z.array(genre), unresolved_genre_ids: z.array(z.number().int()),
  rating: z.object({ site_score: z.number().min(0).max(10).nullable(), rating_count: z.number().int().nonnegative().nullable() }),
  publication_status: z.object({ code: z.number().int().min(1).max(4), name: z.enum(['ongoing', 'completed', 'cancelled', 'hiatus']) }).nullable(),
  translation_completed: z.boolean().nullable(), country: z.string().nullable(), year: z.number().int().nullable(),
  last_released_number: z.string().nullable(), content_rating: contentRating.nullable(), violence_rating: z.enum(['none', 'graphic']).nullable(),
});
const compactSummary = z.object({ hid, slug: identifier, title: label });
export const searchOutput = z.object({
  items: z.array(z.union([summary, compactSummary])).max(50), page: z.number().int(), limit: z.number().int(), returned_count: z.number().int(), warnings: z.array(z.string()),
});
export const filtersSchema = z.object({
  kind: z.enum(['genres', 'tags']).default('genres'),
  query: z.string().trim().min(1).max(200).optional().describe('Match a name or slug; omit to browse.'),
  page: z.number().int().min(1).max(10000).default(1),
  limit: z.number().int().min(1).max(100).default(5),
}).strict();
export const filtersOutput = z.object({
  items: z.array(genre).max(100), page: z.number().int(), limit: z.number().int(), total: z.number().int(), has_more: z.boolean(),
});
export const titleSchema = z.object({
  slug: identifier, hid: hid.optional(), media_type: mediaType.default('manga'),
  synopsis_limit: z.number().int().min(100).max(10000).default(500),
  detailed: z.boolean().default(false).describe('True returns full metadata, alternative titles, and all available detail fields.'),
}).strict();
export const titleOutput = summary.extend({
  alternative_titles: z.array(z.object({ title: label, lang: z.string().nullable() })),
  authors: z.array(person), artists: z.array(person), languages: z.array(z.string()), tags: z.array(tag),
  recommendations: z.array(z.object({ hid, slug: identifier, title: label, url: z.string().url(), votes: z.number().nullable() })),
  partial: z.boolean(), source: z.enum(['catalog_detail', 'oauth_title', 'search']), missing_fields: z.array(z.string()), warnings: z.array(z.string()),
});
const compactTitle = titleOutput.pick({
  hid: true, slug: true, title: true, partial: true, source: true, missing_fields: true, warnings: true,
}).extend({
  synopsis: z.string().optional(), synopsis_truncated: z.literal(true).optional(),
  genres: z.array(genre).max(8).optional(), tags: z.array(tag).max(5).optional(),
  genres_truncated: z.literal(true).optional(), tags_truncated: z.literal(true).optional(),
  recommendations: z.array(compactSummary).max(5).optional(), recommendations_truncated: z.literal(true).optional(),
});
export const titleResult = z.union([titleOutput, compactTitle]);

function parse<T>(schema: z.ZodType<T>, value: unknown): T {
  const parsed = schema.safeParse(value);
  if (!parsed.success) throw new ComickError('invalid_response', 'Comick returned invalid catalog metadata.');
  return parsed.data;
}

function summarize(item: RawTitle, media: 'manga' | 'anime', maximum: number, genres: GenreWithId[] = [], excerpt = true) {
  const titles = item.md_titles ?? item.titles ?? [];
  const title = titles.find(value => value.is_default && value.lang === 'en')?.title
    ?? titles.find(value => value.is_default)?.title ?? item.title;
  const description = item.desc ?? item.description;
  const paragraph = excerpt ? description?.split(/\r?\n\s*\r?\n/)[0] ?? null : description;
  const characters = paragraph === null ? [] : Array.from(paragraph);
  const type = item.media_type ?? media;
  const status = item.status;
  return parse(summary, {
    hid: item.hid, slug: item.slug, title, media_type: type, url: `https://comick.dev/${type === 'anime' ? 'anime' : 'comic'}/${item.slug}`,
    external_ids: item.external_ids ?? null,
    synopsis: paragraph === null ? null : characters.slice(0, maximum).join(''),
    synopsis_truncated: description !== null && (description !== paragraph || characters.length > maximum),
    genres: item.md_comic_md_genres?.map(value => value.md_genres) ?? genres.filter(value => item.genres?.includes(value.id)),
    unresolved_genre_ids: (item.genres ?? []).filter(id => !genres.some(value => value.id === id)),
    rating: { site_score: item.bayesian_rating, rating_count: item.rating_count },
    publication_status: status !== null && Number.isInteger(status) && status >= 1 && status <= 4
      ? { code: status, name: ['ongoing', 'completed', 'cancelled', 'hiatus'][status - 1] } : null,
    translation_completed: item.translation_completed ?? null, country: item.country, year: item.year,
    last_released_number: item.last_released_number ?? (item.last_chapter === null ? null : String(item.last_chapter)),
    content_rating: item.content_rating ?? null, violence_rating: item.violence_rating ?? null,
  });
}

const genreWithId = genre.extend({ id: z.number().int().nonnegative(), group: nullableText });
type GenreWithId = z.infer<typeof genreWithId>;
async function genreList(): Promise<GenreWithId[]> {
  return parse(z.array(genreWithId), await catalogGet('/genre/'));
}

export async function filters(input: z.input<typeof filtersSchema>) {
  const { kind, query, page, limit } = filtersSchema.parse(input);
  const items = kind === 'genres' ? await genreList()
    : parse(z.array(z.object({ title: label, slug: identifier })), await catalogGet('/category/'))
      .map(item => ({ name: item.title, slug: item.slug, group: null }));
  const matching = query ? items.filter(item => `${item.name} ${item.slug}`.toLowerCase().includes(query.toLowerCase())) : items;
  return parse(filtersOutput, {
    items: matching.slice((page - 1) * limit, page * limit), page, limit, total: matching.length, has_more: page * limit < matching.length,
  });
}

async function resolveGenres(items: RawTitle[], warnings: string[]) {
  if (!items.some(item => item.genres?.length)) return [];
  try { return await genreList(); }
  catch { warnings.push('Genre lookup unavailable; unresolved genre IDs were preserved.'); return []; }
}

export async function search(input: z.input<typeof searchSchema>) {
  const { synopsis_limit, detailed, query: keywords, ...query } = searchSchema.parse(input);
  const items = parse(z.array(rawTitle).max(query.limit), await catalogGet('/v1.0/search/', { ...query, q: keywords }));
  if (items.some(item => item.media_type && item.media_type !== query.media_type)) throw new ComickError('invalid_response', 'Comick returned a different media type.');
  const warnings: string[] = [];
  const genres = detailed ? await resolveGenres(items, warnings) : [];
  return parse(searchOutput, {
    items: items.map(item => {
      if (!detailed) return parse(compactSummary, {
        hid: item.hid, slug: item.slug, title: summarize(item, query.media_type, 0).title,
      });
      return summarize(item, query.media_type, synopsis_limit, genres);
    }),
    page: query.page, limit: query.limit, returned_count: items.length, warnings,
  });
}

export async function title(input: z.input<typeof titleSchema>) {
  const query = titleSchema.parse(input);
  let raw: unknown;
  let source: 'catalog_detail' | 'oauth_title' | 'search' = 'catalog_detail';
  const warnings: string[] = [];
  try {
    raw = await catalogGet(`/v1.0/comic/${encodeURIComponent(query.slug)}/`, { media_type: query.media_type });
  } catch (error) {
    if (!(error instanceof ComickError) || (error.status !== 403 && error.code !== 'non_json_response')) throw error;
    warnings.push('Public title details unavailable; returning partial metadata.');
    if (query.hid && await hasCredentials()) {
      const response = parse(z.object({ data: rawTitle }), await apiRequest(`/titles/${encodeURIComponent(query.hid)}`));
      raw = { comic: response.data };
      source = 'oauth_title';
    }
    if (raw === undefined) {
      const candidates = parse(z.array(rawTitle).max(15), await catalogGet('/v1.0/search/', { q: query.slug, media_type: query.media_type, limit: 15, page: 1 }));
      const match = candidates.find(item => (item.media_type ?? query.media_type) === query.media_type
        && (query.hid ? item.hid === query.hid : item.slug === query.slug || item.hid === query.slug));
      if (!match) throw new ComickError('details_unavailable', 'Title details are blocked and no exact fallback match was found. Use comick_search to identify the title.');
      raw = { comic: match };
      source = 'search';
    }
  }
  const detail = parse(z.object({
    comic: rawTitle.extend({
      recommendations: z.array(z.object({ relates: rawTitle.pick({ hid: true, slug: true, title: true, md_titles: true, media_type: true }), total: numeric })).nullish(),
    }),
    authors: z.array(person).optional(), artists: z.array(person).optional(), langList: z.array(label).optional(),
  }), raw);
  const item = detail.comic;
  if ((query.hid && item.hid !== query.hid) || (item.media_type && item.media_type !== query.media_type)
    || (source === 'catalog_detail' && item.slug !== query.slug && item.hid !== query.slug)) {
    throw new ComickError('invalid_response', 'Comick returned a different title identity.');
  }
  const genres = await resolveGenres([item], warnings);
  const data = summarize(item, query.media_type, query.synopsis_limit, genres, false);
  const missing = [
    ...(!item.md_comic_md_genres && !item.genres ? ['genres'] : []),
    ...(!item.mu_comic_categories ? ['tags'] : []),
    ...(!detail.authors ? ['authors'] : []), ...(!detail.artists ? ['artists'] : []),
    ...(!detail.langList ? ['languages'] : []), ...(!item.recommendations ? ['recommendations'] : []),
    ...(data.synopsis === null ? ['synopsis'] : []),
    ...(data.unresolved_genre_ids.length ? ['genre_names'] : []),
  ];
  const full = parse(titleOutput, {
    ...data, alternative_titles: (item.md_titles ?? item.titles ?? []).map(value => ({ title: value.title, lang: value.lang })),
    authors: detail.authors ?? [], artists: detail.artists ?? [], languages: detail.langList ?? [],
    tags: (item.mu_comic_categories ?? []).map(value => ({ name: value.mu_categories.title, slug: value.mu_categories.slug })),
    recommendations: (item.recommendations ?? []).map(value => {
      const related = value.relates;
      const type = related.media_type ?? query.media_type;
      return { hid: related.hid, slug: related.slug, title: related.md_titles?.find(title => title.is_default && title.lang === 'en')?.title ?? related.title,
        url: `https://comick.dev/${type === 'anime' ? 'anime' : 'comic'}/${related.slug}`, votes: value.total };
    }),
    partial: source !== 'catalog_detail' || missing.length > 0, source, missing_fields: missing, warnings,
  });
  if (query.detailed) return full;
  const relevant = full.genres.filter(value => !['format', 'demographic'].includes(value.group?.toLowerCase() ?? ''));
  return parse(compactTitle, {
    hid: full.hid, slug: full.slug, title: full.title,
    synopsis: full.synopsis ?? undefined, synopsis_truncated: full.synopsis_truncated || undefined,
    genres: relevant.length ? relevant.slice(0, 8) : undefined,
    tags: full.tags.length ? full.tags.slice(0, 5) : undefined,
    recommendations: full.recommendations.length ? full.recommendations.slice(0, 5).map(({ hid, slug, title }) => ({ hid, slug, title })) : undefined,
    genres_truncated: relevant.length > 8 || undefined, tags_truncated: full.tags.length > 5 || undefined,
    recommendations_truncated: full.recommendations.length > 5 || undefined,
    partial: full.partial, source: full.source, missing_fields: full.missing_fields, warnings: full.warnings,
  });
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
  if (response.data.some(item => [item.progress, item.continue_entry].some(value => value && value.unit !== (item.media_type === 'manga' ? 'chapter' : 'episode')))) {
    throw new ComickError('invalid_response', 'Comick returned progress for a different media type.');
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
  const unit = result.data.media_type === 'manga' ? 'chapter' : 'episode';
  if ([result.data.progress, result.data.continue_entry].some(value => value && value.unit !== unit)) {
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
  if (!response.success || response.data.data.hid !== hid ||
    [response.data.data.progress, response.data.data.continue_entry].some(value => value && value.unit !== (response.data.data.media_type === 'manga' ? 'chapter' : 'episode'))) {
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

export const chaptersSchema = z.object({
  hid: hid.describe('Title HID from search or title details, not a chapter HID.'),
  slug: identifier.optional().describe('Exact title slug for a Comick chapter page, not a verified external reader URL.'),
  entry_type: z.enum(['chapter', 'episode']).default('chapter').describe('chapter for manga/manhwa/manhua; episode for anime. Episodes do not have reader images.'),
  lang: z.string().min(2).max(100).regex(/^[a-z]{2,3}(?:-[a-z0-9]{2,8})*(?:,[a-z]{2,3}(?:-[a-z0-9]{2,8})*)*$/).optional()
    .describe('Language codes, comma-separated, for example en,id or pt-br. Omit for all languages.'),
  page: z.number().int().min(1).max(200).default(1),
  limit: z.number().int().min(1).max(50).default(5),
  detailed: z.boolean().default(false).describe('Include volume, release/update timestamps and groups for each chapter.'),
}).strict();
const chapter = z.object({
  hid, number: z.string().nullable(), volume: z.string().nullable(), title: z.string().nullable(),
  lang: z.string().nullable(), released_at: z.string().datetime({ offset: true }).nullable(),
  created_at: z.string().datetime({ offset: true }).nullable(), updated_at: z.string().datetime({ offset: true }).nullable(),
  groups: z.array(z.string()), url: z.string().url().nullable(),
});
const compactChapter = chapter.pick({ hid: true, number: true, title: true, lang: true, url: true });
export const chaptersOutput = z.object({
  title_hid: hid, entry_type: z.enum(['chapter', 'episode']), items: z.array(z.union([chapter, compactChapter])).max(50), total: z.number().int().nonnegative(),
  page: z.number().int().positive(), limit: z.number().int().positive(), order: z.literal('newest_created_first'), warnings: z.array(z.string()),
});

export async function chapters(input: z.input<typeof chaptersSchema>) {
  const { hid: titleHid, slug, entry_type, lang, page, limit, detailed } = chaptersSchema.parse(input);
  const timestamp = z.string().datetime({ offset: true }).nullish().transform(value => value ?? null);
  const response = parse(z.object({
    chapters: z.array(z.object({
      hid, chap: z.string().nullable(), vol: z.string().nullish(), title: nullableText, lang: nullableText,
      publish_at: timestamp, created_at: timestamp, updated_at: timestamp, group_name: z.array(label).nullish(),
    })).max(limit),
    total: z.number().int().nonnegative(), limit: z.number().int().positive(),
  }), await catalogGet(`/v1.0/comic/${encodeURIComponent(titleHid)}/chapters`, { entry_type, lang, page, limit, 'date-order': 0 }));
  const full = parse(chaptersOutput, {
    title_hid: titleHid, entry_type, page, limit: response.limit, total: response.total, order: 'newest_created_first',
    items: response.chapters.map(item => ({
      hid: item.hid, number: item.chap, volume: item.vol ?? null, title: item.title, lang: item.lang,
      released_at: item.publish_at, created_at: item.created_at, updated_at: item.updated_at, groups: item.group_name ?? [],
      url: slug && entry_type === 'chapter' ? `https://comick.dev/comic/${slug}/${item.hid}` : null,
    })),
    warnings: [entry_type === 'episode'
      ? 'Episode metadata is not a video stream or a verified watch URL. Episodes have no reader images.'
      : slug ? 'Comick chapter page URLs are tracking/navigation links, not verified external reading URLs.'
        : 'Supply the exact title slug for Comick chapter page URLs; these are not verified external reading URLs.'],
  });
  return detailed ? full : { ...full, items: full.items.map(item => compactChapter.parse(item)) };
}

export const scanlationsSchema = chaptersSchema.pick({ hid: true, lang: true }).extend({
  limit: z.number().int().min(1).max(50).default(10).describe('Number of newest-created chapter releases to inspect, not distinct chapter numbers. 1–50.'),
}).strict();
export const scanlationsOutput = z.object({
  title_hid: hid, requested: z.number().int(), inspected: z.number().int(),
  order: z.literal('newest_created_first'), releases_without_groups: z.number().int(),
  groups: z.array(z.object({
    name: label, slug: identifier.nullable(), official: z.boolean().nullable(), inactive: z.boolean().nullable(),
    release_count: z.number().int().positive(), languages: z.array(z.string()),
    latest_release: chapter.pick({ hid: true, number: true, lang: true, created_at: true }),
  })),
  warnings: z.array(z.string()),
});

export async function scanlations(input: z.input<typeof scanlationsSchema>) {
  const query = scanlationsSchema.parse(input);
  const releaseSchema = z.object({
    hid, chap: nullableText, lang: nullableText, created_at: z.string().datetime({ offset: true }).nullish(),
    group_name: z.array(label).nullish(),
    md_chapters_groups: z.array(z.object({ md_groups: z.object({
      title: label, slug: identifier, official: z.boolean().nullish(), inactive: z.boolean().nullish(),
    }) })).nullish(),
  });
  let raw: unknown;
  try {
    raw = await catalogGet(`/v1.0/comic/${encodeURIComponent(query.hid)}/chapters`, {
      lang: query.lang, page: 1, limit: query.limit, 'date-order': 0, entry_type: 'chapter',
    });
  }
  catch (error) {
    if (error instanceof ComickError && (error.status === 403 || error.code === 'non_json_response')) {
      throw new ComickError('scanlations_unavailable', 'Comick chapter metadata is blocked; scanlation groups could not be verified. This is not an empty group list.', error.status);
    }
    throw error;
  }
  const { chapters: releases } = parse(z.object({ chapters: z.array(releaseSchema).max(query.limit) }), raw);
  const groups = new Map<string, z.infer<typeof scanlationsOutput>['groups'][number]>();
  let missing = 0;
  for (const release of releases) {
    const credits = release.md_chapters_groups != null
      ? release.md_chapters_groups.map(({ md_groups: group }) => ({
        name: group.title, slug: group.slug, official: group.official ?? null, inactive: group.inactive ?? null,
      }))
      : (release.group_name ?? []).map(name => ({ name, slug: null, official: null, inactive: null }));
    const unique = new Map(credits.map(group => [group.slug ? `slug:${group.slug}` : `name:${group.name.toLowerCase()}`, group]));
    if (!unique.size) missing++;
    for (const [key, credit] of unique) {
      const group = groups.get(key);
      if (group) {
        group.release_count++;
        if (release.lang && !group.languages.includes(release.lang)) group.languages.push(release.lang);
      } else {
        groups.set(key, { ...credit, release_count: 1, languages: release.lang ? [release.lang] : [],
          latest_release: { hid: release.hid, number: release.chap, lang: release.lang, created_at: release.created_at ?? null } });
      }
    }
  }
  return parse(scanlationsOutput, {
    title_hid: query.hid, requested: query.limit, inspected: releases.length, order: 'newest_created_first',
    releases_without_groups: missing, groups: [...groups.values()],
    warnings: [
      'Credits come directly from the Comick chapter API. Group slugs identify groups, not external reading websites. Newest-created does not mean highest chapter number.',
      ...(missing ? ['Some releases have no group credits; missing credits do not prove there is no scanlator.'] : []),
    ],
  });
}

const webUrl = z.url({ protocol: /^https?$/ }).refine(value => { const url = URL.parse(value); return url !== null && !url.username && !url.password; }, 'URLs must not contain credentials.');
const imageMetadata = z.object({
  b2key: z.string().min(1).nullish(), url: webUrl.nullish(),
  w: z.number().int().positive().nullish(), h: z.number().int().positive().nullish(),
}).refine(value => value.b2key != null || value.url != null, 'An image must contain b2key or url.');
export const chapterDetailSchema = z.object({
  hid: hid.describe('Chapter or episode HID, not the title HID.'),
}).strict();
const adjacentEntry = z.object({ hid, chap: z.string().nullable(), lang: z.string().nullable() });
export const chapterDetailOutput = z.object({
  hid, entry_type: z.enum(['chapter', 'episode']), number: z.string().nullable(), volume: z.string().nullable(),
  title: z.string().nullable(), lang: z.string().nullable(),
  parent: z.object({ hid, slug: identifier, title: label, media_type: mediaType }),
  groups: z.array(z.string()), external_reference: z.string().nullable(), external_type: z.string().nullable(),
  external_url: webUrl.nullable(), image_count: z.number().int().nonnegative().nullable(),
  next: adjacentEntry.nullable(), prev: adjacentEntry.nullable(),
  source_links: z.array(z.object({ kind: z.enum(['raw', 'engtl', 'othertl']), url: webUrl, lang: z.string().nullable() })),
  warnings: z.array(z.string()),
});
export async function chapterDetail(input: z.input<typeof chapterDetailSchema>) {
  const query = chapterDetailSchema.parse(input);
  const sourceLink = z.union([webUrl, z.object({ url: webUrl, lang: nullableText })]);
  const raw = parse(z.object({
    chapter: z.object({
      hid, entry_type: z.enum(['chapter', 'episode']), chap: nullableText, vol: nullableText, title: nullableText, lang: nullableText,
      group_name: z.array(label).nullish(), external: nullableText, external_type: nullableText,
      md_images: z.array(imageMetadata).nullish(),
      md_comics: z.object({ hid, slug: identifier, title: label, media_type: mediaType,
        links: z.object({ urls: z.object({ raw: z.array(sourceLink).optional(), engtl: z.array(sourceLink).optional(), othertl: z.array(sourceLink).optional() }).nullish() }).nullish(),
      }),
    }), next: adjacentEntry.nullish(), prev: adjacentEntry.nullish(),
  }), await catalogGet(`/chapter/${encodeURIComponent(query.hid)}/`));
  const item = raw.chapter;
  if (item.hid !== query.hid || (item.entry_type === 'episode') !== (item.md_comics.media_type === 'anime')) throw new ComickError('invalid_response', 'Comick returned a different chapter identity or media type.');
  const links = item.md_comics.links?.urls;
  const source_links = (['raw', 'engtl', 'othertl'] as const).flatMap(kind => (links?.[kind] ?? []).map(link => ({
    kind, url: typeof link === 'string' ? link : link.url, lang: typeof link === 'string' ? null : link.lang,
  })));
  return parse(chapterDetailOutput, {
    hid: item.hid, entry_type: item.entry_type, number: item.chap, volume: item.vol, title: item.title, lang: item.lang,
    parent: item.md_comics, groups: item.group_name ?? [], external_reference: item.external, external_type: item.external_type,
    external_url: webUrl.safeParse(item.external).success ? item.external : null,
    image_count: item.entry_type === 'episode' || !item.md_images ? null : item.md_images.length,
    next: raw.next ?? null, prev: raw.prev ?? null, source_links,
    warnings: ['Source links and external references are supplied by Comick, not verified for availability or reading access. No provider URLs are inferred from names or slugs.'],
  });
}
export const chapterImagesSchema = chapterDetailSchema.extend({
  offset: z.number().int().min(0).max(100000).default(0),
  limit: z.number().int().min(1).max(50).default(5),
}).strict();
export const chapterImagesOutput = z.object({
  chapter_hid: hid, items: z.array(imageMetadata).max(50), total: z.number().int().nonnegative(),
  offset: z.number().int().nonnegative(), next_offset: z.number().int().nonnegative().nullable(), warnings: z.array(z.string()),
});
export async function chapterImages(input: z.input<typeof chapterImagesSchema>) {
  const { hid, offset, limit } = chapterImagesSchema.parse(input);
  const images = parse(z.array(imageMetadata), await catalogGet(`/chapter/${encodeURIComponent(hid)}/get_images`));
  return parse(chapterImagesOutput, {
    chapter_hid: hid, items: images.slice(offset, offset + limit), total: images.length, offset,
    next_offset: offset + limit < images.length ? offset + limit : null,
    warnings: ['Metadata only: storage keys are not reader URLs. No CDN URLs are constructed and no images are downloaded. Empty results do not prove that a chapter is readable or unavailable elsewhere. Episodes have no reader images.'],
  });
}
