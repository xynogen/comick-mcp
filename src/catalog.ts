import { z } from 'zod';
import { apiGet, ComickError, hasCredentials } from './oauth.js';

const slugs = (maximum: number) => z.array(z.string().trim().min(1).max(200)).min(1).max(maximum).optional();
const contentRating = z.enum(['safe', 'suggestive', 'erotica', 'pornographic']);

export const searchSchema = z.object({
  q: z.string().trim().min(1).max(200).optional().describe('Title keywords. Omit when browsing similar titles by genre/theme; a source title is not a similarity query.'),
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
  detailed: z.boolean().default(false).describe('Default is an index only: HID, slug, title, rating and status. Fetch comick_title for selected matches; true includes metadata for every match.'),
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
const rawTitle = z.object({
  hid, slug: identifier, title: label, media_type: mediaType.optional(),
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
  synopsis: z.string().nullable(), synopsis_truncated: z.boolean(),
  genres: z.array(genre), unresolved_genre_ids: z.array(z.number().int()),
  rating: z.object({ site_score: z.number().min(0).max(10).nullable(), rating_count: z.number().int().nonnegative().nullable() }),
  publication_status: z.object({ code: z.number().int().min(1).max(4), name: z.enum(['ongoing', 'completed', 'cancelled', 'hiatus']) }).nullable(),
  translation_completed: z.boolean().nullable(), country: z.string().nullable(), year: z.number().int().nullable(),
  last_released_number: z.string().nullable(), content_rating: contentRating.nullable(), violence_rating: z.enum(['none', 'graphic']).nullable(),
});
const compactSummary = z.object({
  hid, slug: identifier, title: label,
  rating: z.number().min(0).max(10).nullable(),
  status: z.enum(['ongoing', 'completed', 'cancelled', 'hiatus']).nullable(),
});
export const searchOutput = z.object({
  items: z.array(z.union([compactSummary, summary])).max(50), page: z.number().int(), limit: z.number().int(), returned_count: z.number().int(), warnings: z.array(z.string()),
});
export const filtersOutput = z.object({ items: z.array(genre), warnings: z.array(z.string()) });
export const titleSchema = z.object({
  slug: identifier, hid: hid.optional(), media_type: mediaType.default('manga'),
  synopsis_limit: z.number().int().min(100).max(10000).default(4000),
}).strict();
export const titleOutput = summary.extend({
  alternative_titles: z.array(z.object({ title: label, lang: z.string().nullable() })).max(10),
  authors: z.array(person), artists: z.array(person), languages: z.array(z.string()), tags: z.array(tag),
  recommendations: z.array(z.object({ hid, slug: identifier, title: label, url: z.string().url(), votes: z.number().nullable() })).max(5),
  partial: z.boolean(), source: z.enum(['catalog_detail', 'oauth_title', 'search']), missing_fields: z.array(z.string()), warnings: z.array(z.string()),
});

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

export async function filters(kind: 'genres' | 'tags') {
  if (kind === 'genres') return parse(filtersOutput, { items: await genreList(), warnings: [] });
  const items = parse(z.array(z.object({ title: label, slug: identifier })), await catalogGet('/category/'));
  return parse(filtersOutput, { items: items.map(item => ({ name: item.title, slug: item.slug, group: null })), warnings: [] });
}

async function resolveGenres(items: RawTitle[], warnings: string[]) {
  if (!items.some(item => item.genres?.length)) return [];
  try { return await genreList(); }
  catch { warnings.push('Genre lookup unavailable; unresolved genre IDs were preserved.'); return []; }
}

export async function search(input: z.input<typeof searchSchema>) {
  const { synopsis_limit, detailed, ...query } = searchSchema.parse(input);
  const items = parse(z.array(rawTitle).max(query.limit), await catalogGet('/v1.0/search/', query));
  if (items.some(item => item.media_type && item.media_type !== query.media_type)) throw new ComickError('invalid_response', 'Comick returned a different media type.');
  const warnings: string[] = [];
  const genres = detailed ? await resolveGenres(items, warnings) : [];
  return parse(searchOutput, {
    items: items.map(item => {
      const data = summarize(item, query.media_type, detailed ? synopsis_limit : 0, genres);
      if (detailed) return data;
      return { hid: data.hid, slug: data.slug, title: data.title, rating: data.rating.site_score, status: data.publication_status?.name ?? null };
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
      const response = parse(z.object({ data: rawTitle }), await apiGet(`/titles/${encodeURIComponent(query.hid)}`));
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
  return parse(titleOutput, {
    ...data, alternative_titles: (item.md_titles ?? item.titles ?? []).slice(0, 10).map(value => ({ title: value.title, lang: value.lang })),
    authors: detail.authors ?? [], artists: detail.artists ?? [], languages: detail.langList ?? [],
    tags: (item.mu_comic_categories ?? []).map(value => ({ name: value.mu_categories.title, slug: value.mu_categories.slug })),
    recommendations: (item.recommendations ?? []).slice(0, 5).map(value => {
      const related = value.relates;
      const type = related.media_type ?? query.media_type;
      return { hid: related.hid, slug: related.slug, title: related.md_titles?.find(title => title.is_default && title.lang === 'en')?.title ?? related.title,
        url: `https://comick.dev/${type === 'anime' ? 'anime' : 'comic'}/${related.slug}`, votes: value.total };
    }),
    partial: source !== 'catalog_detail', source, missing_fields: missing, warnings,
  });
}

export const libraryEntrySchema = z.object({ hid }).strict();
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
  url: z.string().url(),
}) });

export async function libraryEntry(input: z.input<typeof libraryEntrySchema>) {
  const { hid } = libraryEntrySchema.parse(input);
  let response: unknown;
  try { response = await apiGet(`/me/library/${encodeURIComponent(hid)}`); }
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
  return result;
}

export const chaptersSchema = z.object({
  hid: hid.describe('Title HID from search or title details, not a chapter HID.'),
  slug: identifier.optional().describe('Exact title slug from search; supply it to include chapter reader links.'),
  lang: z.string().min(2).max(100).regex(/^[a-z]{2,3}(?:-[a-z0-9]{2,8})*(?:,[a-z]{2,3}(?:-[a-z0-9]{2,8})*)*$/).optional()
    .describe('Language codes, comma-separated, for example en,id or pt-br. Omit for all languages.'),
  page: z.number().int().min(1).max(200).default(1),
  limit: z.number().int().min(1).max(50).default(12),
}).strict();
const chapter = z.object({
  hid, number: z.string().nullable(), volume: z.string().nullable(), title: z.string().nullable(),
  lang: z.string().nullable(), released_at: z.string().datetime({ offset: true }).nullable(),
  created_at: z.string().datetime({ offset: true }).nullable(), updated_at: z.string().datetime({ offset: true }).nullable(),
  groups: z.array(z.string()), url: z.string().url().nullable(),
});
export const chaptersOutput = z.object({
  title_hid: hid, items: z.array(chapter).max(50), total: z.number().int().nonnegative(),
  page: z.number().int().positive(), limit: z.number().int().positive(), order: z.literal('newest_created_first'), warnings: z.array(z.string()),
});

export async function chapters(input: z.input<typeof chaptersSchema>) {
  const { hid: titleHid, slug, lang, page, limit } = chaptersSchema.parse(input);
  const timestamp = z.string().datetime({ offset: true }).nullish().transform(value => value ?? null);
  const response = parse(z.object({
    chapters: z.array(z.object({
      hid, chap: z.string().nullable(), vol: z.string().nullish(), title: nullableText, lang: nullableText,
      publish_at: timestamp, created_at: timestamp, updated_at: timestamp, group_name: z.array(label).nullish(),
    })).max(limit),
    total: z.number().int().nonnegative(), limit: z.number().int().positive(),
  }), await catalogGet(`/v1.0/comic/${encodeURIComponent(titleHid)}/chapters`, { entry_type: 'chapter', lang, page, limit, 'date-order': 0 }));
  return parse(chaptersOutput, {
    title_hid: titleHid, page, limit: response.limit, total: response.total, order: 'newest_created_first',
    items: response.chapters.map(item => ({
      hid: item.hid, number: item.chap, volume: item.vol ?? null, title: item.title, lang: item.lang,
      released_at: item.publish_at, created_at: item.created_at, updated_at: item.updated_at, groups: item.group_name ?? [],
      url: slug ? `https://comick.dev/comic/${slug}/${item.hid}` : null,
    })),
    warnings: slug ? [] : ['Supply the exact title slug from comick_search to include reader links.'],
  });
}
