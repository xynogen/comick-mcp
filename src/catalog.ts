import { z } from 'zod';

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
  limit: z.number().int().min(1).max(50).default(15),
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
  const response = await fetch(url, { signal: AbortSignal.timeout(20_000), redirect: 'error', credentials: 'omit' });
  if (!response.ok) {
    const retryAfter = response.headers.get('retry-after');
    throw new Error(`Comick catalog returned HTTP ${response.status}${retryAfter ? `; Retry-After: ${retryAfter}` : ''}.`);
  }
  if (!response.headers.get('content-type')?.toLowerCase().includes('application/json')) {
    throw new Error('Comick catalog returned non-JSON content; it may be an access-denied or Cloudflare challenge page.');
  }
  return response.json();
}
