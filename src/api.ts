import { accessToken, ComickError, resource } from './oauth.js';

export async function apiRequest(path: string, { method = 'GET', query = {}, body }: {
  method?: 'GET' | 'PUT' | 'PATCH' | 'DELETE';
  query?: Record<string, string | number | undefined>;
  body?: unknown;
} = {}) {
  const url = new URL(`${resource}${path}`);
  for (const [key, value] of Object.entries(query)) {
    if (value !== undefined) url.searchParams.set(key, String(value));
  }
  const writing = method !== 'GET';
  const scope = writing ? 'library:write' : 'library:read';
  let token = await accessToken(undefined, scope);
  for (let attempt = 0; attempt < 2; attempt++) {
    let response: Response;
    try {
      response = await fetch(url, {
        method, ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        headers: { Authorization: `Bearer ${token}`, ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
        signal: AbortSignal.timeout(20_000),
        redirect: 'error', credentials: 'omit',
        cache: 'no-store',
      });
    } catch {
      throw new ComickError(writing ? 'write_outcome_unknown' : 'network_error', writing
        ? 'The library write may have succeeded, but its response was not received. Read the library entry before retrying; do not assume no change.'
        : 'Comick API network unavailable or request timed out.');
    }
    if (response.status === 401 && attempt === 0) {
      token = await accessToken(token, scope);
      continue;
    }
    if (!response.ok) {
      const retryAfter = response.headers.get('retry-after');
      if (writing && response.status >= 500) throw new ComickError('write_outcome_unknown', `Comick returned HTTP ${response.status}; the library write outcome is unknown. Read the entry before retrying.`, response.status, retryAfter ?? undefined);
      if (writing && response.status === 403) throw new ComickError('write_permission_required', 'Comick refused the library write. Check app write permission, granted library:write scope, and account eligibility; read-only access may still work.', 403);
      throw new ComickError(response.status === 429 ? 'rate_limited' : response.status === 401 ? 'reconnect_required' : 'api_error', `Comick API returned HTTP ${response.status}${retryAfter ? `; Retry-After: ${retryAfter}` : ''}.`, response.status, retryAfter ?? undefined);
    }
    if (method === 'DELETE') {
      if (response.status !== 204) throw new ComickError('write_outcome_unknown', 'Comick did not return the documented 204 deletion confirmation. Verify the library before repeating removal.', response.status);
      return null;
    }
    try { return await response.json() as unknown; }
    catch { throw new ComickError(writing ? 'write_outcome_unknown' : 'invalid_response', writing
      ? 'The library write returned success but invalid JSON. Read the entry before retrying.'
      : 'Comick API returned invalid JSON.'); }
  }
  throw new Error('Comick authorization failed. Reconnect with npm run login.');
}
