import assert from 'node:assert/strict';
import childProcess from 'node:child_process';
import { appendFileSync, readFileSync } from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { mock } from 'node:test';
import { z } from 'zod';
import { libraryEntryOutput } from '../src/integration.js';
import { inputProcess, required, keyringInput, writeBody, type ExecStub } from './support.js';

Date.now = () => Date.parse('2030-01-01T00:00:00Z');
let credential: string | undefined = JSON.stringify({ access_token: 'MOCK_ACCESS', refresh_token: 'MOCK_REFRESH', token_type: 'Bearer',
  scope: 'library:read library:write offline_access', client_id: 'mock-stdio', expires_at: Date.now() + 900000 });
const mode = () => z.object({ mode: z.string() }).parse(JSON.parse(readFileSync(required(process.env.COMICK_TEST_SCENARIO), 'utf8'))).mode;
const execStub: ExecStub = (command, args, _options, done) => {
  assert.ok(['powershell.exe', 'secret-tool'].includes(command), 'Tests must not launch a real browser or credential backend');
  return inputProcess(input => {
    const windows = command === 'powershell.exe';
    const request = windows ? keyringInput.parse(JSON.parse(input)) : { operation: args[0], secret: input };
    if (mode() === 'keyring_error') return done(new Error('DO_NOT_LEAK_TOKEN'), '', 'MOCK_ACCESS');
    if (request.operation === 'store') credential = windows ? Buffer.from(required(request.secret), 'base64').toString('utf8') : input;
    if (request.operation === 'clear') credential = undefined;
    const value = request.operation === 'lookup' ? credential ?? '' : '';
    done(null, windows ? Buffer.from(value).toString('base64') : value, '');
  });
};
mock.method(childProcess, 'execFile', execStub);
syncBuiltinESMExports();

const entry: z.infer<typeof libraryEntryOutput>['data'] & { notes: string } = { hid: 'Hid', slug: 'sample', title: 'Sample', media_type: 'manga', status: 1, status_name: 'reading',
  progress: { unit: 'chapter', hid: null, number: '12.5', volume: '0' }, continue_entry: null, rating: 8,
  bayesian_rating: null, publication_status: null, translation_completed: null, last_released_number: '13', total_units: null,
  followed_at: '2029-01-01T00:00:00Z', updated_at: '2029-01-02T00:00:00Z', progressed_at: null, last_released_at: null,
  url: 'https://comick.dev/comic/sample', notes: 'DO_NOT_LEAK_TOKEN' };
let saved = { ...entry };
globalThis.fetch = async (input, options = {}) => {
  const url = new URL(input instanceof Request ? input.url : input);
  assert.ok(['https://api.comick.dev', 'https://comick.dev'].includes(url.origin));
  const method = options.method ?? 'GET';
  appendFileSync(required(process.env.COMICK_TEST_REQUESTS), JSON.stringify({ path: url.pathname, query: [...url.searchParams], method,
    body: options.body instanceof URLSearchParams ? 'oauth' : options.body ? writeBody.parse(JSON.parse(z.string().parse(options.body))) : null }) + '\n');
  const scenario = mode();
  if (scenario === 'network') throw new Error('DO_NOT_LEAK_TOKEN');
  if (scenario === 'rate_limit') return new Response(null, { status: 429, headers: { 'retry-after': '30' } });
  if (scenario === 'forbidden') return new Response(null, { status: 403 });
  if (scenario === 'malformed') return Response.json({ invalid: 'DO_NOT_LEAK_TOKEN' });
  if (scenario === 'html') return new Response('<html>DO_NOT_LEAK_TOKEN</html>', { headers: { 'content-type': 'text/html' } });
  const empty = scenario === 'empty';
  if (url.pathname === '/api/auth/oauth2/token') {
    assert.equal(method, 'POST');
    assert.equal(required(options.body instanceof URLSearchParams ? options.body : undefined).get('grant_type'), 'authorization_code');
    assert.equal(required(options.body instanceof URLSearchParams ? options.body : undefined).get('code'), 'mock-code');
    assert.equal(required(options.body instanceof URLSearchParams ? options.body : undefined).get('client_id'), 'mock-stdio');
    return Response.json({ access_token: 'MOCK_ACCESS', refresh_token: 'MOCK_REFRESH', token_type: 'Bearer',
      scope: 'library:read library:write offline_access', expires_in: 900 });
  }
  if (url.pathname === '/api/auth/oauth2/revoke') {
    assert.equal(method, 'POST');
    return new Response(null, { status: 200 });
  }
  if (scenario === 'many') {
    const rows = Array.from({ length: 8 }, (_, i) => ({ hid: `Hid${i}`, slug: `sample-${i}`, title: `Sample ${i}` }));
    if (url.pathname === '/category/') return Response.json(rows.map(row => ({ ...row, comic_count: 8 })));
    if (url.pathname === '/v1.0/search/') return Response.json(rows.slice(0, Number(url.searchParams.get('limit'))));
    if (url.pathname === '/integrations/v1/me/library') return Response.json({ data: rows.slice(0, Number(url.searchParams.get('limit'))).map(row => ({ ...entry, ...row })), next_cursor: 'more' });
    if (url.pathname === '/v1.0/comic/sample/') return Response.json({ comic: { hid: 'Hid', slug: 'sample', title: 'Sample', media_type: 'manga', desc: 'Plot', year: 2020, status: 1,
      review_count: 8, reviews: rows.map(row => ({ title: row.title, content: 'Review', rating: '8', created_at: '2026-01-01T00:00:00Z', updated_at: null, identities: null })),
      mu_comic_categories: rows.map(row => ({ mu_categories: row, score: 1 })),
      md_comic_md_genres: rows.map(row => ({ md_genres: { name: row.title, slug: row.slug, group: 'Genre' } })),
      links: { urls: { engtl: rows.map(row => ({ url: `https://example.com/${row.slug}`, lang: 'en' })) } },
    } });
    if (url.pathname === '/v1.0/comic/Hid/chapters') return Response.json({ groups: rows.map(row => ({ title: row.title, slug: row.slug, official: false, count: 1 })) });
    if (url.pathname === '/anime/schedule') return Response.json({ year: 2030, season: 'winter', generatedAt: '2030-01-01T00:00:00Z', entries: rows.map(row => ({ ...row,
      schedule: { broadcast: 'Tuesdays at 12:00 (JST)', jstWeekday: 'tuesday', jstTime: '12:00', occurrenceAt: '2030-01-01T03:00:00Z' },
    })) });
  }
  if (url.pathname === '/category/' || url.pathname === '/anime/schedule' || url.pathname.startsWith('/v1.0/')) {
    assert.equal(new Headers(options.headers).get('Authorization'), 'Bearer MOCK_ACCESS');
    assert.equal(options.credentials, 'omit');
    assert.equal(options.redirect, 'error');
    if (url.pathname === '/anime/schedule') return Response.json({ year: 2026, season: 'fall', generatedAt: '2026-11-07T12:00:00Z', total: 2, entries: empty ? [] : [
      { hid: 'AnimeHid', slug: 'sample-anime', title: 'Sample Anime', rating: '8.5', rating_count: 20,
        schedule: { broadcast: 'Mondays at 00:30 (JST)', jstWeekday: 'monday', jstTime: '00:30', occurrenceAt: '2026-11-08T15:30:00Z' } },
      { hid: 'AnimeHid2', slug: 'second-anime', title: 'Second Anime', rating: null,
        schedule: { broadcast: 'Tuesdays at 12:00 (JST)', jstWeekday: 'tuesday', jstTime: '12:00', occurrenceAt: '2026-11-10T03:00:00Z' } },
    ] });
    if (url.pathname === '/category/') return Response.json(empty ? [] : [{ title: 'Regression', slug: 'regression', comic_count: 10 }, { title: 'Uncounted', slug: 'uncounted', comic_count: null }]);
    if (url.pathname === '/v1.0/search/') return Response.json(empty ? [] : [{ hid: 'Hid', slug: 'sample', title: 'Sample', rating: '8.5', bayesian_rating: '8.1', rating_count: 10, private_field: 'DO_NOT_LEAK_TOKEN' }]);
    if (url.pathname === '/v1.0/comic/sample/') return Response.json({ comic: { hid: 'Hid', slug: 'sample', title: 'Sample', media_type: 'manga', desc: 'Catalog description', year: 2020, status: 1,
      review_count: empty ? 0 : 2, reviews: empty ? [] : [
        { title: 'Worth reading', content: 'Strong characters, slow start.', rating: '9', created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-02T00:00:00Z', identities: { traits: { username: 'Reader', email: 'DO_NOT_LEAK_TOKEN' } } },
        { title: 'Not for me', content: 'Too much exposition.', rating: '4', created_at: '2026-01-03T00:00:00Z', updated_at: null, identities: null },
      ],
      mu_comic_categories: [{ mu_categories: { title: 'Regression', slug: 'regression' }, score: 4 }],
      md_comic_md_genres: [{ md_genres: { name: 'Action', slug: 'action', group: 'Genre' } }],
      links: { urls: { engtl: [{ url: 'https://example.com/read', lang: 'en' }] } } } });
    if (url.pathname === '/v1.0/comic/Hid/chapters' && scenario === 'malformed_groups') return Response.json({ unexpected: true });
    if (url.pathname === '/v1.0/comic/Hid/chapters') return Response.json({ groups: [{ title: 'Sample Scans', slug: 'sample-scans', official: false, count: 12 }] });
  }
  if (url.pathname.startsWith('/integrations/v1/')) {
    assert.equal(new Headers(options.headers).get('Authorization'), 'Bearer MOCK_ACCESS');
    assert.equal(options.cache, 'no-store');
    assert.equal(options.credentials, 'omit');
    if (url.pathname === '/integrations/v1/titles') return Response.json({ data: empty ? [] : [{ hid: 'Hid', slug: 'sample', title: 'Sample', media_type: url.searchParams.get('media_type'), description: 'OAuth description' }] });
    if (url.pathname === '/integrations/v1/titles/Hid') return Response.json({ data: { hid: 'Hid', slug: 'sample', title: 'Sample', media_type: 'manga', description: 'OAuth description' } });
    if (url.pathname === '/integrations/v1/me') return Response.json({ id: '12345678-1234-4123-8123-123456789abc', username: 'Reader', avatar_url: null });
    if (url.pathname === '/integrations/v1/me/library') return Response.json({ data: empty ? [] : [saved], next_cursor: null });
    if (url.pathname === '/integrations/v1/me/library/Hid') {
      if (method === 'DELETE') return new Response(null, { status: 204 });
      if (method !== 'GET') {
        const body = writeBody.parse(JSON.parse(z.string().parse(options.body)));
        const progress = body.progress === undefined ? saved.progress : body.progress === null ? null : {
          unit: 'chapter' as const, hid: body.progress.hid ?? null, number: body.progress.number ?? '13', volume: body.progress.volume ?? null };
        saved = libraryEntryOutput.shape.data.extend({ notes: z.string() }).parse({ ...saved, ...body, progress, status_name: ['reading', 'completed', 'on_hold', 'dropped', 'plan_to_read'][(body.status ?? saved.status) - 1] });
      }
      return Response.json({ data: saved });
    }
  }
  throw new Error(`Unmocked upstream route: ${method} ${url.pathname}`);
};
