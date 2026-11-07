import assert from 'node:assert/strict';
import childProcess from 'node:child_process';
import { appendFileSync, readFileSync } from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';

Date.now = () => Date.parse('2030-01-01T00:00:00Z');
let credential = JSON.stringify({ access_token: 'MOCK_ACCESS', refresh_token: 'MOCK_REFRESH', token_type: 'Bearer',
  scope: 'library:read library:write offline_access', client_id: 'mock-stdio', expires_at: Date.now() + 900000 });
const mode = () => JSON.parse(readFileSync(process.env.COMICK_TEST_SCENARIO, 'utf8')).mode;
childProcess.execFile = (command, args, _options, done) => {
  assert.ok(['powershell.exe', 'secret-tool'].includes(command), 'Tests must not launch a real browser or credential backend');
  return { stdin: { on() { return this; }, end(input) {
    const windows = command === 'powershell.exe';
    const request = windows ? JSON.parse(input) : { operation: args[0], secret: input };
    if (mode() === 'keyring_error') return done(new Error('DO_NOT_LEAK_TOKEN'), '', 'MOCK_ACCESS');
    if (request.operation === 'store') credential = windows ? Buffer.from(request.secret, 'base64').toString('utf8') : input;
    if (request.operation === 'clear') credential = undefined;
    const value = request.operation === 'lookup' ? credential ?? '' : '';
    done(null, windows ? Buffer.from(value).toString('base64') : value, '');
  } } };
};
syncBuiltinESMExports();

const entry = { hid: 'Hid', slug: 'sample', title: 'Sample', media_type: 'manga', status: 1, status_name: 'reading',
  progress: { unit: 'chapter', hid: null, number: '12.5', volume: '0' }, continue_entry: null, rating: 8,
  bayesian_rating: null, publication_status: null, translation_completed: null, last_released_number: '13', total_units: null,
  followed_at: '2029-01-01T00:00:00Z', updated_at: '2029-01-02T00:00:00Z', progressed_at: null, last_released_at: null,
  url: 'https://comick.dev/comic/sample', notes: 'DO_NOT_LEAK_TOKEN' };
let saved = { ...entry };
globalThis.fetch = async (input, options = {}) => {
  const url = new URL(input);
  assert.ok(['https://api.comick.dev', 'https://comick.dev'].includes(url.origin));
  const method = options.method ?? 'GET';
  appendFileSync(process.env.COMICK_TEST_REQUESTS, JSON.stringify({ path: url.pathname, query: [...url.searchParams], method,
    body: options.body instanceof URLSearchParams ? 'oauth' : options.body ? JSON.parse(options.body) : null }) + '\n');
  const scenario = mode();
  if (scenario === 'network') throw new Error('DO_NOT_LEAK_TOKEN');
  if (scenario === 'rate_limit') return new Response(null, { status: 429, headers: { 'retry-after': '30' } });
  if (scenario === 'forbidden') return new Response(null, { status: 403 });
  if (scenario === 'malformed') return Response.json({ invalid: 'DO_NOT_LEAK_TOKEN' });
  if (scenario === 'html') return new Response('<html>DO_NOT_LEAK_TOKEN</html>', { headers: { 'content-type': 'text/html' } });
  const empty = scenario === 'empty';
  if (url.pathname === '/api/auth/oauth2/token') {
    assert.equal(method, 'POST');
    assert.equal(options.body.get('grant_type'), 'authorization_code');
    assert.equal(options.body.get('code'), 'mock-code');
    assert.equal(options.body.get('client_id'), 'mock-stdio');
    return Response.json({ access_token: 'MOCK_ACCESS', refresh_token: 'MOCK_REFRESH', token_type: 'Bearer',
      scope: 'library:read library:write offline_access', expires_in: 900 });
  }
  if (url.pathname === '/api/auth/oauth2/revoke') {
    assert.equal(method, 'POST');
    return new Response(null, { status: 200 });
  }
  if (url.pathname.startsWith('/integrations/v1/')) {
    assert.equal(options.headers.Authorization, 'Bearer MOCK_ACCESS');
    assert.equal(options.cache, 'no-store');
    if (url.pathname === '/integrations/v1/me') return Response.json({ id: '12345678-1234-4123-8123-123456789abc', username: 'Reader', avatar_url: null });
    if (url.pathname === '/integrations/v1/me/library') return Response.json({ data: empty ? [] : [saved], next_cursor: null });
    if (url.pathname === '/integrations/v1/me/library/Hid') {
      if (method === 'DELETE') return new Response(null, { status: 204 });
      if (method !== 'GET') {
        const body = JSON.parse(options.body);
        const progress = body.progress === undefined ? saved.progress : body.progress === null ? null : {
          unit: 'chapter', hid: body.progress.hid ?? null, number: body.progress.number ?? '13', volume: body.progress.volume ?? null };
        saved = { ...saved, ...body, progress, status_name: ['reading', 'completed', 'on_hold', 'dropped', 'plan_to_read'][(body.status ?? saved.status) - 1] };
      }
      return Response.json({ data: saved });
    }
  }
  assert.equal(method, 'GET', 'Catalog reads must not mutate the account');
  assert.equal(options.headers, undefined, 'Catalog requests must be anonymous');
  if (url.pathname === '/genre/') return Response.json(empty ? [] : [{ id: 5, name: 'Action', slug: 'action', group: 'Genre' }]);
  if (url.pathname === '/category/') return Response.json(empty ? [] : [{ title: 'Magic', slug: 'magic' }]);
  if (url.pathname === '/v1.0/search/') return Response.json(empty ? [] : [{ hid: 'Hid', slug: 'sample', title: 'Sample', genres: [5], bayesian_rating: '8.5' }]);
  if (url.pathname === '/v1.0/comic/sample/') return Response.json({ comic: { hid: 'Hid', slug: 'sample', title: 'Sample' } });
  if (url.pathname === '/v1.0/comic/Hid/chapters') return Response.json({ chapters: empty ? [] : [{ hid: 'ChapterHid', chap: '0', vol: null, title: null, lang: 'en', group_name: ['Group'] }], total: empty ? 0 : 1, limit: Number(url.searchParams.get('limit')) });
  if (url.pathname === '/chapter/ChapterHid/') return Response.json({ chapter: { hid: 'ChapterHid', entry_type: 'chapter', chap: '0', vol: null, title: null, lang: 'en', external: null, external_type: null, md_images: [], md_comics: { hid: 'Hid', slug: 'sample', title: 'Sample', media_type: 'manga' } } });
  if (url.pathname === '/chapter/ChapterHid/get_images') return Response.json(empty ? [] : [{ b2key: 'one.jpg', w: 800, h: 1200 }]);
  throw new Error(`Unmocked upstream route: ${method} ${url.pathname}`);
};
