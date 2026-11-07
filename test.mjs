import assert from 'node:assert/strict';
import { test, mock } from 'node:test';
import childProcess from 'node:child_process';
import { syncBuiltinESMExports } from 'node:module';
import { createHash } from 'node:crypto';
import { createServer, request as httpRequest } from 'node:http';
import { once } from 'node:events';
import { copyFile, mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';

const root = fileURLToPath(new URL('.', import.meta.url));
const networkFetch = globalThis.fetch;
globalThis.fetch = (input, options) => {
  const url = new URL(input instanceof Request ? input.url : input);
  assert.ok(url.protocol === 'http:' && url.hostname === '127.0.0.1', `Unexpected external network request: ${url.origin}`);
  return networkFetch(input, options);
};

let windowsCommand;
for (const platform of ['linux', 'win32']) test(`OAuth PKCE, state, refresh rotation, failure safety, and API retry (${platform}, mocked)`, async () => {
  const originalPlatform = Object.getOwnPropertyDescriptor(process, 'platform');
  Object.defineProperty(process, 'platform', { value: platform });
  const directory = await mkdtemp(`${root}.test-`);
  const originalFetch = globalThis.fetch;
  const originalLog = console.error;
  const previousId = process.env.COMICK_CLIENT_ID;
  const previousCallback = process.env.COMICK_REDIRECT_URI;
  const previousState = process.env.XDG_STATE_HOME;
  process.env.XDG_STATE_HOME = directory;
  let credential;
  let keyringFailure = false;
  let storeFailure = false;
  let clearFailure = false;
  const keyringExec = (command, args, options, done) => {
    assert.equal(command, platform === 'win32' ? 'powershell.exe' : 'secret-tool');
    if (platform === 'win32') {
      windowsCommand = args;
      const script = Buffer.from(args.at(-1), 'base64').toString('utf16le');
      assert.match(script, /CredReadW/);
      assert.match(script, /CredWriteW/);
      assert.doesNotMatch(script, /access-new|refresh-new|test-public-client/);
    } else assert.ok(args.includes('test-public-client'));
    assert.equal(args.includes(credential), false);
    assert.equal(options.timeout, 30_000);
    const stdin = { on() { return this; }, end(secret) {
      let operation = args[0];
      if (platform === 'win32') {
        const request = JSON.parse(secret);
        assert.equal(request.target, `comick-mcp:${createHash('sha256').update('https://comick.dev/api/auth/oauth2\0test-public-client').digest('hex')}`);
        operation = request.operation;
        secret = request.secret === undefined ? undefined : Buffer.from(request.secret, 'base64').toString('utf8');
      }
      if (keyringFailure) { done(new Error('backend leaked access-new'), '', 'refresh-new'); return; }
      if (operation === 'store') {
        if (storeFailure) { done(new Error('store failed'), '', ''); return; }
        credential = secret;
        done(null, '', '');
      } else if (operation === 'clear') {
        if (clearFailure) { done(new Error('delete leaked access-old'), '', 'refresh-old'); return; }
        credential = undefined;
        done(null, '', '');
      } else if (credential === undefined) {
        if (platform === 'win32') done(null, '', '');
        else done(Object.assign(new Error('not found'), { code: 1 }), '', '');
      } else {
        done(null, platform === 'win32' ? Buffer.from(credential, 'utf8').toString('base64') : credential, '');
      }
    } };
    return { stdin };
  };
  const keyringMock = mock.method(childProcess, 'execFile', keyringExec);
  syncBuiltinESMExports();
  process.env.COMICK_CLIENT_ID = 'test-public-client';
  try {
    await mkdir(`${directory}/dist`);
    await copyFile(`${root}dist/oauth.js`, `${directory}/dist/oauth.js`);
    await copyFile(`${root}dist/catalog.js`, `${directory}/dist/catalog.js`);
    const oauth = await import(pathToFileURL(`${directory}/dist/oauth.js`).href);
    const catalog = await import(pathToFileURL(`${directory}/dist/catalog.js`).href);
    const tokenResponse = (access = 'access-new', refresh = 'refresh-new') => Response.json({
      access_token: access, token_type: 'Bearer', expires_in: 900,
      scope: 'library:read offline_access', refresh_token: refresh,
    });
    const store = async (expires = Date.now() - 1000) => {
      credential = JSON.stringify({
        access_token: 'access-old', refresh_token: 'refresh-old', token_type: 'Bearer',
        scope: 'library:read offline_access', client_id: 'test-public-client', expires_at: expires,
      });
    };

    const probe = createServer();
    probe.listen(0, '127.0.0.1');
    await once(probe, 'listening');
    const port = probe.address().port;
    await new Promise(resolve => probe.close(resolve));
    process.env.COMICK_REDIRECT_URI = `http://127.0.0.1:${port}/callback`;
    let authorize;
    let onAuthorize;
    const authorization = new Promise(resolve => { onAuthorize = resolve; });
    console.error = message => {
      if (message.startsWith('Open this URL')) {
        authorize = new URL(message.split('\n')[1]);
        onAuthorize();
      }
    };
    let exchanges = 0;
    globalThis.fetch = async (url, options) => {
      exchanges++;
      assert.equal(String(url), 'https://comick.dev/api/auth/oauth2/token');
      assert.equal(options.body.get('grant_type'), 'authorization_code');
      assert.equal(options.body.get('code'), 'test-code');
      assert.equal(options.body.get('resource'), oauth.resource);
      assert.equal(createHash('sha256').update(options.body.get('code_verifier')).digest('base64url'), authorize.searchParams.get('code_challenge'));
      return tokenResponse();
    };
    const login = oauth.login();
    await Promise.race([authorization, login]);
    assert.equal(authorize.searchParams.get('scope'), 'library:read library:write offline_access');
    assert.equal(authorize.searchParams.get('code_challenge_method'), 'S256');
    let callback = new URL(process.env.COMICK_REDIRECT_URI);
    callback.search = new URLSearchParams({ state: 'wrong-state', code: 'wrong-code' });
    assert.equal((await originalFetch(callback)).status, 400);
    assert.equal(exchanges, 0);
    callback.search = new URLSearchParams({ state: authorize.searchParams.get('state') });
    callback.searchParams.append('code', 'first');
    callback.searchParams.append('code', 'second');
    assert.equal((await originalFetch(callback)).status, 400);
    assert.equal(exchanges, 0);
    callback.search = new URLSearchParams({ state: authorize.searchParams.get('state'), code: 'test-code' });
    const firstCallback = await originalFetch(callback);
    assert.equal(firstCallback.status, 200);
    assert.match(firstCallback.headers.get('content-type'), /text\/html/);
    assert.match(await firstCallback.text(), /Return to the connection page/);
    await login;
    assert.equal(exchanges, 1);
    await assert.rejects(stat(`${directory}/.comick/tokens.json`), { code: 'ENOENT' });
    if (originalPlatform.value !== 'win32') assert.equal((await stat(`${directory}/comick-mcp`)).mode & 0o777, 0o700);
    assert.equal(await oauth.accessToken(), 'access-new');
    assert.equal((await oauth.connect('status')).status, 'saved');
    const browser = mock.method(childProcess, 'execFile', (command, args, options, callback) => {
      if (command === 'secret-tool' || command === 'powershell.exe') return keyringExec(command, args, options, callback);
      assert.equal(command, 'xdg-open');
      assert.equal(new URL(args[0]).origin, 'https://comick.dev');
      assert.equal(options.timeout, 10_000);
      callback(null);
    });
    syncBuiltinESMExports();
    const browserCalls = () => browser.mock.calls.filter(call => call.arguments[0] === 'xdg-open').length;
    const waitForLogin = async () => {
      for (let attempt = 0; attempt < 100; attempt++) {
        const status = await oauth.connect('status');
        if (status.status !== 'pending') return status;
        await new Promise(resolve => setTimeout(resolve, 10));
      }
      assert.fail('Login did not finish within one second.');
    };
    try {
      const started = await oauth.connect('start');
      assert.equal(started.status, 'pending');
      await assert.rejects(oauth.disconnect(), error => error.code === 'credentials_busy');
      assert.equal(started.browser_opened, platform === 'linux');
      assert.equal(browserCalls(), platform === 'linux' ? 1 : 0);
      assert.equal((await oauth.connect('start')).authorization_url, started.authorization_url);
      assert.equal(browserCalls(), platform === 'linux' ? 1 : 0);
      const authorizationUrl = new URL(started.authorization_url);
      callback.search = new URLSearchParams({ state: authorizationUrl.searchParams.get('state'), code: 'test-code' });
      const callbackResponse = await originalFetch(callback);
      assert.equal(callbackResponse.status, 200);
      assert.equal(callbackResponse.headers.get('cache-control'), 'no-store');
      assert.match(callbackResponse.headers.get('content-type'), /text\/html/);
      assert.match(callbackResponse.headers.get('content-security-policy'), /default-src 'none'/);
      const callbackHtml = await callbackResponse.text();
      assert.match(callbackHtml, /color-scheme: dark/);
      assert.match(callbackHtml, /<html lang="en">/);
      assert.match(callbackHtml, /Authorization received. Sign-in is still in progress./);
      assert.match(callbackHtml, /href="http:\/\/127\.0\.0\.1:8788\/"/);
      assert.doesNotMatch(callbackHtml, /test-code|access-new|refresh-new|check the terminal/);
      const connected = await waitForLogin();
      assert.equal(connected.status, 'connected');
      assert.equal(connected.refresh_available, true);
      assert.doesNotMatch(JSON.stringify(connected), /access-new|refresh-new|access_token|refresh_token/);
      await assert.rejects(stat(`${directory}/.comick/tokens.json`), { code: 'ENOENT' });

      const denied = await oauth.connect('start', false);
      callback.search = new URLSearchParams({ state: new URL(denied.authorization_url).searchParams.get('state'), error: 'access_denied' });
      assert.equal((await originalFetch(callback)).status, 400);
      assert.equal((await waitForLogin()).status, 'failed');
      assert.equal(JSON.parse(credential).access_token, 'access-new');
      assert.equal(browserCalls(), platform === 'linux' ? 1 : 0);
      browser.mock.mockImplementation((command, args, options, done) => command === 'secret-tool' || command === 'powershell.exe'
        ? keyringExec(command, args, options, done) : done(new Error('no desktop browser')));
      const manual = await oauth.connect('start');
      assert.equal(manual.browser_opened, false);
      assert.match(manual.browser_message, /manually/);
      callback.search = new URLSearchParams({ state: new URL(manual.authorization_url).searchParams.get('state'), error: 'access_denied' });
      assert.equal((await originalFetch(callback)).status, 400);
      assert.equal((await waitForLogin()).status, 'failed');
    } finally {
      browser.mock.restore();
      syncBuiltinESMExports();
    }

    await store();
    let refreshCalls = 0;
    globalThis.fetch = async (_url, options) => {
      refreshCalls++;
      assert.equal(options.body.get('refresh_token'), 'refresh-old');
      assert.equal(JSON.parse(credential).refresh_token, undefined);
      await assert.rejects(oauth.accessToken(), /busy/);
      return tokenResponse();
    };
    assert.equal(await oauth.accessToken(), 'access-new');
    assert.equal(await oauth.accessToken(), 'access-new');
    assert.equal(refreshCalls, 1);
    assert.equal(JSON.parse(credential).refresh_token, 'refresh-new');

    await store();
    globalThis.fetch = async () => { throw new Error('response lost'); };
    await assert.rejects(oauth.accessToken(), error => error.code === 'reconnect_required' && !/response lost/.test(error.message));
    await assert.rejects(oauth.accessToken(), /Reconnect/);
    assert.equal(JSON.parse(credential).refresh_token, undefined);

    await store(Date.now() + 900_000);
    const calls = [];
    globalThis.fetch = async (url, options) => {
      calls.push(String(url));
      if (String(url).endsWith('/token')) return tokenResponse();
      if (options.headers.Authorization === 'Bearer access-old') return new Response(null, { status: 401 });
      assert.equal(options.headers.Authorization, 'Bearer access-new');
      return Response.json({ data: [], next_cursor: null });
    };
    assert.deepEqual(await oauth.apiRequest('/me/library', { query: { limit: 10, cursor: 'opaque+/=' } }), { data: [], next_cursor: null });
    assert.equal(calls.length, 3);
    assert.equal(new URL(calls[0]).searchParams.get('cursor'), 'opaque+/=');

    globalThis.fetch = async () => new Response(null, { status: 429, headers: { 'retry-after': '60' } });
    await assert.rejects(oauth.apiRequest('/me'), /HTTP 429; Retry-After: 60/);
    process.env.COMICK_REDIRECT_URI = 'http://0.0.0.0:8787/callback';
    await assert.rejects(oauth.login(), /127\.0\.0\.1/);
    await store();
    const beforeFailure = credential;
    storeFailure = true;
    globalThis.fetch = async () => { assert.fail('Refresh must not run when keyring invalidation fails.'); };
    await assert.rejects(oauth.accessToken(), /OS keyring store failed/);
    assert.equal(credential, beforeFailure);
    storeFailure = false;
    keyringFailure = true;
    await assert.rejects(oauth.accessToken(), error => /OS keyring lookup failed/.test(error.message) && !/access-new|refresh-new/.test(error.message));
    keyringFailure = false;
    credential = '{bad JSON';
    await assert.rejects(oauth.accessToken(), /Invalid Comick credentials in OS keyring/);
    credential = undefined;
    await assert.rejects(oauth.accessToken(), /No Comick credentials in OS keyring/);
    if (platform === 'win32') {
      await store();
      globalThis.fetch = async () => tokenResponse('é'.repeat(2000));
      await assert.rejects(oauth.accessToken(), /2560 bytes/);
      assert.equal(JSON.parse(credential).access_token, 'access-old');
      assert.equal(JSON.parse(credential).refresh_token, undefined);
    }
    await store(Date.now() + 900_000);
    const requested = [];
    globalThis.fetch = async (url, options) => {
      requested.push(String(url));
      if (String(url).includes('/v1.0/comic/')) return new Response(null, { status: 403 });
      assert.equal(String(url), `${oauth.resource}/titles/KnownHid`);
      assert.equal(options.headers.Authorization, 'Bearer access-old');
      return Response.json({ data: { hid: 'KnownHid', slug: 'known-title', title: 'Known Title', media_type: 'manga', description: 'OAuth description' } });
    };
    const partial = await catalog.title({ slug: 'known-title', hid: 'KnownHid', detailed: true });
    assert.equal(partial.source, 'oauth_title');
    assert.equal(partial.partial, true);
    assert.ok(partial.missing_fields.includes('genres'));
    assert.equal(requested.length, 2);
    globalThis.fetch = async url => String(url).includes('/v1.0/comic/') ? new Response(null, { status: 403 }) : new Response(null, { status: 429, headers: { 'retry-after': '15' } });
    await assert.rejects(catalog.title({ slug: 'known-title', hid: 'KnownHid' }), error => error.code === 'rate_limited' && error.retryAfter === '15');
    globalThis.fetch = async url => String(url).includes('/v1.0/comic/') ? new Response(null, { status: 403 })
      : Response.json({ data: { hid: 'WrongHid', slug: 'wrong-title', title: 'Wrong', media_type: 'manga' } });
    await assert.rejects(catalog.title({ slug: 'known-title', hid: 'KnownHid' }), error => error.code === 'invalid_response');

    const entry = { hid: 'KnownHid', slug: 'known-title', title: 'Known Title', media_type: 'manga', status: 1, status_name: 'reading',
      progress: { unit: 'chapter', hid: null, number: '12.5', volume: '0' },
      continue_entry: { unit: 'chapter', hid: 'ChapterHid', number: 'Special', volume: null },
      rating: 8.5, bayesian_rating: 9.1, publication_status: 2, translation_completed: true, last_released_number: '20.5', total_units: null,
      followed_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-02T00:00:00Z', progressed_at: null, last_released_at: null,
      url: 'https://comick.dev/comic/known-title', notes: 'DO_NOT_FORWARD', access_token: 'DO_NOT_FORWARD' };
    let entryCalls = 0;
    globalThis.fetch = async (url, options) => {
      entryCalls++;
      assert.equal(String(url), `${oauth.resource}/me/library/KnownHid`);
      assert.equal(options.headers.Authorization, 'Bearer access-old');
      assert.equal(options.cache, 'no-store');
      assert.equal(options.credentials, 'omit');
      return Response.json({ data: entry });
    };
    const saved = await catalog.libraryEntry({ hid: 'KnownHid' });
    assert.equal(entryCalls, 1);
    assert.equal(saved.data.progress.number, '12.5');
    assert.equal(saved.data.progress.volume, '0');
    assert.equal(saved.data.progress.hid, null);
    assert.equal(saved.data.continue_entry.number, 'Special');
    assert.equal(saved.data.rating, 8.5);
    assert.doesNotMatch(JSON.stringify(saved), /DO_NOT_FORWARD/);
    assert.equal(saved.data.updated_at, undefined);
    const complete = await catalog.libraryEntry({ hid: 'KnownHid', detailed: true });
    assert.equal(complete.data.updated_at, entry.updated_at);
    assert.ok(JSON.stringify(saved).length < JSON.stringify(complete).length);

    // Writes preserve omitted values and never retry an ambiguous outcome.
    let writes = [];
    globalThis.fetch = async (url, options) => { writes.push(options); return Response.json({ data: entry }); };
    await assert.rejects(catalog.librarySave({ hid: 'KnownHid', rating: 8 }), error => error.code === 'write_permission_required');
    assert.equal(writes.length, 0);
    const readOnlyCredential = credential;
    const grantWrites = () => {
      credential = JSON.stringify({ ...JSON.parse(readOnlyCredential), scope: 'library:read library:write offline_access' });
    };
    grantWrites();
    globalThis.fetch = async (url, options) => {
      assert.equal(String(url), `${oauth.resource}/me/library/KnownHid`);
      assert.equal(options.headers['Content-Type'], 'application/json');
      assert.equal(options.redirect, 'error');
      assert.equal(options.credentials, 'omit');
      assert.equal(options.cache, 'no-store');
      writes.push({ method: options.method, body: JSON.parse(options.body) });
      const body = JSON.parse(options.body);
      const progress = body.progress === undefined ? entry.progress : body.progress === null ? null :
        { unit: 'chapter', hid: body.progress.hid ?? null, number: body.progress.number ?? '13', volume: body.progress.volume ?? null };
      return Response.json({ data: { ...entry, ...body, progress } });
    };
    for (const [input, method, body] of [
      [{ action: 'upsert', status: 5 }, 'PUT', { status: 5 }],
      [{ status: 1, progress: { number: '12.5', volume: '0' }, rating: 8 }, 'PATCH', { status: 1, progress: { number: '12.5', volume: '0' }, rating: 8 }],
      [{ progress: { hid: 'ChapterHid' } }, 'PATCH', { progress: { hid: 'ChapterHid' } }],
      [{ progress: { number: '0' } }, 'PATCH', { progress: { number: '0' } }],
      [{ progress: { number: 'Special', volume: null } }, 'PATCH', { progress: { number: 'Special', volume: null } }],
      [{ progress: null, rating: null }, 'PATCH', { progress: null, rating: null }],
      [{ rating: 10 }, 'PATCH', { rating: 10 }],
    ]) {
      const output = await catalog.librarySave({ hid: 'KnownHid', ...input });
      assert.deepEqual(writes.at(-1), { method, body });
      assert.equal(output.data.rating, body.rating === undefined ? entry.rating : body.rating);
      assert.doesNotMatch(JSON.stringify(output), /DO_NOT_FORWARD/);
    }
    for (const input of [
      {}, { action: 'upsert', rating: 8 }, { rating: 8.5 }, { rating: '8' }, { rating: 0 }, { status: 6 },
      { progress: { number: 12 } }, { progress: {} }, { progress: { hid: 'ChapterHid', number: '12' } },
      { progress: { hid: 'ChapterHid', volume: '2' } }, { progress: { volume: '2' } },
      { progress: { number: '' } }, { progress: { number: 'x'.repeat(4096) } }, { user_id: 'Other' },
    ]) {
      const count = writes.length;
      await assert.rejects(catalog.librarySave({ hid: 'KnownHid', ...input }), error => error.name === 'ZodError');
      assert.equal(writes.length, count);
    }
    globalThis.fetch = async (_url, options) => {
      assert.deepEqual(JSON.parse(options.body), { progress: { number: '3' } });
      return Response.json({ data: { ...entry, media_type: 'anime', status_name: 'watching', progress: { unit: 'episode', hid: null, number: '3', volume: null }, continue_entry: null } });
    };
    const animeWrite = await catalog.librarySave({ hid: 'KnownHid', progress: { number: '3' }, detailed: true });
    assert.equal(animeWrite.data.progress.unit, 'episode');
    assert.equal(animeWrite.data.updated_at, entry.updated_at);
    let deleteCalls = 0;
    globalThis.fetch = async (url, options) => {
      deleteCalls++;
      assert.equal(url.pathname, '/integrations/v1/me/library/KnownHid');
      assert.equal(options.method, 'DELETE');
      assert.equal(options.body, undefined);
      assert.equal(options.headers['Content-Type'], undefined);
      return new Response(null, { status: 204 });
    };
    await assert.rejects(catalog.libraryRemove({ hid: 'KnownHid', confirm: false }), error => error.name === 'ZodError');
    assert.equal(deleteCalls, 0);
    for (let i = 0; i < 2; i++) assert.deepEqual(await catalog.libraryRemove({ hid: 'KnownHid', confirm: true }), { hid: 'KnownHid', status: 'removed_or_already_absent' });
    assert.equal(deleteCalls, 2);
    for (const response of [new Response('bad JSON'), Response.json({ data: { ...entry, hid: 'WrongHid' } }),
      Response.json({ data: { ...entry, progress: { ...entry.progress, unit: 'episode' } } }), new Response(null, { status: 503 })]) {
      let calls = 0;
      globalThis.fetch = async () => { calls++; return response; };
      await assert.rejects(catalog.librarySave({ hid: 'KnownHid', rating: 8 }), error => error.code === 'write_outcome_unknown');
      assert.equal(calls, 1);
    }
    let lostCalls = 0;
    globalThis.fetch = async () => { lostCalls++; throw new Error('DO_NOT_LEAK_TOKEN'); };
    await assert.rejects(catalog.librarySave({ hid: 'KnownHid', rating: 8 }), error => error.code === 'write_outcome_unknown' && !/DO_NOT_LEAK_TOKEN/.test(error.message));
    assert.equal(lostCalls, 1);
    for (const [status, code] of [[400, 'api_error'], [403, 'write_permission_required'], [404, 'api_error'], [429, 'rate_limited']]) {
      globalThis.fetch = async () => new Response(null, { status, headers: { 'retry-after': '30' } });
      await assert.rejects(catalog.librarySave({ hid: 'KnownHid', rating: 8 }), error => error.code === code && error.status === status);
    }
    globalThis.fetch = async () => Response.json({ data: entry });
    await assert.rejects(catalog.libraryRemove({ hid: 'KnownHid', confirm: true }), error => error.code === 'write_outcome_unknown');
    let refreshWrites = 0;
    globalThis.fetch = async (url, options) => {
      if (String(url).endsWith('/token')) return Response.json({ access_token: 'write-new', token_type: 'Bearer', expires_in: 900, scope: 'library:read library:write', refresh_token: 'write-refresh' });
      refreshWrites++;
      if (refreshWrites === 1) return new Response(null, { status: 401 });
      assert.equal(options.headers.Authorization, 'Bearer write-new');
      assert.equal(options.body, JSON.stringify({ rating: 8 }));
      return Response.json({ data: { ...entry, rating: 8 } });
    };
    assert.equal((await catalog.librarySave({ hid: 'KnownHid', rating: 8 })).data.rating, 8);
    assert.equal(refreshWrites, 2);
    grantWrites();
    credential = JSON.stringify({ ...JSON.parse(credential), expires_at: 0 });
    let lostScopeRequests = 0;
    globalThis.fetch = async url => {
      assert.match(String(url), /\/token$/);
      lostScopeRequests++;
      return tokenResponse();
    };
    await assert.rejects(catalog.librarySave({ hid: 'KnownHid', rating: 8 }), error => error.code === 'write_permission_required');
    assert.equal(lostScopeRequests, 1);
    credential = readOnlyCredential;

    const cursor = 'opaque+/=';
    const rows = Array.from({ length: 7 }, (_, i) => ({ ...entry, hid: `Known${i}`, cover_url: null, country: 'cn',
      translation_status: 'ongoing', titles: [{ title: `Alternative ${i}`, lang: 'en', is_default: true }] }));
    globalThis.fetch = async url => {
      assert.equal(url.pathname, '/integrations/v1/me/library');
      assert.equal(url.searchParams.get('limit'), '5');
      assert.equal(url.searchParams.has('detailed'), false);
      assert.equal(url.searchParams.get('media_type'), 'manga');
      assert.equal(url.searchParams.get('status'), '1');
      const next = url.searchParams.get('cursor');
      assert.ok(next === null || next === cursor);
      return Response.json({ data: next ? rows.slice(5) : rows.slice(0, 5), next_cursor: next ? null : cursor });
    };
    const first = await catalog.library({ media_type: 'manga', status: 1 });
    assert.equal(first.data.length, 5);
    assert.deepEqual(Object.keys(first.data[0]).sort(), ['hid', 'media_type', 'progress', 'slug', 'status_name', 'title']);
    assert.deepEqual(await catalog.library({ media_type: 'manga', status: 1, cursor: null }), first);
    const next = await catalog.library({ media_type: 'manga', status: 1, cursor: first.next_cursor });
    assert.equal(next.next_cursor, null);
    assert.deepEqual([...first.data, ...next.data].map(row => row.hid), rows.map(row => row.hid));
    const fullPage = await catalog.library({ media_type: 'manga', status: 1, detailed: true });
    assert.equal(fullPage.data[0].titles[0].title, 'Alternative 0');
    assert.equal(fullPage.data[0].translation_status, 'ongoing');
    assert.equal(fullPage.data[0].updated_at, entry.updated_at);
    assert.ok(JSON.stringify(first).length < JSON.stringify(fullPage).length);
    assert.doesNotMatch(JSON.stringify(fullPage), /DO_NOT_FORWARD/);
    const publicProfile = { id: '12345678-1234-4123-8123-123456789abc', username: 'Reader', avatar_url: 'https://example.com/avatar' };
    globalThis.fetch = async url => {
      assert.equal(url.pathname, '/integrations/v1/me');
      assert.equal(url.search, '');
      return Response.json({ ...publicProfile, access_token: 'DO_NOT_FORWARD' });
    };
    assert.deepEqual(await catalog.me({}), { id: publicProfile.id, username: 'Reader' });
    assert.deepEqual(await catalog.me({ detailed: true }), publicProfile);
    globalThis.fetch = async () => Response.json({ data: [{ ...entry, progress: { ...entry.progress, number: 12 } }], next_cursor: null });
    await assert.rejects(catalog.library({}), error => error.code === 'invalid_response');
    for (const invalid of [{ ...entry, hid: 'Wrong' }, { ...entry, progress: { ...entry.progress, number: 12 } },
      { ...entry, progress: { ...entry.progress, unit: 'episode' } }]) {
      globalThis.fetch = async () => Response.json({ data: invalid });
      await assert.rejects(catalog.libraryEntry({ hid: 'KnownHid' }), error => error.code === 'invalid_response');
    }
    globalThis.fetch = async () => Response.json({ data: { ...entry, media_type: 'anime', status_name: 'watching', progress: null, continue_entry: null } });
    assert.equal((await catalog.libraryEntry({ hid: 'KnownHid' })).data.progress, null);
    for (const status of [403, 404, 429]) {
      globalThis.fetch = async () => new Response(null, { status });
      await assert.rejects(catalog.libraryEntry({ hid: 'KnownHid' }), error => error.status === status && (status !== 404 || error.code === 'library_entry_not_found'));
    }

    const revoked = [];
    globalThis.fetch = async (url, options) => {
      assert.equal(String(url), 'https://comick.dev/api/auth/oauth2/revoke');
      assert.equal(options.method, 'POST');
      assert.equal(options.redirect, 'error');
      assert.equal(options.credentials, 'omit');
      assert.equal(options.body.get('client_id'), 'test-public-client');
      assert.equal(options.headers['Content-Type'], 'application/x-www-form-urlencoded');
      assert.ok(options.signal instanceof AbortSignal);
      await assert.rejects(oauth.accessToken(), /busy/);
      revoked.push([options.body.get('token_type_hint'), options.body.get('token')]);
      return new Response(null, { status: 200 });
    };
    const disconnected = await oauth.disconnect();
    assert.equal(disconnected.revocation, 'complete');
    assert.equal(disconnected.local_deleted, true);
    assert.deepEqual(revoked, [['access_token', 'access-old'], ['refresh_token', 'refresh-old']]);
    assert.equal(credential, undefined);
    assert.equal((await oauth.connect('status')).status, 'disconnected');
    assert.equal((await oauth.disconnect()).revocation, 'not_needed');
    assert.equal(revoked.length, 2);

    await store();
    const { refresh_token, ...accessOnly } = JSON.parse(credential);
    assert.equal(refresh_token, 'refresh-old');
    credential = JSON.stringify(accessOnly);
    assert.equal((await oauth.disconnect()).revocation, 'complete');
    assert.equal(revoked.length, 3);

    await store();
    let attempts = 0;
    globalThis.fetch = async () => { attempts++; return new Response(null, { status: attempts === 1 ? 503 : 200 }); };
    const failedRevoke = await oauth.disconnect();
    assert.equal(attempts, 2);
    assert.equal(failedRevoke.revocation, 'partial');
    assert.match(failedRevoke.warnings.join(' '), /connected-apps/);
    assert.equal(credential, undefined);
    await store();
    attempts = 0;
    globalThis.fetch = async () => { attempts++; throw new DOMException('token access-old refresh-old', 'TimeoutError'); };
    const timeout = await oauth.disconnect();
    assert.equal(attempts, 2);
    assert.equal(timeout.revocation, 'failed');
    assert.doesNotMatch(JSON.stringify(timeout), /access-old|refresh-old/);
    assert.equal(credential, undefined);

    await store();
    clearFailure = true;
    globalThis.fetch = async () => new Response(null, { status: 200 });
    await assert.rejects(oauth.disconnect(), error => error.code === 'credential_store_failed' && !/access-old|refresh-old/.test(error.message));
    assert.notEqual(credential, undefined);
    clearFailure = false;
    assert.equal((await oauth.disconnect()).status, 'disconnected');
  } finally {
    Object.defineProperty(process, 'platform', originalPlatform);
    globalThis.fetch = originalFetch;
    console.error = originalLog;
    keyringMock.mock.restore();
    syncBuiltinESMExports();
    if (previousState === undefined) delete process.env.XDG_STATE_HOME;
    else process.env.XDG_STATE_HOME = previousState;
    if (previousId === undefined) delete process.env.COMICK_CLIENT_ID;
    else process.env.COMICK_CLIENT_ID = previousId;
    if (previousCallback === undefined) delete process.env.COMICK_REDIRECT_URI;
    else process.env.COMICK_REDIRECT_URI = previousCallback;
    await rm(directory, { recursive: true, force: true });
  }
});

test('Windows Credential Manager native round-trip and size limit', { skip: process.platform !== 'win32' || process.env.COMICK_TEST_NATIVE !== '1' }, async () => {
  const target = `comick-mcp:self-check:${process.pid}:${Date.now()}`;
  const secret = JSON.stringify({ access_token: 'dummy-日本語-é', refresh_token: 'not-a-real-token' });
  const run = (operation, value) => new Promise((resolve, reject) => {
    const child = childProcess.execFile('powershell.exe', windowsCommand, { timeout: 30_000, windowsHide: true }, (error, stdout) => {
      if (error) reject(new Error('Native WinCred self-check failed.'));
      else resolve(Buffer.from(stdout.trim(), 'base64').toString('utf8'));
    });
    child.stdin.on('error', reject);
    child.stdin.end(JSON.stringify({ operation, target, secret: value === undefined ? undefined : Buffer.from(value, 'utf8').toString('base64') }));
  });
  try {
    assert.equal(await run('lookup'), '');
    await run('store', secret);
    assert.equal(await run('lookup'), secret);
    await run('store', 'updated-dummy');
    assert.equal(await run('lookup'), 'updated-dummy');
    await assert.rejects(run('store', 'é'.repeat(1281)));
    assert.equal(await run('lookup'), 'updated-dummy');
    await run('clear');
    assert.equal(await run('lookup'), '');
    await run('clear');
  } finally {
    const script = `
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class ComickCredentialCleanup {
    [DllImport("advapi32.dll", EntryPoint = "CredDeleteW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool Delete(string target, uint type, uint flags);
}
'@
if (-not [ComickCredentialCleanup]::Delete([Console]::In.ReadToEnd(), 1, 0)) {
  if ([Runtime.InteropServices.Marshal]::GetLastWin32Error() -ne 1168) { exit 1 }
}`;
    await new Promise((resolve, reject) => {
      const child = childProcess.execFile('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')],
        { timeout: 30_000, windowsHide: true }, error => error ? reject(new Error(`Could not remove self-check credential ${target}.`)) : resolve());
      child.stdin.on('error', reject);
      child.stdin.end(target);
    });
  }
  assert.equal(await run('lookup'), '');
});

test('catalog filters, repeated query values, anonymous requests and HTTP failures (mocked)', async () => {
  const { catalogGet, searchSchema } = await import('./dist/catalog.js');
  const originalFetch = globalThis.fetch;
  try {
    const query = searchSchema.parse({
      genres: ['action', 'fantasy'], excludes: ['harem'], tags: ['magic'], 'excluded-tags': ['love-triangle'],
      country: ['jp', 'kr'], demographic: [1, 3], content_rating: ['safe', 'suggestive'],
      completed: false, minimum: 0, maximum: 100, from: 2000, to: 2025,
    });
    globalThis.fetch = async (url, options) => {
      assert.equal(url.origin, 'https://api.comick.dev');
      assert.equal(url.pathname, '/v1.0/search/');
      assert.deepEqual(url.searchParams.getAll('genres'), ['action', 'fantasy']);
      assert.deepEqual(url.searchParams.getAll('country'), ['jp', 'kr']);
      assert.deepEqual(url.searchParams.getAll('demographic'), ['1', '3']);
      assert.deepEqual(url.searchParams.getAll('excluded-tags'), ['love-triangle']);
      assert.deepEqual(url.searchParams.getAll('content_rating'), ['safe', 'suggestive']);
      assert.equal(url.searchParams.get('minimum'), '0');
      assert.equal(url.searchParams.get('completed'), 'false');
      assert.equal(url.searchParams.get('sort'), 'rating');
      assert.equal(url.searchParams.get('media_type'), 'manga');
      assert.equal(url.searchParams.has('q'), false);
      assert.equal(options.headers, undefined);
      assert.equal(options.credentials, 'omit');
      assert.equal(options.redirect, 'error');
      assert.ok(options.signal instanceof AbortSignal);
      return Response.json([{ slug: 'example', title: 'Example' }]);
    };
    assert.deepEqual(await catalogGet('/v1.0/search/', query), [{ slug: 'example', title: 'Example' }]);
    for (const invalid of [{ genres: Array(11).fill('action') }, { page: 51 }, { limit: 51 },
      { minimum: 20, maximum: 10 }, { from: 2025, to: 2000 }, { country: ['../'] },
      { minimum_rating: 11 }, { content_rating: ['unknown'] }, { query: '  ' }, { token: 'secret' }]) {
      assert.equal(searchSchema.safeParse(invalid).success, false);
    }
    globalThis.fetch = async () => new Response(null, { status: 429, headers: { 'retry-after': '60' } });
    await assert.rejects(catalogGet('/genre/'), /HTTP 429; Retry-After: 60/);
    globalThis.fetch = async () => new Response(null, { status: 404 });
    await assert.rejects(catalogGet('/v1.0/comic/missing/'), /HTTP 404/);
    globalThis.fetch = async () => new Response('<html>Challenge</html>', { headers: { 'content-type': 'text/html' } });
    await assert.rejects(catalogGet('/genre/'), /non-JSON/);
    globalThis.fetch = async () => { throw new Error('network unavailable'); };
    await assert.rejects(catalogGet('/genre/'), /network unavailable/);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('compact catalog metadata, genre resolution and exact bounded detail fallbacks', async () => {
  const { search, title, filters, searchOutput, titleOutput, titleResult } = await import('./dist/catalog.js');
  const originalFetch = globalThis.fetch;
  const previousId = process.env.COMICK_CLIENT_ID;
  delete process.env.COMICK_CLIENT_ID;
  const item = { hid: 'KnownHid', slug: 'known-title', title: 'Original', media_type: 'manga',
    desc: '😀'.repeat(105) + '\n\nOther paragraph', genres: [5, 999], bayesian_rating: '9.19', rating_count: '20',
    status: 2, last_chapter: 12.5, translation_completed: true, year: 2020,
    md_titles: [{ title: 'Display Title', lang: 'en', is_default: true }],
    reviews: ['do not forward'], parsed: '<script>no</script>', user_id: 'private-contributor' };
  const genres = [{ id: 5, name: 'Action', slug: 'action', group: 'Genre', comic_count: 500 }];
  try {
    let calls = [];
    globalThis.fetch = async (url, options) => {
      calls.push(String(url));
      assert.equal(options.headers, undefined);
      assert.equal(options.credentials, 'omit');
      assert.equal(url.searchParams.has('synopsis_limit'), false);
      assert.equal(url.searchParams.has('detailed'), false);
      return Response.json(url.pathname === '/genre/' ? genres : [item]);
    };
    const page = await search({ query: 'known', synopsis_limit: 100, detailed: true });
    assert.ok(searchOutput.safeParse(page).success);
    assert.equal(page.items[0].title, 'Display Title');
    assert.equal(page.items[0].rating.site_score, 9.19);
    assert.equal(page.items[0].rating.rating_count, 20);
    assert.equal(page.items[0].publication_status.name, 'completed');
    assert.equal(page.items[0].last_released_number, '12.5');
    assert.equal(Array.from(page.items[0].synopsis).length, 100);
    assert.equal(page.items[0].synopsis, '😀'.repeat(100));
    assert.equal(page.items[0].synopsis_truncated, true);
    assert.deepEqual(page.items[0].unresolved_genre_ids, [999]);
    assert.deepEqual(page.items[0].genres, [{ name: 'Action', slug: 'action', group: 'Genre' }]);
    assert.equal(calls.length, 2);
    assert.doesNotMatch(JSON.stringify(page), /private-contributor|script|reviews|comic_count/);
    assert.equal('total' in page, false);
    calls = [];
    const compact = await search({ query: 'known' });
    assert.ok(searchOutput.safeParse(compact).success);
    assert.equal(compact.limit, 5);
    assert.deepEqual(Object.keys(compact.items[0]).sort(), ['hid', 'slug', 'title']);
    assert.equal(calls.length, 1);
    assert.equal(new URL(calls[0]).searchParams.get('q'), 'known');
    assert.equal(new URL(calls[0]).searchParams.has('query'), false);
    assert.ok(JSON.stringify(compact).length < JSON.stringify(page).length);
    assert.equal('synopsis' in (await search({ synopsis_limit: 0 })).items[0], false);
    assert.ok(calls.some(url => new URL(url).searchParams.get('limit') === '5'));
    const manyGenres = Array.from({ length: 12 }, (_, id) => ({ id, name: `Theme ${id}`, slug: `theme-${id}`, group: 'Theme' }));
    globalThis.fetch = async url => Response.json(url.pathname === '/genre/' ? manyGenres : [{ ...item, genres: manyGenres.map(value => value.id), desc: 'x'.repeat(500) }]);
    const short = await search({});
    assert.deepEqual(Object.keys(short.items[0]).sort(), ['hid', 'slug', 'title']);
    const bounded = await search({ detailed: true });
    assert.equal(bounded.items[0].genres.length, 12);
    assert.equal(bounded.items[0].synopsis_truncated, true);
    globalThis.fetch = async url => Response.json(url.pathname === '/genre/' ? genres : [item]);
    assert.equal((await filters({ kind: 'genres' })).items[0].name, 'Action');
    globalThis.fetch = async () => Response.json([{ title: 'Level System', slug: 'level-system', id: 1, comic_count: 300 }]);
    assert.deepEqual((await filters({ kind: 'tags' })).items, [{ name: 'Level System', slug: 'level-system', group: null }]);
    globalThis.fetch = async () => Response.json(manyGenres);
    const firstFilters = await filters({});
    assert.equal(firstFilters.items.length, 5);
    assert.equal(firstFilters.total, 12);
    assert.equal(firstFilters.has_more, true);
    const allFilters = [];
    for (let page = 1; page <= 3; page++) allFilters.push(...(await filters({ page })).items);
    assert.deepEqual(allFilters.map(item => item.slug), manyGenres.map(item => item.slug));
    assert.deepEqual((await filters({ query: 'THEME-11' })).items.map(item => item.slug), ['theme-11']);
    assert.equal((await filters({ page: 3 })).has_more, false);
    assert.deepEqual((await filters({ query: 'missing' })).items, []);

    globalThis.fetch = async url => url.pathname === '/genre/' ? new Response(null, { status: 503 }) : Response.json([item]);
    const unresolved = await search({ detailed: true });
    assert.equal(unresolved.items.length, 1);
    assert.equal(unresolved.warnings.length, 1);
    assert.deepEqual(unresolved.items[0].unresolved_genre_ids, [5, 999]);
    const unresolvedShort = await search({});
    assert.deepEqual(unresolvedShort.warnings, []);
    assert.equal(unresolvedShort.items[0].title, 'Display Title');
    for (const value of ['', '  ', 'not-a-number', null]) {
      globalThis.fetch = async () => Response.json([{ ...item, genres: [], bayesian_rating: value }]);
      assert.equal((await search({})).items[0].title, 'Display Title');
    }
    for (const invalid of [{ ...item, hid: '../bad' }, { ...item, media_type: 'anime' }, { ...item, title: '' }]) {
      globalThis.fetch = async () => Response.json([invalid]);
      await assert.rejects(search({}), error => error.code === 'invalid_response');
    }
    globalThis.fetch = async () => Response.json([]);
    assert.equal((await search({})).returned_count, 0);

    const detail = { comic: { ...item, genres: undefined, md_comic_md_genres: [{ md_genres: genres[0] }],
      mu_comic_categories: [{ mu_categories: { title: 'Level System', slug: 'level-system' } }],
      recommendations: Array.from({ length: 6 }, (_, i) => ({ relates: { hid: `rec${i}`, slug: `rec-${i}`, title: 'Related' }, total: 20 })) },
      authors: [{ name: 'Author', slug: 'author' }], artists: [], langList: ['en', 'id'] };
    globalThis.fetch = async () => Response.json(detail);
    const brief = await title({ slug: item.slug });
    assert.deepEqual(Object.keys(brief).filter(key => brief[key] !== undefined).sort(), ['genres', 'hid', 'missing_fields', 'partial', 'recommendations', 'recommendations_truncated', 'slug', 'source', 'synopsis', 'tags', 'title', 'warnings']);
    assert.equal(brief.recommendations_truncated, true);
    assert.ok(Array.from(brief.synopsis).length <= 500);
    assert.deepEqual(brief.genres, [{ name: 'Action', slug: 'action', group: 'Genre' }]);
    assert.deepEqual(brief.tags, [{ name: 'Level System', slug: 'level-system' }]);
    assert.equal(brief.recommendations.length, 5);
    assert.ok(brief.recommendations.every(value => Object.keys(value).length === 3));
    assert.ok(titleResult.safeParse(brief).success);
    assert.equal(brief.source, 'catalog_detail');
    assert.deepEqual(brief.missing_fields, []);
    assert.deepEqual(brief.warnings, []);
    const full = await title({ slug: item.slug, detailed: true });
    assert.ok(JSON.stringify(brief).length < JSON.stringify(full).length);
    assert.ok(titleOutput.safeParse(full).success);
    assert.equal(full.partial, false);
    assert.equal(full.source, 'catalog_detail');
    assert.equal(full.recommendations.length, 6);
    assert.equal(full.tags[0].slug, 'level-system');
    assert.ok(full.synopsis.includes('Other paragraph'));
    assert.equal(full.synopsis_truncated, false);
    assert.doesNotMatch(JSON.stringify(full), /private-contributor|script|reviews/);
    const unavailable = { comic: { ...detail.comic, recommendations: undefined, mu_comic_categories: undefined } };
    globalThis.fetch = async () => Response.json(unavailable);
    const incomplete = await title({ slug: item.slug });
    assert.equal(incomplete.source, 'catalog_detail');
    assert.equal(incomplete.partial, true);
    assert.deepEqual(incomplete.missing_fields, ['tags', 'authors', 'artists', 'languages', 'recommendations']);
    assert.equal(incomplete.recommendations, undefined);
    globalThis.fetch = async () => Response.json({ ...detail, comic: { ...detail.comic, recommendations: [], mu_comic_categories: [] } });
    const empty = await title({ slug: item.slug });
    assert.equal(empty.partial, false);
    assert.deepEqual(empty.missing_fields, []);
    assert.equal(empty.recommendations, undefined);
    assert.equal(empty.tags, undefined);
    const expandedDetail = { ...detail, comic: { ...detail.comic, desc: 'x'.repeat(700),
      md_titles: Array.from({ length: 12 }, (_, i) => ({ title: `Alternative ${i}`, lang: 'en' })),
      md_comic_md_genres: manyGenres.map(md_genres => ({ md_genres })),
      mu_comic_categories: Array.from({ length: 7 }, (_, i) => ({ mu_categories: { title: `Tag ${i}`, slug: `tag-${i}` } })),
    } };
    globalThis.fetch = async () => Response.json(expandedDetail);
    const preview = await title({ slug: item.slug });
    assert.equal(preview.synopsis.length, 500);
    assert.equal(preview.synopsis_truncated, true);
    assert.equal(preview.genres.length, 8);
    assert.equal(preview.genres_truncated, true);
    assert.equal(preview.tags.length, 5);
    assert.equal(preview.tags_truncated, true);
    const expanded = await title({ slug: item.slug, detailed: true, synopsis_limit: 1000 });
    assert.equal(expanded.synopsis.length, 700);
    assert.equal(expanded.synopsis_truncated, false);
    assert.equal(expanded.alternative_titles.length, 12);
    assert.equal(expanded.genres.length, 12);
    assert.equal(expanded.tags.length, 7);
    assert.equal(expanded.recommendations.length, 6);

    for (const blocked of ['403', 'html']) {
      calls = [];
      globalThis.fetch = async url => {
        calls.push(String(url));
        if (url.pathname.includes('/comic/')) return blocked === '403' ? new Response(null, { status: 403 }) : new Response('<html>Challenge</html>');
        if (url.pathname === '/genre/') return Response.json(genres);
        return Response.json([{ ...item, hid: 'wrong', slug: 'wrong-title' }, item]);
      };
      const fallback = await title({ slug: item.slug });
      assert.equal(fallback.partial, true);
      assert.ok(fallback.warnings.some(value => /Public title details unavailable/.test(value)));
      assert.ok(fallback.missing_fields.includes('recommendations'));
      assert.equal(fallback.source, 'search');
      assert.ok(titleResult.safeParse(fallback).success);
      const fallbackFull = await title({ slug: item.slug, detailed: true });
      assert.ok(fallbackFull.missing_fields.includes('authors'));
      assert.equal(fallback.hid, item.hid);
      assert.equal(calls.filter(url => url.includes('/search/')).length, 2);
    }
    for (const wrong of [{ ...item, hid: 'wrong', slug: 'wrong-title' }, { ...item, media_type: 'anime' }]) {
      globalThis.fetch = async url => url.pathname.includes('/comic/') ? new Response(null, { status: 403 }) : Response.json([wrong]);
      await assert.rejects(title({ slug: item.slug }), error => error.code === 'details_unavailable');
    }
    globalThis.fetch = async url => url.pathname.includes('/comic/') ? new Response(null, { status: 403 }) : Response.json([item]);
    assert.equal((await title({ slug: item.hid })).hid, item.hid);
    for (const status of [404, 429, 500, 503]) {
      let count = 0;
      globalThis.fetch = async () => { count++; return new Response(null, { status }); };
      await assert.rejects(title({ slug: item.slug }), error => error.status === status);
      assert.equal(count, 1);
    }
    globalThis.fetch = async () => Response.json({ comic: { ...item, hid: 'wrong', slug: 'wrong-title' } });
    await assert.rejects(title({ slug: item.slug }), error => error.code === 'invalid_response');
    globalThis.fetch = async () => new Response('{bad', { headers: { 'content-type': 'application/json' } });
    await assert.rejects(search({}), error => error.code === 'invalid_response');
  } finally {
    globalThis.fetch = originalFetch;
    if (previousId === undefined) delete process.env.COMICK_CLIENT_ID;
    else process.env.COMICK_CLIENT_ID = previousId;
  }
});

test('scanlation groups summarize bounded latest releases without inventing sources', async () => {
  const { scanlations, scanlationsSchema, scanlationsOutput } = await import('./dist/catalog.js');
  const originalFetch = globalThis.fetch;
  let calls = 0;
  const row = { hid: 'Newest', chap: '9.5', title: null, lang: 'en', created_at: '2026-01-03T00:00:00Z', group_name: [' Raven ', 'raven', 'Asura'] };
  try {
    globalThis.fetch = async url => {
      calls++;
      assert.equal(url.pathname, '/v1.0/comic/TitleHid/chapters');
      assert.equal(url.searchParams.get('limit'), '4');
      assert.equal(url.searchParams.get('page'), '1');
      assert.equal(url.searchParams.get('lang'), 'en,id');
      assert.equal(url.searchParams.get('date-order'), '0');
      return Response.json({ chapters: [row,
        { ...row, hid: 'Older', chap: '100', lang: 'id', group_name: ['RAVEN'] },
        { ...row, hid: 'Missing', group_name: null },
        { ...row, hid: 'Empty', group_name: [] }], total: 20, limit: 4 });
    };
    const output = await scanlations({ hid: 'TitleHid', lang: 'en,id', limit: 4 });
    assert.ok(scanlationsOutput.safeParse(output).success);
    assert.equal(calls, 1);
    assert.equal(output.requested, 4);
    assert.equal(output.inspected, 4);
    assert.equal(output.releases_without_groups, 2);
    assert.deepEqual(output.groups.map(group => group.name), ['raven', 'Asura']);
    assert.equal(output.groups[0].release_count, 2);
    assert.deepEqual(output.groups[0].languages, ['en', 'id']);
    assert.equal(output.groups[0].latest_release.hid, 'Newest');
    assert.equal(output.groups[0].latest_release.number, '9.5');
    assert.equal('url' in output.groups[0], false);
    assert.equal(output.warnings.length, 2);
    assert.equal(scanlationsSchema.parse({ hid: 'TitleHid' }).limit, 10);
    for (const input of [{ hid: '../bad' }, { hid: 'Hid', limit: '5' }, { hid: 'Hid', limit: 0 },
      { hid: 'Hid', limit: 51 }, { hid: 'Hid', limit: 1.5 }, { hid: 'Hid', lang: 'English' }, { hid: 'Hid', page: 2 }]) {
      assert.equal(scanlationsSchema.safeParse(input).success, false);
    }
    const group = { title: 'QiScans', slug: 'qiscans', official: false, inactive: false };
    globalThis.fetch = async () => Response.json({ chapters: [
      { ...row, md_chapters_groups: [{ md_groups: group }, { md_groups: group }], identities: { private: 'DO_NOT_FORWARD' } },
      { ...row, hid: 'Other', md_chapters_groups: [{ md_groups: { ...group, title: 'Renamed', slug: 'qiscans' } }] },
      { ...row, hid: 'Different', md_chapters_groups: [{ md_groups: { ...group, slug: 'different-qiscans' } }] },
      { ...row, hid: 'KnownEmpty', md_chapters_groups: [] },
    ] });
    const direct = await scanlations({ hid: 'TitleHid', limit: 4 });
    assert.deepEqual(direct.groups.map(group => group.slug), ['qiscans', 'different-qiscans']);
    assert.equal(direct.groups[0].release_count, 2);
    assert.equal(direct.groups[0].official, false);
    assert.equal(direct.groups[0].inactive, false);
    assert.equal(direct.groups[0].name, 'QiScans');
    assert.equal(direct.releases_without_groups, 1);
    assert.doesNotMatch(JSON.stringify(direct), /DO_NOT_FORWARD|identities|Raven|Asura/);
    globalThis.fetch = async () => Response.json({ chapters: [{ ...row, md_chapters_groups: [{ md_groups: { ...group, slug: '../bad' } }] }] });
    await assert.rejects(scanlations({ hid: 'TitleHid' }), error => error.code === 'invalid_response');
    globalThis.fetch = async () => Response.json({ chapters: [], total: 0, limit: 10 });
    assert.deepEqual((await scanlations({ hid: 'Hid' })).groups, []);
    for (const response of [new Response(null, { status: 403 }), new Response('<html>Blocked</html>')]) {
      globalThis.fetch = async () => response;
      await assert.rejects(scanlations({ hid: 'Hid' }), error => error.code === 'scanlations_unavailable');
    }
    globalThis.fetch = async () => new Response(null, { status: 429, headers: { 'retry-after': '30' } });
    await assert.rejects(scanlations({ hid: 'Hid' }), error => error.code === 'rate_limited' && error.retryAfter === '30');
  } finally { globalThis.fetch = originalFetch; }
});

test('chapter paging, date order, language filters, reader links and safe failures', async () => {
  const { chapters, chaptersSchema, libraryEntrySchema } = await import('./dist/catalog.js');
  const originalFetch = globalThis.fetch;
  const row = { hid: 'ChapterHid', chap: '12.5', vol: '0', title: 'Special', lang: 'pt-br',
    publish_at: '2026-01-01T02:00:00+02:00', created_at: '2026-01-01T01:00:00+02:00', updated_at: null,
    group_name: ['Example'], identities: { private: 'DO_NOT_FORWARD' }, id: 10 };
  try {
    let count = 0;
    globalThis.fetch = async (url, options) => {
      count++;
      assert.equal(url.pathname, '/v1.0/comic/TitleHid/chapters');
      assert.equal(url.searchParams.get('date-order'), '0');
      assert.equal(url.searchParams.get('entry_type'), 'chapter');
      assert.equal(url.searchParams.get('page'), '2');
      assert.equal(url.searchParams.get('limit'), '2');
      assert.equal(url.searchParams.get('lang'), 'en,pt-br,es-419');
      assert.equal(url.searchParams.has('slug'), false);
      assert.equal(options.headers, undefined);
      assert.equal(options.credentials, 'omit');
      return Response.json({ chapters: [row, { ...row, hid: 'ZeroHid', chap: '0' }], total: 20, limit: 2 });
    };
    const page = await chapters({ hid: 'TitleHid', slug: 'known-title', lang: 'en,pt-br,es-419', page: 2, limit: 2, detailed: true });
    assert.equal(count, 1);
    assert.equal(page.total, 20);
    assert.equal(page.order, 'newest_created_first');
    assert.equal(page.items[0].number, '12.5');
    assert.equal(page.items[0].volume, '0');
    assert.equal(page.items[1].number, '0');
    assert.equal(page.items[0].url, 'https://comick.dev/comic/known-title/ChapterHid');
    assert.equal(page.items[0].released_at, row.publish_at);
    assert.doesNotMatch(JSON.stringify(page), /DO_NOT_FORWARD|identities/);
    globalThis.fetch = async url => {
      assert.equal(url.searchParams.get('limit'), '5');
      assert.equal(url.searchParams.has('detailed'), false);
      return Response.json({ chapters: [{ ...row, chap: 'Extra' }], total: 1, limit: 5 });
    };
    const withoutSlug = await chapters({ hid: 'TitleHid' });
    assert.equal(withoutSlug.items[0].url, null);
    assert.equal(withoutSlug.items[0].number, 'Extra');
    assert.deepEqual(Object.keys(withoutSlug.items[0]).sort(), ['hid', 'lang', 'number', 'title', 'url']);
    assert.equal(withoutSlug.entry_type, 'chapter');
    assert.equal(withoutSlug.warnings.length, 1);
    globalThis.fetch = async () => Response.json({ chapters: [], total: 0, limit: 12 });
    assert.equal((await chapters({ hid: 'TitleHid' })).items.length, 0);
    for (const invalid of [{ hid: '../bad' }, { hid: 'Hid', lang: '' }, { hid: 'Hid', lang: 'en,' },
      { hid: 'Hid', page: 0 }, { hid: 'Hid', limit: 51 }, { hid: 'Hid', slug: '../bad' }, { hid: 'Hid', token: 'secret' }]) {
      assert.equal(chaptersSchema.safeParse(invalid).success, false);
    }
    assert.equal(libraryEntrySchema.safeParse({ hid: 'Hid', user_id: 'other' }).success, false);
    for (const malformed of [{ ...row, hid: '../bad' }, { ...row, chap: 12.5 }, { ...row, publish_at: 'not-a-date' }]) {
      globalThis.fetch = async () => Response.json({ chapters: [malformed], total: 1, limit: 12 });
      await assert.rejects(chapters({ hid: 'TitleHid' }), error => error.code === 'invalid_response');
    }
    for (const status of [403, 404, 429, 503]) {
      globalThis.fetch = async () => new Response(null, { status, headers: { 'retry-after': '60' } });
      await assert.rejects(chapters({ hid: 'TitleHid' }), error => error.status === status && error.retryAfter === '60');
    }
    globalThis.fetch = async () => new Response('<html>Challenge</html>');
    await assert.rejects(chapters({ hid: 'TitleHid' }), error => error.code === 'non_json_response');
  } finally { globalThis.fetch = originalFetch; }
});

test('chapter detail, bounded image metadata, episodes and tracker identifiers', async () => {
  const { chapterDetail, chapterDetailSchema, chapterImages, chapterImagesSchema, chapters, search, title } = await import('./dist/catalog.js');
  const originalFetch = globalThis.fetch;
  const parent = { hid: 'TitleHid', slug: 'sample', title: 'Sample', media_type: 'manga',
    links: { urls: { raw: ['https://publisher.example/title'], engtl: [{ url: 'https://publisher.example/en/title', lang: 'en' }] } } };
  const row = { hid: 'ChapterHid', entry_type: 'chapter', chap: '12.5', vol: '0', title: null, lang: 'en',
    group_name: ['Group'], external: null, external_type: null, md_images: [], md_comics: parent,
    identities: { private: 'DO_NOT_FORWARD' }, uploader_notes: 'DO_NOT_FORWARD' };
  try {
    globalThis.fetch = async (url, options) => {
      assert.equal(url.pathname, '/chapter/ChapterHid/');
      assert.equal(url.search, '');
      assert.equal(options.headers, undefined);
      return Response.json({ chapter: row, next: { hid: 'Next', chap: '13', lang: 'en', id: 123 }, prev: null });
    };
    const detail = await chapterDetail({ hid: 'ChapterHid' });
    assert.equal(detail.hid, 'ChapterHid');
    assert.equal(detail.parent.hid, 'TitleHid');
    assert.equal(detail.number, '12.5');
    assert.equal(detail.image_count, 0);
    assert.equal(detail.external_url, null);
    assert.equal(detail.next.hid, 'Next');
    assert.deepEqual(detail.source_links.map(link => link.kind), ['raw', 'engtl']);
    assert.doesNotMatch(JSON.stringify(detail), /DO_NOT_FORWARD|identities|uploader_notes|"id"/);
    for (const [external, expected] of [['https://reader.example/chapter/12', 'https://reader.example/chapter/12'],
      ['provider-slug', null], ['javascript:alert(1)', null], ['https://user:secret@example.test', null]]) {
      globalThis.fetch = async () => Response.json({ chapter: { ...row, external } });
      assert.equal((await chapterDetail({ hid: 'ChapterHid' })).external_url, expected);
    }
    globalThis.fetch = async () => Response.json({ chapter: { ...row, md_images: undefined } });
    assert.equal((await chapterDetail({ hid: 'ChapterHid' })).image_count, null);
    globalThis.fetch = async () => Response.json({ chapter: { ...row, entry_type: 'episode', md_comics: { ...parent, media_type: 'anime' } } });
    const episode = await chapterDetail({ hid: 'ChapterHid' });
    assert.equal(episode.entry_type, 'episode');
    assert.equal(episode.image_count, null);
    for (const malformed of [{ ...row, hid: 'Wrong' }, { ...row, entry_type: 'episode' },
      { ...row, md_comics: { ...parent, links: { urls: { raw: ['javascript:bad'] } } } }]) {
      globalThis.fetch = async () => Response.json({ chapter: malformed });
      await assert.rejects(chapterDetail({ hid: 'ChapterHid' }), error => error.code === 'invalid_response');
    }
    const images = [{ b2key: 'one.jpg', w: 800, h: 1200, private: 'DO_NOT_FORWARD' },
      { b2key: 'two.jpg', url: 'https://images.example/two.jpg', w: 800, h: 1000 }, { b2key: 'three.jpg' }];
    globalThis.fetch = async url => {
      assert.equal(url.pathname, '/chapter/ChapterHid/get_images');
      assert.equal(url.search, '');
      return Response.json(images);
    };
    const first = await chapterImages({ hid: 'ChapterHid', limit: 2 });
    assert.equal(first.total, 3);
    assert.equal(first.items.length, 2);
    assert.equal(first.next_offset, 2);
    assert.equal(first.items[0].url, undefined);
    assert.equal(first.items[1].url, images[1].url);
    assert.doesNotMatch(JSON.stringify(first), /DO_NOT_FORWARD|meo.comick/);
    const last = await chapterImages({ hid: 'ChapterHid', offset: first.next_offset, limit: 2 });
    assert.equal(last.items[0].b2key, 'three.jpg');
    assert.equal(last.next_offset, null);
    globalThis.fetch = async () => Response.json([]);
    assert.equal((await chapterImages({ hid: 'ChapterHid' })).total, 0);
    for (const malformed of [{ images: [] }, [{ nope: 'unexpected' }], [{ b2key: 'one', url: 'file:///private' }]]) {
      globalThis.fetch = async () => Response.json(malformed);
      await assert.rejects(chapterImages({ hid: 'ChapterHid' }), error => error.code === 'invalid_response');
    }
    globalThis.fetch = async url => {
      assert.equal(url.searchParams.get('entry_type'), 'episode');
      return Response.json({ chapters: [{ hid: 'EpisodeHid', chap: '3', lang: 'ja' }], total: 1, limit: 5 });
    };
    const episodes = await chapters({ hid: 'TitleHid', slug: 'sample', entry_type: 'episode' });
    assert.equal(episodes.entry_type, 'episode');
    assert.equal(episodes.items[0].url, null);
    assert.match(episodes.warnings[0], /no reader images/);
    const external_ids = { anilist: '000123', myanimelist: null, mangabaka: '789', mangaupdates: 'abc123' };
    const item = { hid: 'TitleHid', slug: 'sample', title: 'Sample', external_ids };
    globalThis.fetch = async url => Response.json(url.pathname.includes('/search') ? [item] : { comic: item });
    assert.deepEqual((await search({ detailed: true })).items[0].external_ids, external_ids);
    assert.equal((await search({})).items[0].external_ids, undefined);
    assert.deepEqual((await title({ slug: 'sample', detailed: true })).external_ids, external_ids);
    assert.equal((await title({ slug: 'sample' })).external_ids, undefined);
    globalThis.fetch = async () => Response.json([{ ...item, external_ids: undefined }]);
    assert.equal((await search({ detailed: true })).items[0].external_ids, null);
    for (const schema of [chapterDetailSchema, chapterImagesSchema]) assert.equal(schema.safeParse({ hid: '../bad' }).success, false);
    for (const input of [{ hid: 'Hid', offset: -1 }, { hid: 'Hid', limit: 51 }, { hid: 'Hid', limit: '5' }]) assert.equal(chapterImagesSchema.safeParse(input).success, false);
    for (const operation of [chapterDetail, chapterImages]) {
      globalThis.fetch = async () => new Response(null, { status: 403 });
      await assert.rejects(operation({ hid: 'Hid' }), error => error.status === 403);
      globalThis.fetch = async () => new Response('<html>Challenge</html>');
      await assert.rejects(operation({ hid: 'Hid' }), error => error.code === 'non_json_response');
    }
  } finally { globalThis.fetch = originalFetch; }
});

test('real MCP stdio handshake, tool listing, validation and missing login', async () => {
  const transport = new StdioClientTransport({
    command: process.execPath, args: [`${root}dist/index.js`],
    env: { PATH: process.env.PATH ?? '' }, stderr: 'pipe',
  });
  const client = new Client({ name: 'comick-self-check', version: '1.0.0' });
  try {
    await client.connect(transport);
    const { tools } = await client.listTools();
    assert.deepEqual(tools.map(tool => tool.name).sort(), ['comick_chapter', 'comick_chapter_images', 'comick_chapters', 'comick_connect', 'comick_disconnect', 'comick_filters', 'comick_library', 'comick_library_entry', 'comick_library_remove', 'comick_library_save', 'comick_me', 'comick_scanlations', 'comick_search', 'comick_title']);
    for (const name of ['comick_search', 'comick_filters']) {
      const schema = tools.find(tool => tool.name === name).inputSchema;
      assert.ok(schema.properties.query);
      assert.equal(schema.properties.q, undefined);
    }
    const libraryInput = tools.find(tool => tool.name === 'comick_library').inputSchema;
    assert.ok(!libraryInput.required?.includes('cursor'));
    assert.match(libraryInput.properties.cursor.description, /first page.*next_cursor/);
    assert.ok(tools.filter(tool => !['comick_connect', 'comick_disconnect', 'comick_library_save', 'comick_library_remove'].includes(tool.name)).every(tool => tool.annotations.readOnlyHint));
    for (const name of ['comick_library_save', 'comick_library_remove']) {
      const tool = tools.find(tool => tool.name === name);
      assert.equal(tool.annotations.readOnlyHint, false);
      assert.equal(tool.annotations.destructiveHint, true);
      assert.equal(tool.annotations.idempotentHint, true);
      assert.ok(tool.outputSchema);
    }
    const disconnect = tools.find(tool => tool.name === 'comick_disconnect');
    assert.equal(disconnect.annotations.destructiveHint, true);
    assert.equal(disconnect.annotations.idempotentHint, true);
    for (const name of ['comick_search', 'comick_title', 'comick_filters', 'comick_disconnect', 'comick_library_entry', 'comick_chapters', 'comick_me', 'comick_library']) assert.ok(tools.find(tool => tool.name === name).outputSchema);
    assert.ok(tools.find(tool => tool.name === 'comick_scanlations').outputSchema);
    for (const name of ['comick_chapter', 'comick_chapter_images']) assert.ok(tools.find(tool => tool.name === name).outputSchema);
    assert.equal(tools.find(tool => tool.name === 'comick_connect').annotations.readOnlyHint, false);
    const connection = await client.callTool({ name: 'comick_connect', arguments: { action: 'start' } });
    assert.equal(connection.isError, true);
    assert.match(connection.content[0].text, /COMICK_CLIENT_ID/);
    assert.equal(JSON.parse(connection.content[0].text).error.code, 'configuration_required');
    const invalid = await client.callTool({ name: 'comick_library', arguments: { limit: 101 } });
    assert.equal(invalid.isError, true);
    assert.doesNotMatch(invalid.content[0].text, /COMICK_CLIENT_ID/);
    const invalidLimit = JSON.parse(invalid.content[0].text).error;
    assert.equal(invalidLimit.code, 'invalid_input');
    assert.equal(invalidLimit.retryable, false);
    assert.deepEqual(invalidLimit.issues[0].path, ['limit']);
    assert.equal(invalidLimit.issues[0].expected.type, 'integer');
    assert.equal(invalidLimit.issues[0].expected.minimum, 1);
    assert.equal(invalidLimit.issues[0].expected.maximum, 100);
    assert.match(invalidLimit.issues[0].recommendation, /integer.*>= 1.*<= 100/);
    for (const [name, args, path, type] of [
      ['comick_search', { limit: '5' }, ['limit'], 'integer'],
      ['comick_search', { limit: 1.5 }, ['limit'], 'integer'],
      ['comick_search', { country: [5] }, ['country', 0], 'string'],
      ['comick_title', {}, ['slug'], 'string'],
      ['comick_filters', { page: null }, ['page'], 'integer'],
      ['comick_chapters', { hid: 42 }, ['hid'], 'string'],
      ['comick_scanlations', { hid: 'Hid', limit: '5' }, ['limit'], 'integer'],
      ['comick_library_entry', { hid: false }, ['hid'], 'string'],
      ['comick_library_save', { hid: 'Hid', rating: '8' }, ['rating'], 'integer'],
      ['comick_library_save', { hid: 'Hid', status: 6 }, ['status'], 'integer'],
      ['comick_me', { detailed: 'false' }, ['detailed'], 'boolean'],
      ['comick_connect', { open_browser: 'false' }, ['open_browser'], 'boolean'],
    ]) {
      const response = await client.callTool({ name, arguments: args });
      assert.equal(response.isError, true);
      const failure = JSON.parse(response.content[0].text).error;
      assert.equal(failure.code, 'invalid_input');
      assert.deepEqual(failure.issues[0].path, path);
      assert.equal(failure.issues[0].expected.type, type);
      assert.ok(failure.issues[0].recommendation);
      assert.match(failure.message, /No request was executed/);
    }
    const enumError = await client.callTool({ name: 'comick_filters', arguments: { kind: 'DO_NOT_ECHO_SECRET' } });
    const enumFailure = JSON.parse(enumError.content[0].text).error;
    assert.deepEqual(enumFailure.issues[0].expected.enum, ['genres', 'tags']);
    assert.match(enumFailure.issues[0].recommendation, /genres.*tags/);
    assert.doesNotMatch(enumError.content[0].text, /DO_NOT_ECHO_SECRET/);
    const rangeError = await client.callTool({ name: 'comick_search', arguments: { minimum: 20, maximum: 10 } });
    assert.match(JSON.parse(rangeError.content[0].text).error.issues[0].recommendation, /maximum must be at least minimum/);
    const tooMany = await client.callTool({ name: 'comick_search', arguments: { country: Array(10).fill(123), genres: [false] } });
    const bounded = JSON.parse(tooMany.content[0].text).error;
    assert.equal(bounded.issues.length, 10);
    assert.equal(bounded.issues_truncated, true);
    for (const [name, args] of [['comick_search', { minimum: 20, maximum: 10 }],
      ['comick_search', { genres: Array(11).fill('action') }], ['comick_title', { slug: '../me' }],
      ['comick_library_entry', { hid: '../me' }], ['comick_chapters', { hid: 'Hid', lang: 'en/../../' }],
      ['comick_chapters', { hid: 'Hid', page: 0 }], ['comick_chapters', { hid: 'Hid', limit: 51 }],
      ['comick_filters', { kind: 'unknown' }], ['comick_disconnect', { token: 'secret' }], ['comick_connect', { action: 'start', token: 'secret' }]]) {
      const rejected = await client.callTool({ name, arguments: args });
      assert.equal(rejected.isError, true);
      const failure = JSON.parse(rejected.content[0].text).error;
      assert.equal(failure.code, 'invalid_input');
      assert.ok(failure.issues.every(issue => issue.recommendation));
      assert.doesNotMatch(rejected.content[0].text, /secret/);
    }
    for (const args of [{ hid: 'Hid' }, { hid: 'Hid', action: 'upsert', rating: 8 },
      { hid: 'Hid', progress: { number: 12 } }, { hid: 'Hid', progress: { hid: 'ChapterHid', number: '12' } }]) {
      const rejected = await client.callTool({ name: 'comick_library_save', arguments: args });
      assert.equal(rejected.isError, true);
      assert.equal(JSON.parse(rejected.content[0].text).error.code, 'invalid_input');
    }
    const unconfirmed = await client.callTool({ name: 'comick_library_remove', arguments: { hid: 'Hid' } });
    assert.equal(JSON.parse(unconfirmed.content[0].text).error.code, 'invalid_input');
    for (const [name, args] of [['comick_library_save', { hid: 'Hid', rating: 8 }], ['comick_library_remove', { hid: 'Hid', confirm: true }]]) {
      const response = await client.callTool({ name, arguments: args });
      assert.equal(JSON.parse(response.content[0].text).error.code, 'configuration_required');
    }
    const result = await client.callTool({ name: 'comick_me', arguments: {} });
    assert.equal(result.isError, true);
    assert.match(result.content[0].text, /COMICK_CLIENT_ID/);
    const entry = await client.callTool({ name: 'comick_library_entry', arguments: { hid: 'KnownHid' } });
    assert.equal(entry.isError, true);
    assert.equal(JSON.parse(entry.content[0].text).error.code, 'configuration_required');
  } finally {
    await client.close();
    await transport.close();
  }
});

test('all 14 MCP tools: deterministic contracts, validation, failures and request effects', async t => {
  const directory = await mkdtemp(`${root}.test-`);
  const scenario = `${directory}/scenario.json`;
  const requests = `${directory}/requests.jsonl`;
  await writeFile(scenario, JSON.stringify({ mode: 'normal' }));
  await writeFile(requests, '');
  const probe = createServer();
  probe.listen(0, '127.0.0.1');
  await once(probe, 'listening');
  const redirect = `http://127.0.0.1:${probe.address().port}/callback`;
  await new Promise(resolve => probe.close(resolve));
  const transport = new StdioClientTransport({
    command: process.execPath, args: ['--import', pathToFileURL(`${root}test/mcp-upstream.mjs`).href, `${root}dist/index.js`],
    env: { PATH: process.env.PATH ?? '', COMICK_CLIENT_ID: 'mock-stdio', XDG_STATE_HOME: directory,
      COMICK_REDIRECT_URI: redirect, COMICK_TEST_SCENARIO: scenario, COMICK_TEST_REQUESTS: requests }, stderr: 'pipe',
  });
  const client = new Client({ name: 'comick-contract-self-check', version: '1.0.0' });
  let stderr = '';
  transport.stderr?.on('data', chunk => { stderr += chunk; });
  const calls = async () => (await readFile(requests, 'utf8')).trim().split('\n').filter(Boolean).map(line => JSON.parse(line));
  const setMode = mode => writeFile(scenario, JSON.stringify({ mode }));
  const call = async (name, args) => {
    const response = await client.callTool({ name, arguments: args });
    assert.equal(response.content.length, 1);
    assert.equal(response.content[0].type, 'text');
    assert.doesNotMatch(JSON.stringify(response), /DO_NOT_LEAK_TOKEN|MOCK_ACCESS|MOCK_REFRESH/);
    const value = JSON.parse(response.content[0].text);
    if (response.isError) {
      assert.equal(response.structuredContent, undefined);
      assert.equal(typeof value.error.code, 'string');
      if (value.error.code === 'invalid_input') assert.ok(value.error.issues.every(issue => typeof issue.recommendation === 'string'));
      else assert.equal(typeof value.error.recommendation, 'string');
    } else assert.deepEqual(response.structuredContent, value);
    return { response, value };
  };
  const catalogCases = [
    ['comick_search', {}, '/v1.0/search/'],
    ['comick_filters', {}, '/genre/'],
    ['comick_title', { slug: 'sample' }, '/v1.0/comic/sample/'],
    ['comick_chapters', { hid: 'Hid' }, '/v1.0/comic/Hid/chapters'],
    ['comick_scanlations', { hid: 'Hid' }, '/v1.0/comic/Hid/chapters'],
    ['comick_chapter', { hid: 'ChapterHid' }, '/chapter/ChapterHid/'],
    ['comick_chapter_images', { hid: 'ChapterHid' }, '/chapter/ChapterHid/get_images'],
  ];
  const accountCases = [
    ['comick_me', {}, '/integrations/v1/me'],
    ['comick_library', {}, '/integrations/v1/me/library'],
    ['comick_library_entry', { hid: 'Hid' }, '/integrations/v1/me/library/Hid'],
  ];
  const writeCases = [
    ['comick_library_save', { hid: 'Hid', rating: 8 }, '/integrations/v1/me/library/Hid'],
    ['comick_library_remove', { hid: 'Hid', confirm: true }, '/integrations/v1/me/library/Hid'],
  ];
  const cases = [...catalogCases, ...accountCases, ...writeCases,
    ['comick_connect', { action: 'status' }], ['comick_disconnect', {}]];
  try {
    await client.connect(transport);
    const { tools } = await client.listTools();
    const catalog = await import('./dist/catalog.js');
    const oauth = await import('./dist/oauth.js');
    const outputs = { comick_search: catalog.searchOutput, comick_filters: catalog.filtersOutput, comick_title: catalog.titleResult,
      comick_chapters: catalog.chaptersOutput, comick_scanlations: catalog.scanlationsOutput, comick_chapter: catalog.chapterDetailOutput,
      comick_chapter_images: catalog.chapterImagesOutput, comick_me: catalog.meOutput, comick_library: catalog.libraryOutput,
      comick_library_entry: catalog.libraryEntryResult, comick_library_save: catalog.libraryEntryResult,
      comick_library_remove: catalog.libraryRemoveOutput, comick_disconnect: oauth.disconnectOutput };
    assert.deepEqual(cases.map(([name]) => name).sort(), tools.map(tool => tool.name).sort(), 'Every registered tool must have a contract case');
    for (const [name, args] of cases) await t.test(`${name}: invalid input has no upstream effects`, async () => {
      const before = await calls();
      const { response, value } = await call(name, { ...args, DO_NOT_LEAK_TOKEN: 'DO_NOT_LEAK_TOKEN' });
      assert.equal(response.isError, true);
      assert.equal(value.error.code, 'invalid_input');
      assert.equal(value.error.retryable, false);
      assert.ok(value.error.issues.some(issue => issue.code === 'unrecognized_keys'));
      assert.deepEqual(await calls(), before);
    });
    for (const [name, args, path] of [...catalogCases, ...accountCases, ...writeCases]) await t.test(`${name}: stable success and exact request count`, async () => {
      const count = (await calls()).length;
      const first = await call(name, args);
      const second = await call(name, args);
      assert.notEqual(first.response.isError, true);
      assert.ok(outputs[name].safeParse(first.value).success, `${name} must satisfy its output contract`);
      assert.deepEqual(first.response, second.response);
      const sent = (await calls()).slice(count);
      assert.equal(sent.length, 2);
      assert.ok(sent.every(request => request.path === path));
      assert.ok(sent.every(request => request.method === (name === 'comick_library_save' ? 'PATCH' : name === 'comick_library_remove' ? 'DELETE' : 'GET')));
      if (name === 'comick_library_save') assert.deepEqual(sent[0].body, { rating: 8 });
      if (name === 'comick_library_remove') assert.equal(sent[0].body, null);
      if (name === 'comick_search') {
        assert.deepEqual(first.value.items, [{ hid: 'Hid', slug: 'sample', title: 'Sample' }]);
        assert.equal(first.value.limit, 5);
      }
      if (name === 'comick_me') assert.deepEqual(first.value, { id: '12345678-1234-4123-8123-123456789abc', username: 'Reader' });
      if (name === 'comick_library_entry') assert.equal(first.value.data.progress.number, '12.5');
    });
    for (const [name, args] of [...catalogCases, ...accountCases, ...writeCases]) {
      for (const mode of ['network', 'rate_limit', 'forbidden', 'malformed', 'html']) await t.test(`${name}: ${mode} is safe and repeatable`, async () => {
        await setMode(mode);
        const before = (await calls()).length;
        const first = await call(name, args);
        const second = await call(name, args);
        assert.equal(first.response.isError, true);
        assert.deepEqual(first.response, second.response);
        const writing = writeCases.some(([tool]) => tool === name);
        const expected = mode === 'rate_limit' ? 'rate_limited'
          : mode === 'forbidden' ? writing ? 'write_permission_required' : name === 'comick_scanlations' ? 'scanlations_unavailable' : catalogCases.some(([tool]) => tool === name) ? 'catalog_error' : 'api_error'
          : writing ? 'write_outcome_unknown'
            : mode === 'network' ? 'network_error'
              : mode === 'html' && name === 'comick_scanlations' ? 'scanlations_unavailable'
                : mode === 'html' && catalogCases.some(([tool]) => tool === name) ? 'non_json_response'
                  : 'invalid_response';
        assert.equal(first.value.error.code, expected);
        if (mode === 'rate_limit') {
          assert.equal(first.value.error.retry_after, '30');
          assert.equal(first.value.error.status, 429);
        }
        const sent = (await calls()).slice(before);
        assert.equal(sent.length, name === 'comick_title' && ['html', 'forbidden'].includes(mode) ? 4 : 2, 'No hidden retries or unexpected calls');
      });
    }
    await setMode('empty');
    for (const [name, args, key] of [
      ['comick_search', {}, 'items'], ['comick_filters', {}, 'items'], ['comick_library', {}, 'data'],
      ['comick_chapters', { hid: 'Hid' }, 'items'], ['comick_scanlations', { hid: 'Hid' }, 'groups'],
      ['comick_chapter_images', { hid: 'ChapterHid' }, 'items'],
    ]) await t.test(`${name}: known empty is a successful empty list`, async () => {
      const { response, value } = await call(name, args);
      assert.notEqual(response.isError, true);
      assert.deepEqual(value[key], []);
    });
    await setMode('normal');
    await t.test('library save: read-back preserves fields and idempotent values', async () => {
      const before = (await call('comick_library_entry', { hid: 'Hid' })).value.data;
      const args = { hid: 'Hid', action: 'upsert', status: 5, progress: { number: '0', volume: '0' } };
      const first = await call('comick_library_save', args);
      assert.equal(first.value.data.rating, before.rating);
      assert.deepEqual(first.response, (await call('comick_library_save', args)).response);
      assert.deepEqual(first.value.data, (await call('comick_library_entry', { hid: 'Hid' })).value.data);
      const cleared = await call('comick_library_save', { hid: 'Hid', progress: null, rating: null });
      assert.equal(cleared.value.data.progress, null);
      assert.equal(cleared.value.data.rating, null);
      assert.equal(cleared.value.data.status_name, 'plan_to_read');
    });
    await t.test('connect start: PKCE consent flow completes through real MCP and loopback callback', async () => {
      const count = (await calls()).length;
      const started = await call('comick_connect', { action: 'start', open_browser: false });
      assert.notEqual(started.response.isError, true);
      assert.equal(started.value.status, 'pending');
      const authorization = new URL(started.value.authorization_url);
      assert.equal(authorization.origin, 'https://comick.dev');
      assert.equal(authorization.searchParams.get('scope'), 'library:read library:write offline_access');
      assert.equal(authorization.searchParams.get('code_challenge_method'), 'S256');
      assert.match(authorization.searchParams.get('code_challenge'), /^[A-Za-z0-9_-]{43}$/);
      assert.equal(authorization.searchParams.get('redirect_uri'), redirect);
      assert.equal((await call('comick_connect', { action: 'start', open_browser: false })).value.authorization_url, authorization.href);
      const callback = new URL(redirect);
      callback.search = new URLSearchParams({ state: authorization.searchParams.get('state'), code: 'mock-code' });
      const response = await fetch(callback);
      assert.equal(response.status, 200);
      assert.doesNotMatch(await response.text(), /mock-code|MOCK_ACCESS|MOCK_REFRESH/);
      let status;
      for (let attempt = 0; attempt < 200; attempt++) {
        status = (await call('comick_connect', { action: 'status' })).value;
        if (status.status !== 'pending') break;
        await new Promise(resolve => setTimeout(resolve, 10));
      }
      assert.equal(status.status, 'connected');
      const sent = (await calls()).slice(count);
      assert.deepEqual(sent.map(request => [request.path, request.method]), [['/api/auth/oauth2/token', 'POST']]);
    });
    await t.test('connect status: stable public summary without exposing tokens', async () => {
      const before = await calls();
      const first = await call('comick_connect', { action: 'status' });
      assert.notEqual(first.response.isError, true);
      assert.equal(first.value.status, 'connected');
      assert.equal(first.value.scope, 'library:read library:write offline_access');
      assert.deepEqual(first.response, (await call('comick_connect', { action: 'status' })).response);
      assert.deepEqual(await calls(), before);
    });
    await setMode('keyring_error');
    for (const [name, args] of [['comick_connect', { action: 'status' }], ['comick_disconnect', {}]]) await t.test(`${name}: credential backend failure`, async () => {
      const before = await calls();
      const { response, value } = await call(name, args);
      assert.equal(response.isError, true);
      assert.equal(value.error.code, 'credential_store_failed');
      assert.deepEqual(await calls(), before);
    });
    await setMode('normal');
    await t.test('disconnect: successful revocation and local deletion over real MCP', async () => {
      const before = (await calls()).length;
      const { response, value } = await call('comick_disconnect', {});
      assert.notEqual(response.isError, true);
      assert.equal(value.revocation, 'complete');
      assert.equal(value.local_deleted, true);
      assert.deepEqual(value.warnings, []);
      assert.deepEqual((await calls()).slice(before).map(request => [request.path, request.method]),
        [['/api/auth/oauth2/revoke', 'POST'], ['/api/auth/oauth2/revoke', 'POST']]);
      const started = (await call('comick_connect', { action: 'start', open_browser: false })).value;
      const callback = new URL(redirect);
      callback.search = new URLSearchParams({ state: new URL(started.authorization_url).searchParams.get('state'), code: 'mock-code' });
      assert.equal((await fetch(callback)).status, 200);
      let status;
      for (let attempt = 0; attempt < 200; attempt++) {
        status = (await call('comick_connect', { action: 'status' })).value;
        if (status.status !== 'pending') break;
        await new Promise(resolve => setTimeout(resolve, 10));
      }
      assert.equal(status.status, 'connected');
    });
    await setMode('network');
    await t.test('disconnect: unconfirmed remote revocation is not reported as complete', async () => {
      const before = (await calls()).length;
      const { response, value } = await call('comick_disconnect', {});
      assert.notEqual(response.isError, true);
      assert.equal(value.local_deleted, true);
      assert.equal(value.revocation, 'failed');
      assert.equal(value.warnings.length, 3);
      assert.equal((await calls()).length - before, 2);
      const again = await call('comick_disconnect', {});
      assert.equal(again.value.revocation, 'not_needed');
      assert.equal((await calls()).length - before, 2);
      assert.equal((await call('comick_connect', { action: 'status' })).value.status, 'disconnected');
    });
    assert.doesNotMatch(stderr, /DO_NOT_LEAK_TOKEN|MOCK_ACCESS|MOCK_REFRESH/);
  } finally {
    await client.close();
    await transport.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test('local connect UI only serves loopback status and same-origin connect', async () => {
  const { createUiServer } = await import('./dist/ui.js');
  const server = createUiServer();
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const origin = `http://127.0.0.1:${server.address().port}`;
  const previousId = process.env.COMICK_CLIENT_ID;
  delete process.env.COMICK_CLIENT_ID;
  try {
    const page = await fetch(origin);
    const html = await page.text();
    assert.equal(page.status, 200);
    assert.match(html, /Connect Comick|Reload status/);
    assert.match(html, /<html lang="en">/);
    assert.match(html, /Loading status…/);
    assert.match(html, /After approving access on Comick/);
    assert.match(html, /Another sign-in process is still running/);
    assert.match(html, /color-scheme:\s*dark/);
    assert.match(html, /focus-visible/);
    assert.match(page.headers.get('content-security-policy'), /script-src 'nonce-/);
    assert.equal(page.headers.get('cache-control'), 'no-store');
    assert.equal((await fetch(`${origin}/status`)).status, 503);
    assert.equal((await fetch(`${origin}/connect`, { method: 'POST', headers: { Origin: 'https://other.example', 'Content-Type': 'application/json' } })).status, 403);
    const connect = await fetch(`${origin}/connect`, { method: 'POST', headers: { Origin: origin, 'Content-Type': 'application/json' } });
    assert.equal(connect.status, 503);
    assert.match((await connect.json()).error, /COMICK_CLIENT_ID/);
    const hostileStatus = await new Promise((resolve, reject) => {
      const request = httpRequest(origin, { headers: { Host: 'attacker.example' } }, response => { response.resume(); resolve(response.statusCode); });
      request.on('error', reject).end();
    });
    assert.equal(hostileStatus, 404);
    assert.equal((await fetch(`${origin}/callback?code=secret`)).status, 404);
  } finally {
    if (previousId === undefined) delete process.env.COMICK_CLIENT_ID;
    else process.env.COMICK_CLIENT_ID = previousId;
    await new Promise(resolve => server.close(resolve));
  }
});
