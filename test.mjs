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
    await copyFile(`${root}dist/integration.js`, `${directory}/dist/integration.js`);
    await copyFile(`${root}dist/api.js`, `${directory}/dist/api.js`);
    const oauth = await import(pathToFileURL(`${directory}/dist/oauth.js`).href);
    const api = await import(pathToFileURL(`${directory}/dist/api.js`).href);
    const integration = await import(pathToFileURL(`${directory}/dist/integration.js`).href);
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
    assert.match(await firstCallback.text(), /Return to your MCP client or connection page/);
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
      assert.doesNotMatch(callbackHtml, /href="http:\/\/127\.0\.0\.1:/);
      assert.doesNotMatch(callbackHtml, /test-code|access-new|refresh-new|check the terminal/);
      const connected = await waitForLogin();
      assert.equal(connected.status, 'connected');
      assert.equal(connected.refresh_available, true);
      assert.doesNotMatch(JSON.stringify(connected), /access-new|refresh-new|access_token|refresh_token/);
      await assert.rejects(stat(`${directory}/.comick/tokens.json`), { code: 'ENOENT' });

      const denied = await oauth.connect('start', false);
      callback.search = new URLSearchParams({ state: new URL(denied.authorization_url).searchParams.get('state'), error: 'access_denied' });
      assert.equal((await originalFetch(callback)).status, 400);
      const afterDenied = await waitForLogin();
      assert.equal(afterDenied.status, 'saved');
      assert.match(afterDenied.last_login_error, /authorization denied/);
      assert.equal(JSON.parse(credential).access_token, 'access-new');
      assert.equal(browserCalls(), platform === 'linux' ? 1 : 0);
      browser.mock.mockImplementation((command, args, options, done) => command === 'secret-tool' || command === 'powershell.exe'
        ? keyringExec(command, args, options, done) : done(new Error('no desktop browser')));
      const manual = await oauth.connect('start');
      assert.equal(manual.browser_opened, false);
      assert.match(manual.browser_message, /manually/);
      callback.search = new URLSearchParams({ state: new URL(manual.authorization_url).searchParams.get('state'), error: 'access_denied' });
      assert.equal((await originalFetch(callback)).status, 400);
      assert.equal((await waitForLogin()).status, 'saved');
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
      const { open } = await import('node:fs/promises');
      await assert.rejects(open(`${directory}/comick-mcp/${createHash('sha256').update('test-public-client').digest('hex')}.lock`, 'wx'), { code: 'EEXIST' });
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
    assert.deepEqual(await api.apiRequest('/me/library', { query: { limit: 10, cursor: 'opaque+/=' } }), { data: [], next_cursor: null });
    assert.equal(calls.length, 3);
    assert.equal(new URL(calls[0]).searchParams.get('cursor'), 'opaque+/=');

    await store();
    let concurrentRefreshes = 0;
    globalThis.fetch = async () => { concurrentRefreshes++; return tokenResponse(); };
    assert.deepEqual(await Promise.all(Array.from({ length: 10 }, () => oauth.accessToken())), Array(10).fill('access-new'));
    assert.equal(concurrentRefreshes, 1);
    keyringFailure = true;
    await assert.rejects(oauth.accessToken(), error => error.code === 'credential_store_failed');
    keyringFailure = false;
    assert.equal(await oauth.accessToken(), 'access-new');

    const previousWait = process.env.COMICK_TOKEN_QUEUE_TIMEOUT_MS;
    let releaseRefresh;
    let refreshStarted;
    const startedRefresh = new Promise(resolve => { refreshStarted = resolve; });
    const heldRefresh = new Promise(resolve => { releaseRefresh = resolve; });
    await store();
    let queuedRequests = 0;
    globalThis.fetch = async () => { queuedRequests++; refreshStarted(); return heldRefresh; };
    const activeRefresh = oauth.accessToken();
    await startedRefresh;
    try {
      process.env.COMICK_TOKEN_QUEUE_TIMEOUT_MS = '5';
      await assert.rejects(api.apiRequest('/me'), error => error.code === 'credentials_busy' && /Timed out/.test(error.message));
      releaseRefresh(tokenResponse());
      assert.equal(await activeRefresh, 'access-new');
      assert.equal(await oauth.accessToken(), 'access-new', 'Expired queue entries must not block later calls');
      assert.equal(queuedRequests, 1, 'Expired queued calls must never send a delayed API request');
      for (const invalid of ['0', '-1', '1.5', 'NaN', '300001']) {
        process.env.COMICK_TOKEN_QUEUE_TIMEOUT_MS = invalid;
        await assert.rejects(oauth.accessToken(), error => error.code === 'configuration_required');
      }
    } finally {
      releaseRefresh(tokenResponse());
      await activeRefresh;
      if (previousWait === undefined) delete process.env.COMICK_TOKEN_QUEUE_TIMEOUT_MS;
      else process.env.COMICK_TOKEN_QUEUE_TIMEOUT_MS = previousWait;
    }

    globalThis.fetch = async () => new Response(null, { status: 429, headers: { 'retry-after': '60' } });
    await assert.rejects(api.apiRequest('/me'), /HTTP 429; Retry-After: 60/);
    process.env.COMICK_REDIRECT_URI = 'http://0.0.0.0:8787/callback';
    await assert.rejects(oauth.login(), /127\.0\.0\.1/);
    await assert.rejects(oauth.connect('start', false), /127\.0\.0\.1/);
    assert.equal((await oauth.connect('status')).status, 'saved');
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
    const noSession = await oauth.connect('status');
    assert.equal(noSession.status, 'failed');
    assert.match(noSession.message, /127\.0\.0\.1/);
    await store(Date.now() + 900_000);
    assert.equal((await oauth.connect('status')).status, 'saved', 'A session saved later must supersede the failed attempt');
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
      assert.equal(String(url), `${oauth.resource}/titles/KnownHid`);
      assert.equal(options.headers.Authorization, 'Bearer access-old');
      return Response.json({ data: { hid: 'KnownHid', slug: 'known-title', title: 'Known Title', media_type: 'manga', description: 'OAuth description' } });
    };
    const detail = await integration.title({ hid: 'KnownHid', detailed: true });
    assert.equal(detail.description, 'OAuth description');
    assert.equal(requested.length, 1);
    globalThis.fetch = async () => new Response(null, { status: 429, headers: { 'retry-after': '15' } });
    await assert.rejects(integration.title({ hid: 'KnownHid' }), error => error.code === 'rate_limited' && error.retryAfter === '15');
    globalThis.fetch = async () => Response.json({ data: { hid: 'WrongHid', slug: 'wrong-title', title: 'Wrong', media_type: 'manga' } });
    await assert.rejects(integration.title({ hid: 'KnownHid' }), error => error.code === 'invalid_response');
    globalThis.fetch = async (url, options) => {
      assert.equal(url.pathname, '/integrations/v1/titles');
      assert.equal(url.searchParams.get('q'), 'Known');
      assert.equal(url.searchParams.get('limit'), '5');
      assert.equal(url.searchParams.has('query'), false);
      assert.equal(options.headers.Authorization, 'Bearer access-old');
      return Response.json({ data: [{ hid: 'KnownHid', slug: 'known-title', title: 'Known Title', media_type: 'manga', private_field: 'DO_NOT_FORWARD' }] });
    };
    assert.deepEqual((await integration.search({ query: 'Known' })).items, [{ hid: 'KnownHid', slug: 'known-title', title: 'Known Title' }]);
    assert.doesNotMatch(JSON.stringify(await integration.search({ query: 'Known', detailed: true })), /DO_NOT_FORWARD/);
    for (const input of [{ query: 'x' }, { query: 'x'.repeat(101) }, { query: 'Known', limit: 21 }, { query: 'Known', page: 1 }, { query: 'Known', genres: ['action'] }, { q: 'Known' }]) {
      assert.equal(integration.searchSchema.safeParse(input).success, false);
    }

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
    const saved = await integration.libraryEntry({ hid: 'KnownHid' });
    assert.equal(entryCalls, 1);
    assert.equal(saved.data.progress.number, '12.5');
    assert.equal(saved.data.progress.volume, '0');
    assert.equal(saved.data.progress.hid, null);
    assert.equal(saved.data.continue_entry.number, 'Special');
    assert.equal(saved.data.rating, 8.5);
    assert.doesNotMatch(JSON.stringify(saved), /DO_NOT_FORWARD/);
    assert.equal(saved.data.updated_at, undefined);
    const complete = await integration.libraryEntry({ hid: 'KnownHid', detailed: true });
    assert.equal(complete.data.updated_at, entry.updated_at);
    assert.ok(JSON.stringify(saved).length < JSON.stringify(complete).length);

    // Writes preserve omitted values and never retry an ambiguous outcome.
    let writes = [];
    globalThis.fetch = async (url, options) => { writes.push(options); return Response.json({ data: entry }); };
    await assert.rejects(integration.librarySave({ hid: 'KnownHid', rating: 8 }), error => error.code === 'write_permission_required');
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
      const output = await integration.librarySave({ hid: 'KnownHid', ...input });
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
      await assert.rejects(integration.librarySave({ hid: 'KnownHid', ...input }), error => error.name === 'ZodError');
      assert.equal(writes.length, count);
    }
    globalThis.fetch = async (_url, options) => {
      assert.deepEqual(JSON.parse(options.body), { progress: { number: '3' } });
      return Response.json({ data: { ...entry, media_type: 'anime', status_name: 'watching', progress: { unit: 'episode', hid: null, number: '3', volume: null }, continue_entry: null } });
    };
    const animeWrite = await integration.librarySave({ hid: 'KnownHid', progress: { number: '3' }, detailed: true });
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
    await assert.rejects(integration.libraryRemove({ hid: 'KnownHid', confirm: false }), error => error.name === 'ZodError');
    assert.equal(deleteCalls, 0);
    for (let i = 0; i < 2; i++) assert.deepEqual(await integration.libraryRemove({ hid: 'KnownHid', confirm: true }), { hid: 'KnownHid', status: 'removed_or_already_absent' });
    assert.equal(deleteCalls, 2);
    for (const response of [new Response('bad JSON'), Response.json({ data: { ...entry, hid: 'WrongHid' } }),
      Response.json({ data: { ...entry, progress: { ...entry.progress, unit: 'episode' } } }), new Response(null, { status: 503 })]) {
      let calls = 0;
      globalThis.fetch = async () => { calls++; return response; };
      await assert.rejects(integration.librarySave({ hid: 'KnownHid', rating: 8 }), error => error.code === 'write_outcome_unknown');
      assert.equal(calls, 1);
    }
    let lostCalls = 0;
    globalThis.fetch = async () => { lostCalls++; throw new Error('DO_NOT_LEAK_TOKEN'); };
    await assert.rejects(integration.librarySave({ hid: 'KnownHid', rating: 8 }), error => error.code === 'write_outcome_unknown' && !/DO_NOT_LEAK_TOKEN/.test(error.message));
    assert.equal(lostCalls, 1);
    for (const [status, code] of [[400, 'api_error'], [403, 'write_permission_required'], [404, 'api_error'], [429, 'rate_limited']]) {
      globalThis.fetch = async () => new Response(null, { status, headers: { 'retry-after': '30' } });
      await assert.rejects(integration.librarySave({ hid: 'KnownHid', rating: 8 }), error => error.code === code && error.status === status);
    }
    globalThis.fetch = async () => Response.json({ data: entry });
    await assert.rejects(integration.libraryRemove({ hid: 'KnownHid', confirm: true }), error => error.code === 'write_outcome_unknown');
    let refreshWrites = 0;
    globalThis.fetch = async (url, options) => {
      if (String(url).endsWith('/token')) return Response.json({ access_token: 'write-new', token_type: 'Bearer', expires_in: 900, scope: 'library:read library:write', refresh_token: 'write-refresh' });
      refreshWrites++;
      if (refreshWrites === 1) return new Response(null, { status: 401 });
      assert.equal(options.headers.Authorization, 'Bearer write-new');
      assert.equal(options.body, JSON.stringify({ rating: 8 }));
      return Response.json({ data: { ...entry, rating: 8 } });
    };
    assert.equal((await integration.librarySave({ hid: 'KnownHid', rating: 8 })).data.rating, 8);
    assert.equal(refreshWrites, 2);
    grantWrites();
    credential = JSON.stringify({ ...JSON.parse(credential), expires_at: 0 });
    let lostScopeRequests = 0;
    globalThis.fetch = async url => {
      assert.match(String(url), /\/token$/);
      lostScopeRequests++;
      return tokenResponse();
    };
    await assert.rejects(integration.librarySave({ hid: 'KnownHid', rating: 8 }), error => error.code === 'write_permission_required');
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
    const first = await integration.library({ media_type: 'manga', status: 1 });
    assert.equal(first.data.length, 5);
    assert.deepEqual(Object.keys(first.data[0]).sort(), ['hid', 'media_type', 'progress', 'slug', 'status_name', 'title']);
    assert.deepEqual(await integration.library({ media_type: 'manga', status: 1, cursor: null }), first);
    const next = await integration.library({ media_type: 'manga', status: 1, cursor: first.next_cursor });
    assert.equal(next.next_cursor, null);
    assert.deepEqual([...first.data, ...next.data].map(row => row.hid), rows.map(row => row.hid));
    const fullPage = await integration.library({ media_type: 'manga', status: 1, detailed: true });
    assert.equal(fullPage.data[0].titles[0].title, 'Alternative 0');
    assert.equal(fullPage.data[0].translation_status, 'ongoing');
    assert.equal(fullPage.data[0].updated_at, entry.updated_at);
    assert.ok(JSON.stringify(first).length < JSON.stringify(fullPage).length);
    assert.doesNotMatch(JSON.stringify(fullPage), /DO_NOT_FORWARD/);
    for (const input of [{ status: 5 }, { media_type: 'anime' }, { status: 5, detailed: true }, { media_type: 'anime', detailed: true }]) {
      globalThis.fetch = async () => Response.json({ data: [entry], next_cursor: null });
      await assert.rejects(integration.library(input), error => error.code === 'invalid_response' && /filters/.test(error.message));
    }
    for (const field of ['progress', 'continue_entry']) {
      const invalid = { ...entry, [field]: { ...entry[field], unit: 'episode' } };
      globalThis.fetch = async () => Response.json({ data: [invalid], next_cursor: null });
      await assert.rejects(integration.library({}), error => error.code === 'invalid_response');
      globalThis.fetch = async () => Response.json({ data: invalid });
      await assert.rejects(integration.libraryEntry({ hid: 'KnownHid' }), error => error.code === 'invalid_response');
      const before = credential;
      credential = JSON.stringify({ ...JSON.parse(credential), scope: 'library:read library:write offline_access' });
      try {
        await assert.rejects(integration.librarySave({ hid: 'KnownHid', rating: 8 }), error => error.code === 'write_outcome_unknown');
      } finally { credential = before; }
    }
    const publicProfile = { id: '12345678-1234-4123-8123-123456789abc', username: 'Reader', avatar_url: 'https://example.com/avatar' };
    globalThis.fetch = async url => {
      assert.equal(url.pathname, '/integrations/v1/me');
      assert.equal(url.search, '');
      return Response.json({ ...publicProfile, access_token: 'DO_NOT_FORWARD' });
    };
    assert.deepEqual(await integration.me({}), { id: publicProfile.id, username: 'Reader' });
    assert.deepEqual(await integration.me({ detailed: true }), publicProfile);
    globalThis.fetch = async () => Response.json({ data: [{ ...entry, progress: { ...entry.progress, number: 12 } }], next_cursor: null });
    await assert.rejects(integration.library({}), error => error.code === 'invalid_response');
    for (const invalid of [{ ...entry, hid: 'Wrong' }, { ...entry, progress: { ...entry.progress, number: 12 } },
      { ...entry, progress: { ...entry.progress, unit: 'episode' } }]) {
      globalThis.fetch = async () => Response.json({ data: invalid });
      await assert.rejects(integration.libraryEntry({ hid: 'KnownHid' }), error => error.code === 'invalid_response');
    }
    globalThis.fetch = async () => Response.json({ data: { ...entry, media_type: 'anime', status_name: 'watching', progress: null, continue_entry: null } });
    assert.equal((await integration.libraryEntry({ hid: 'KnownHid' })).data.progress, null);
    for (const status of [403, 404, 429]) {
      globalThis.fetch = async () => new Response(null, { status });
      await assert.rejects(integration.libraryEntry({ hid: 'KnownHid' }), error => error.status === status && (status !== 404 || error.code === 'library_entry_not_found'));
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


test('OAuth-only MCP schemas, validation and missing login', async () => {
  const transport = new StdioClientTransport({ command: process.execPath, args: [`${root}dist/index.js`], env: { PATH: process.env.PATH ?? '' }, stderr: 'pipe' });
  const client = new Client({ name: 'comick-self-check', version: '1.0.0' });
  try {
    await client.connect(transport);
    const { tools } = await client.listTools();
    assert.deepEqual(tools.map(tool => tool.name).sort(), ['comick_connect', 'comick_disconnect', 'comick_library', 'comick_library_entry', 'comick_library_remove', 'comick_library_save', 'comick_me', 'comick_search', 'comick_title']);
    const search = tools.find(tool => tool.name === 'comick_search').inputSchema;
    assert.deepEqual(search.required, ['query']);
    assert.equal(search.properties.query.minLength, 2);
    assert.equal(search.properties.query.maxLength, 100);
    assert.equal(search.properties.limit.maximum, 20);
    assert.equal(search.properties.page, undefined);
    for (const [name, args] of [['comick_search', { query: 'Known' }], ['comick_title', { hid: 'Hid' }], ['comick_me', {}]]) {
      const response = await client.callTool({ name, arguments: args });
      assert.equal(JSON.parse(response.content[0].text).error.code, 'configuration_required');
    }
    for (const [name, args] of [['comick_search', {}], ['comick_search', { query: 'Known', limit: 21 }], ['comick_search', { query: 'Known', genres: ['action'] }], ['comick_title', { slug: 'sample' }], ['comick_library_remove', { hid: 'Hid' }]]) {
      const response = await client.callTool({ name, arguments: args });
      assert.equal(JSON.parse(response.content[0].text).error.code, 'invalid_input');
      const failure = JSON.parse(response.content[0].text).error;
      assert.ok(failure.issues.every(issue => typeof issue.recommendation === 'string'));
      if (args.limit === 21) assert.equal(failure.issues.find(issue => issue.path[0] === 'limit').expected.maximum, 20);
    }
  } finally { await client.close(); await transport.close(); }
});

test('all 9 OAuth MCP tools: contracts, validation, failures and request effects', async t => {
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
  const titleCases = [
    ['comick_search', { query: 'Sample' }, '/integrations/v1/titles'],
    ['comick_title', { hid: 'Hid' }, '/integrations/v1/titles/Hid'],
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
  const cases = [...titleCases, ...accountCases, ...writeCases,
    ['comick_connect', { action: 'status' }], ['comick_disconnect', {}]];
  try {
    await client.connect(transport);
    const { tools } = await client.listTools();
    const integration = await import('./dist/integration.js');
    const oauth = await import('./dist/oauth.js');
    const outputs = { comick_search: integration.searchOutput, comick_title: integration.titleResult, comick_me: integration.meOutput, comick_library: integration.libraryOutput,
      comick_library_entry: integration.libraryEntryResult, comick_library_save: integration.libraryEntryResult,
      comick_library_remove: integration.libraryRemoveOutput, comick_disconnect: oauth.disconnectOutput };
    assert.deepEqual(cases.map(([name]) => name).sort(), tools.map(tool => tool.name).sort(), 'Every registered tool must have a contract case');
    await t.test('stress: 100 sequential and 100 concurrent OAuth reads recover without retries', async () => {
      const reads = [...titleCases, ...accountCases];
      for (const concurrency of [1, 10]) {
        const count = (await calls()).length;
        const latencies = [];
        const errors = {};
        let successes = 0;
        const started = performance.now();
        for (let offset = 0; offset < 100; offset += concurrency) {
          const results = await Promise.allSettled(Array.from({ length: concurrency }, async (_, index) => {
            const [name, args] = reads[(offset + index) % reads.length];
            const start = performance.now();
            const result = await call(name, args);
            latencies.push(performance.now() - start);
            return result;
          }));
          for (const result of results) {
            assert.equal(result.status, 'fulfilled', 'Transport and output validation must survive concurrent calls');
            if (result.value.response.isError) {
              const code = result.value.value.error.code;
              assert.equal(code, 'credentials_busy');
              errors[code] = (errors[code] ?? 0) + 1;
            } else successes++;
          }
        }
        const elapsed = performance.now() - started;
        latencies.sort((a, b) => a - b);
        const sent = (await calls()).slice(count);
        assert.equal(sent.length, successes, 'Rejected reads must not send requests; successful reads must not retry');
        assert.ok(sent.every(request => request.method === 'GET' && request.path.startsWith('/integrations/v1/')));
        assert.equal(successes, 100);
        assert.notEqual((await call('comick_me', {})).response.isError, true, 'Credential lock must be released after the burst');
        console.log(JSON.stringify({ stress: 'mock upstream, real MCP transport', concurrency, requests: 100, successes, errors, elapsed_ms: Math.round(elapsed), p50_ms: Math.round(latencies[49]), p95_ms: Math.round(latencies[94]) }));
      }
    });
    for (const [name, args] of cases) await t.test(`${name}: invalid input has no upstream effects`, async () => {
      const before = await calls();
      const { response, value } = await call(name, { ...args, DO_NOT_LEAK_TOKEN: 'DO_NOT_LEAK_TOKEN' });
      assert.equal(response.isError, true);
      assert.equal(value.error.code, 'invalid_input');
      assert.equal(value.error.retryable, false);
      assert.ok(value.error.issues.some(issue => issue.code === 'unrecognized_keys'));
      assert.deepEqual(await calls(), before);
    });
    await t.test('library filters: mismatched upstream entries are rejected over MCP', async () => {
      const before = (await calls()).length;
      for (const args of [{ status: 5 }, { media_type: 'anime', detailed: true }]) {
        const { response, value } = await call('comick_library', args);
        assert.equal(response.isError, true);
        assert.equal(value.error.code, 'invalid_response');
      }
      assert.equal((await calls()).length - before, 2, 'Invalid responses must not cause retries');
    });
    for (const [name, args, path] of [...titleCases, ...accountCases, ...writeCases]) await t.test(`${name}: stable success and exact request count`, async () => {
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
    for (const [name, args] of [...titleCases, ...accountCases, ...writeCases]) {
      for (const mode of ['network', 'rate_limit', 'forbidden', 'malformed', 'html']) await t.test(`${name}: ${mode} is safe and repeatable`, async () => {
        await setMode(mode);
        const before = (await calls()).length;
        const first = await call(name, args);
        const second = await call(name, args);
        assert.equal(first.response.isError, true);
        assert.deepEqual(first.response, second.response);
        const writing = writeCases.some(([tool]) => tool === name);
        const expected = mode === 'rate_limit' ? 'rate_limited'
          : mode === 'forbidden' ? writing ? 'write_permission_required' : 'api_error'
          : writing ? 'write_outcome_unknown' : mode === 'network' ? 'network_error' : 'invalid_response';
        assert.equal(first.value.error.code, expected);
        if (mode === 'rate_limit') {
          assert.equal(first.value.error.retry_after, '30');
          assert.equal(first.value.error.status, 429);
        }
        const sent = (await calls()).slice(before);
        assert.equal(sent.length, 2, 'No public fallback or hidden retries');
      });
    }
    await setMode('empty');
    for (const [name, args, key] of [
      ['comick_search', { query: 'Sample' }, 'items'], ['comick_library', {}, 'data'],
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
