import assert from 'node:assert/strict';
import { test, mock } from 'node:test';
import childProcess from 'node:child_process';
import { syncBuiltinESMExports } from 'node:module';
import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { copyFile, mkdir, mkdtemp, rm, stat } from 'node:fs/promises';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';

const root = fileURLToPath(new URL('.', import.meta.url));

test('OAuth PKCE, state, refresh rotation, failure safety, and API retry (mocked)', async () => {
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
  const keyringExec = (command, args, options, done) => {
    assert.equal(command, 'secret-tool');
    assert.ok(args.includes('test-public-client'));
    assert.equal(args.includes(credential), false);
    assert.equal(options.timeout, 30_000);
    const stdin = { on() { return this; }, end(secret) {
      if (keyringFailure) { done(new Error('backend leaked access-new'), '', 'refresh-new'); return; }
      if (args[0] === 'store') {
        if (storeFailure) { done(new Error('store failed'), '', ''); return; }
        credential = secret;
        done(null, '', '');
      } else if (credential === undefined) {
        done(Object.assign(new Error('not found'), { code: 1 }), '', '');
      } else {
        done(null, credential, '');
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
    const oauth = await import(pathToFileURL(`${directory}/dist/oauth.js`).href);
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
    assert.equal(authorize.searchParams.get('scope'), 'library:read offline_access');
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
    assert.equal((await originalFetch(callback)).status, 200);
    await login;
    assert.equal(exchanges, 1);
    await assert.rejects(stat(`${directory}/.comick/tokens.json`), { code: 'ENOENT' });
    assert.equal((await stat(`${directory}/comick-mcp`)).mode & 0o777, 0o700);
    assert.equal(await oauth.accessToken(), 'access-new');
    assert.equal((await oauth.connect('status')).status, 'saved');
    const browser = mock.method(childProcess, 'execFile', (command, args, options, callback) => {
      if (command === 'secret-tool') return keyringExec(command, args, options, callback);
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
      assert.equal(started.browser_opened, true);
      assert.equal(browserCalls(), 1);
      assert.equal((await oauth.connect('start')).authorization_url, started.authorization_url);
      assert.equal(browserCalls(), 1);
      const authorizationUrl = new URL(started.authorization_url);
      callback.search = new URLSearchParams({ state: authorizationUrl.searchParams.get('state'), code: 'test-code' });
      const callbackResponse = await originalFetch(callback);
      assert.equal(callbackResponse.status, 200);
      assert.equal(callbackResponse.headers.get('cache-control'), 'no-store');
      assert.doesNotMatch(await callbackResponse.text(), /access-new|refresh-new/);
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
      assert.equal(browserCalls(), 1);
      browser.mock.mockImplementation((command, args, options, done) => command === 'secret-tool'
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
    await assert.rejects(oauth.accessToken(), /response lost/);
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
    assert.deepEqual(await oauth.apiGet('/me/library', { limit: 10, cursor: 'opaque+/=' }), { data: [], next_cursor: null });
    assert.equal(calls.length, 3);
    assert.equal(new URL(calls[0]).searchParams.get('cursor'), 'opaque+/=');

    globalThis.fetch = async () => new Response(null, { status: 429, headers: { 'retry-after': '60' } });
    await assert.rejects(oauth.apiGet('/me'), /HTTP 429; Retry-After: 60/);
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
  } finally {
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
      { minimum_rating: 11 }, { content_rating: ['unknown'] }, { q: '  ' }, { token: 'secret' }]) {
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

test('real MCP stdio handshake, tool listing, validation and missing login', async () => {
  const transport = new StdioClientTransport({
    command: process.execPath, args: [`${root}dist/index.js`],
    env: { PATH: process.env.PATH ?? '' }, stderr: 'pipe',
  });
  const client = new Client({ name: 'comick-self-check', version: '1.0.0' });
  try {
    await client.connect(transport);
    const { tools } = await client.listTools();
    assert.deepEqual(tools.map(tool => tool.name).sort(), ['comick_connect', 'comick_filters', 'comick_library', 'comick_me', 'comick_search', 'comick_title']);
    assert.ok(tools.filter(tool => tool.name !== 'comick_connect').every(tool => tool.annotations.readOnlyHint));
    assert.equal(tools.find(tool => tool.name === 'comick_connect').annotations.readOnlyHint, false);
    const connection = await client.callTool({ name: 'comick_connect', arguments: { action: 'start' } });
    assert.equal(connection.isError, true);
    assert.match(connection.content[0].text, /COMICK_CLIENT_ID/);
    const invalid = await client.callTool({ name: 'comick_library', arguments: { limit: 101 } });
    assert.equal(invalid.isError, true);
    assert.doesNotMatch(invalid.content[0].text, /COMICK_CLIENT_ID/);
    for (const [name, args] of [['comick_search', { minimum: 20, maximum: 10 }],
      ['comick_search', { genres: Array(11).fill('action') }], ['comick_title', { slug: '../me' }],
      ['comick_filters', { kind: 'unknown' }], ['comick_connect', { action: 'start', token: 'secret' }]]) {
      const rejected = await client.callTool({ name, arguments: args });
      assert.equal(rejected.isError, true);
    }
    const result = await client.callTool({ name: 'comick_me', arguments: {} });
    assert.equal(result.isError, true);
    assert.match(result.content[0].text, /COMICK_CLIENT_ID/);
  } finally {
    await client.close();
    await transport.close();
  }
});
