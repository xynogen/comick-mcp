import assert from 'node:assert/strict';
import { test, mock } from 'node:test';
import childProcess from 'node:child_process';
import { syncBuiltinESMExports } from 'node:module';
import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { copyFile, mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';

const root = fileURLToPath(new URL('.', import.meta.url));

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
    const partial = await catalog.title({ slug: 'known-title', hid: 'KnownHid' });
    assert.equal(partial.source, 'oauth_title');
    assert.equal(partial.partial, true);
    assert.ok(partial.missing_fields.includes('genres'));
    assert.equal(requested.length, 2);
    globalThis.fetch = async url => String(url).includes('/v1.0/comic/') ? new Response(null, { status: 403 }) : new Response(null, { status: 429, headers: { 'retry-after': '15' } });
    await assert.rejects(catalog.title({ slug: 'known-title', hid: 'KnownHid' }), error => error.code === 'rate_limited' && error.retryAfter === '15');
    globalThis.fetch = async url => String(url).includes('/v1.0/comic/') ? new Response(null, { status: 403 })
      : Response.json({ data: { hid: 'WrongHid', slug: 'wrong-title', title: 'Wrong', media_type: 'manga' } });
    await assert.rejects(catalog.title({ slug: 'known-title', hid: 'KnownHid' }), error => error.code === 'invalid_response');

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

test('Windows Credential Manager native round-trip and size limit', { skip: process.platform !== 'win32' }, async () => {
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

test('compact catalog metadata, genre resolution and exact bounded detail fallbacks', async () => {
  const { search, title, filters, searchOutput, titleOutput } = await import('./dist/catalog.js');
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
      return Response.json(url.pathname === '/genre/' ? genres : [item]);
    };
    const page = await search({ q: 'known', synopsis_limit: 100 });
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
    assert.equal((await filters('genres')).items[0].name, 'Action');
    globalThis.fetch = async () => Response.json([{ title: 'Level System', slug: 'level-system', id: 1, comic_count: 300 }]);
    assert.deepEqual((await filters('tags')).items, [{ name: 'Level System', slug: 'level-system', group: null }]);

    globalThis.fetch = async url => url.pathname === '/genre/' ? new Response(null, { status: 503 }) : Response.json([item]);
    const unresolved = await search({});
    assert.equal(unresolved.items.length, 1);
    assert.equal(unresolved.warnings.length, 1);
    assert.deepEqual(unresolved.items[0].unresolved_genre_ids, [5, 999]);
    for (const value of ['', '  ', 'not-a-number', null]) {
      globalThis.fetch = async () => Response.json([{ ...item, genres: [], bayesian_rating: value }]);
      assert.equal((await search({})).items[0].rating.site_score, null);
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
    const full = await title({ slug: item.slug });
    assert.ok(titleOutput.safeParse(full).success);
    assert.equal(full.partial, false);
    assert.equal(full.source, 'catalog_detail');
    assert.equal(full.recommendations.length, 5);
    assert.equal(full.tags[0].slug, 'level-system');
    assert.ok(full.synopsis.includes('Other paragraph'));
    assert.equal(full.synopsis_truncated, false);
    assert.doesNotMatch(JSON.stringify(full), /private-contributor|script|reviews/);

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
      assert.equal(fallback.source, 'search');
      assert.ok(fallback.missing_fields.includes('authors'));
      assert.equal(fallback.hid, item.hid);
      assert.equal(calls.filter(url => url.includes('/search/')).length, 1);
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

test('real MCP stdio handshake, tool listing, validation and missing login', async () => {
  const transport = new StdioClientTransport({
    command: process.execPath, args: [`${root}dist/index.js`],
    env: { PATH: process.env.PATH ?? '' }, stderr: 'pipe',
  });
  const client = new Client({ name: 'comick-self-check', version: '1.0.0' });
  try {
    await client.connect(transport);
    const { tools } = await client.listTools();
    assert.deepEqual(tools.map(tool => tool.name).sort(), ['comick_connect', 'comick_disconnect', 'comick_filters', 'comick_library', 'comick_me', 'comick_search', 'comick_title']);
    assert.ok(tools.filter(tool => !['comick_connect', 'comick_disconnect'].includes(tool.name)).every(tool => tool.annotations.readOnlyHint));
    const disconnect = tools.find(tool => tool.name === 'comick_disconnect');
    assert.equal(disconnect.annotations.destructiveHint, true);
    assert.equal(disconnect.annotations.idempotentHint, true);
    for (const name of ['comick_search', 'comick_title', 'comick_filters', 'comick_disconnect']) assert.ok(tools.find(tool => tool.name === name).outputSchema);
    assert.equal(tools.find(tool => tool.name === 'comick_connect').annotations.readOnlyHint, false);
    const connection = await client.callTool({ name: 'comick_connect', arguments: { action: 'start' } });
    assert.equal(connection.isError, true);
    assert.match(connection.content[0].text, /COMICK_CLIENT_ID/);
    assert.equal(JSON.parse(connection.content[0].text).error.code, 'configuration_required');
    const invalid = await client.callTool({ name: 'comick_library', arguments: { limit: 101 } });
    assert.equal(invalid.isError, true);
    assert.doesNotMatch(invalid.content[0].text, /COMICK_CLIENT_ID/);
    for (const [name, args] of [['comick_search', { minimum: 20, maximum: 10 }],
      ['comick_search', { genres: Array(11).fill('action') }], ['comick_title', { slug: '../me' }],
      ['comick_filters', { kind: 'unknown' }], ['comick_disconnect', { token: 'secret' }], ['comick_connect', { action: 'start', token: 'secret' }]]) {
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

test('MCP structured results and safe failures over real stdio with mocked upstream', async () => {
  const directory = await mkdtemp(`${root}.test-`);
  const preload = `${directory}/upstream.mjs`;
  await writeFile(preload, `
globalThis.fetch = async (url) => {
  if (url.searchParams?.get('q') === 'fail') throw new Error('DO_NOT_LEAK_TOKEN');
  if (url.pathname === '/genre/') return Response.json([{id:5,name:'Action',slug:'action',group:'Genre'}]);
  if (url.pathname === '/v1.0/search/') return Response.json([{hid:'Hid',slug:'sample',title:'Sample',genres:[5],bayesian_rating:'8.5'}]);
  if (url.pathname === '/v1.0/comic/sample/') return Response.json({comic:{hid:'Hid',slug:'sample',title:'Sample'}});
  throw new Error('Unexpected upstream request');
};
`);
  const transport = new StdioClientTransport({
    command: process.execPath, args: ['--import', pathToFileURL(preload).href, `${root}dist/index.js`],
    env: { PATH: process.env.PATH ?? '' }, stderr: 'pipe',
  });
  const client = new Client({ name: 'comick-structured-self-check', version: '1.0.0' });
  let stderr = '';
  transport.stderr?.on('data', chunk => { stderr += chunk; });
  try {
    await client.connect(transport);
    for (const [name, args] of [['comick_search', {}], ['comick_title', { slug: 'sample' }], ['comick_filters', { kind: 'genres' }]]) {
      const response = await client.callTool({ name, arguments: args });
      assert.notEqual(response.isError, true);
      assert.deepEqual(JSON.parse(response.content[0].text), response.structuredContent);
      if (name === 'comick_search') assert.equal(response.structuredContent.items[0].genres[0].name, 'Action');
    }
    const failure = await client.callTool({ name: 'comick_search', arguments: { q: 'fail' } });
    assert.equal(failure.isError, true);
    assert.equal(JSON.parse(failure.content[0].text).error.code, 'network_error');
    assert.doesNotMatch(JSON.stringify(failure) + stderr, /DO_NOT_LEAK_TOKEN/);
  } finally {
    await client.close();
    await transport.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test('recorded public API samples satisfy compact schemas when available', async t => {
  const base = `${process.env.TEMP ?? '/tmp'}/comick-mcp-research`;
  let samples;
  try { samples = await Promise.all(['search', 'genres', 'detail'].map(name => readFile(`${base}/${name}/index.html`, 'utf8').then(JSON.parse))); }
  catch { t.skip('Public research samples are not present.'); return; }
  const { search, title } = await import('./dist/catalog.js');
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async url => Response.json(url.pathname === '/genre/' ? samples[1] : url.pathname.includes('/comic/') ? samples[2] : samples[0]);
    const page = await search({ q: 'Solo Leveling', limit: 2 });
    const detail = await title({ slug: '00-solo-leveling' });
    assert.equal(page.items[0].title, 'Solo Leveling');
    assert.equal(detail.title, 'Solo Leveling');
    assert.ok(JSON.stringify(detail).length < JSON.stringify(samples[2]).length / 5);
  } finally { globalThis.fetch = originalFetch; }
});
