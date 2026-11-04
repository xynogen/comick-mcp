import { createHash, randomBytes } from 'node:crypto';
import { mkdir, open, readFile, rename, unlink } from 'node:fs/promises';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { z } from 'zod';

export const resource = 'https://api.comick.dev/integrations/v1';
const issuer = 'https://comick.dev/api/auth/oauth2';
const directory = fileURLToPath(new URL('../.comick/', import.meta.url));
const tokenFile = `${directory}/tokens.json`;
const tokenSchema = z.object({
  access_token: z.string().min(1),
  token_type: z.string().refine(value => value.toLowerCase() === 'bearer'),
  expires_in: z.number().int().positive(),
  scope: z.string().refine(value => value.split(' ').includes('library:read')),
  refresh_token: z.string().min(1).optional(),
});
const storedSchema = tokenSchema.omit({ expires_in: true }).extend({
  expires_at: z.number().finite(),
  client_id: z.string().min(1),
});
type StoredToken = z.infer<typeof storedSchema>;

function clientId() {
  const id = process.env.COMICK_CLIENT_ID?.trim();
  if (!id) throw new Error('Set COMICK_CLIENT_ID for a registered public Comick app.');
  return id;
}

async function locked<T>(action: () => Promise<T>): Promise<T> {
  await mkdir(directory, { recursive: true, mode: 0o700 });
  let lock;
  try {
    lock = await open(`${directory}/lock`, 'wx', 0o600);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'EEXIST') {
      throw new Error('Comick credentials are busy. Retry after login/refresh finishes. If a process crashed, remove .comick/lock only after stopping all runners.');
    }
    throw error;
  }
  try {
    return await action();
  } finally {
    await lock.close();
    await unlink(`${directory}/lock`);
  }
}

async function save(tokens: StoredToken) {
  const temporary = `${tokenFile}.${randomBytes(8).toString('hex')}.tmp`;
  const file = await open(temporary, 'wx', 0o600);
  try {
    await file.writeFile(JSON.stringify(tokens));
    await file.sync();
  } finally {
    await file.close();
  }
  await rename(temporary, tokenFile);
}

async function exchange(parameters: Record<string, string>, id: string): Promise<StoredToken> {
  const response = await fetch(`${issuer}/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ ...parameters, client_id: id, resource }),
    signal: AbortSignal.timeout(20_000),
    redirect: 'error',
  });
  if (!response.ok) throw new Error(`Comick token exchange failed (HTTP ${response.status}). Reconnect with npm run login; do not retry an old code or refresh token.`);
  const parsed = tokenSchema.safeParse(await response.json());
  if (!parsed.success) throw new Error('Invalid Comick token response or library:read not granted. Reconnect with npm run login.');
  const { expires_in, ...tokens } = parsed.data;
  return { ...tokens, client_id: id, expires_at: Date.now() + expires_in * 1000 };
}

export async function accessToken(rejectedToken?: string) {
  return locked(async () => {
    const id = clientId();
    let tokens: StoredToken;
    try {
      const parsed = storedSchema.safeParse(JSON.parse(await readFile(tokenFile, 'utf8')));
      if (!parsed.success) throw new Error('Invalid credential file.');
      tokens = parsed.data;
    } catch {
      throw new Error('No valid Comick credentials. Run npm run login first.');
    }
    if (tokens.client_id !== id) throw new Error('Client ID changed. Reconnect with npm run login.');
    if (tokens.expires_at > Date.now() + 30_000 && tokens.access_token !== rejectedToken) return tokens.access_token;
    if (!tokens.refresh_token) throw new Error('Comick session expired or revoked. Reconnect with npm run login.');
    const { refresh_token, ...withoutRefresh } = tokens;
    // A refresh may consume the old token even if its response is lost; never reuse it.
    await save({ ...withoutRefresh, expires_at: 0 });
    const replacement = await exchange({ grant_type: 'refresh_token', refresh_token }, id);
    await save(replacement);
    return replacement.access_token;
  });
}

export async function apiGet(path: string, query: Record<string, string | number | undefined> = {}) {
  const url = new URL(`${resource}${path}`);
  for (const [key, value] of Object.entries(query)) {
    if (value !== undefined) url.searchParams.set(key, String(value));
  }
  let token = await accessToken();
  for (let attempt = 0; attempt < 2; attempt++) {
    const response = await fetch(url, {
      headers: { Authorization: `Bearer ${token}` },
      signal: AbortSignal.timeout(20_000),
      redirect: 'error',
      cache: 'no-store',
    });
    if (response.status === 401 && attempt === 0) {
      token = await accessToken(token);
      continue;
    }
    if (!response.ok) {
      const retryAfter = response.headers.get('retry-after');
      throw new Error(`Comick API returned HTTP ${response.status}${retryAfter ? `; Retry-After: ${retryAfter}` : ''}.`);
    }
    return response.json();
  }
  throw new Error('Comick authorization failed. Reconnect with npm run login.');
}

export async function login() {
  const id = clientId();
  const callback = new URL(process.env.COMICK_REDIRECT_URI ?? 'http://127.0.0.1:8787/callback');
  if (callback.protocol !== 'http:' || callback.hostname !== '127.0.0.1' || !callback.port || callback.username || callback.password || callback.search || callback.hash) {
    throw new Error('COMICK_REDIRECT_URI must be an HTTP 127.0.0.1 URL with an explicit port and no credentials, query or fragment.');
  }
  await locked(async () => {
    const verifier = randomBytes(32).toString('base64url');
    const state = randomBytes(32).toString('base64url');
    const authorize = new URL(`${issuer}/authorize`);
    authorize.search = new URLSearchParams({
      response_type: 'code', client_id: id, redirect_uri: callback.href,
      scope: 'library:read offline_access', resource, state,
      code_challenge: createHash('sha256').update(verifier).digest('base64url'),
      code_challenge_method: 'S256',
    }).toString();
    const server = createServer();
    server.listen(Number(callback.port), '127.0.0.1');
    await once(server, 'listening');
    try {
      const code = await new Promise<string>((accept, reject) => {
        const timer = setTimeout(() => reject(new Error('OAuth login timed out after 5 minutes.')), 300_000);
        let consumed = false;
        server.on('request', (request, response) => {
          response.setHeader('Cache-Control', 'no-store');
          response.setHeader('Content-Type', 'text/plain; charset=utf-8');
          response.setHeader('Referrer-Policy', 'no-referrer');
          response.setHeader('X-Content-Type-Options', 'nosniff');
          let url: URL;
          try {
            url = new URL(request.url ?? '/', callback.origin);
          } catch {
            response.writeHead(400).end('Invalid callback URL.');
            return;
          }
          if (request.method !== 'GET' || request.headers.host !== callback.host || url.pathname !== callback.pathname) {
            response.writeHead(404).end('Not found.');
            return;
          }
          if (consumed || url.searchParams.getAll('state').length !== 1 || url.searchParams.get('state') !== state) {
            response.writeHead(400).end('Invalid OAuth state.');
            return;
          }
          const codes = url.searchParams.getAll('code');
          const denied = url.searchParams.has('error');
          if (!denied && (codes.length !== 1 || !codes[0])) {
            response.writeHead(400).end('Missing or duplicate authorization code.');
            return;
          }
          consumed = true;
          clearTimeout(timer);
          if (denied) {
            response.writeHead(400).end('Authorization denied.');
            reject(new Error('Comick authorization denied.'));
            return;
          }
          response.end('Callback received. You can close this tab; check the terminal for the login result.');
          accept(codes[0]);
        });
        console.error(`Open this URL in your browser to connect Comick:\n${authorize.href}`);
      });
      const tokens = await exchange({ grant_type: 'authorization_code', code, redirect_uri: callback.href, code_verifier: verifier }, id);
      await save(tokens);
      console.error(`Comick connected (${tokens.scope}).${tokens.refresh_token ? '' : ' Offline access declined; login again when the access token expires.'}`);
    } finally {
      server.closeAllConnections();
      await new Promise<void>((accept, reject) => server.close(error => error ? reject(error) : accept()));
    }
  });
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  login().catch(error => {
    console.error(error instanceof Error ? error.message : 'Comick login failed.');
    process.exitCode = 1;
  });
}
