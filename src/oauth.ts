import { createHash, randomBytes } from 'node:crypto';
import { mkdir, open, unlink } from 'node:fs/promises';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';
import { isAbsolute, join, resolve } from 'node:path';
import { homedir } from 'node:os';
import { execFile } from 'node:child_process';
import { z } from 'zod';

export const resource = 'https://api.comick.dev/integrations/v1';
const issuer = 'https://comick.dev/api/auth/oauth2';
const stateHome = process.env.XDG_STATE_HOME;
const directory = join(stateHome && isAbsolute(stateHome) ? stateHome : join(homedir(), '.local/state'), 'comick-mcp');
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

export class ComickError extends Error {
  constructor(public code: string, message: string, public status?: number, public retryAfter?: string) {
    super(message);
  }
}

function clientId() {
  const id = process.env.COMICK_CLIENT_ID?.trim();
  if (!id) throw new ComickError('configuration_required', 'Set COMICK_CLIENT_ID for a registered public Comick app.');
  return id;
}

async function locked<T>(action: () => Promise<T>): Promise<T> {
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const lockFile = join(directory, `${createHash('sha256').update(clientId()).digest('hex')}.lock`);
  let lock;
  try {
    lock = await open(lockFile, 'wx', 0o600);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'EEXIST') {
      throw new ComickError('credentials_busy', `Comick credentials are busy. Retry after login/refresh finishes. If a process crashed, remove ${lockFile} only after stopping all runners.`);
    }
    throw error;
  }
  try {
    return await action();
  } finally {
    await lock.close();
    await unlink(lockFile);
  }
}

// ponytail: built-in PowerShell bridges WinCred; use a native binding if process startup becomes a bottleneck.
const windowsKeyring = `
$ErrorActionPreference = 'Stop'
try {
  Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class ComickCredentials {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct Credential {
        public uint Flags, Type;
        public string TargetName, Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public uint CredentialBlobSize;
        public IntPtr CredentialBlob;
        public uint Persist, AttributeCount;
        public IntPtr Attributes;
        public string TargetAlias, UserName;
    }
    [DllImport("advapi32.dll", EntryPoint = "CredReadW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool Read(string target, uint type, uint flags, out IntPtr credential);
    [DllImport("advapi32.dll", EntryPoint = "CredWriteW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool Write(ref Credential credential, uint flags);
    [DllImport("advapi32.dll", EntryPoint = "CredDeleteW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool Remove(string target, uint type, uint flags);
    public static void Delete(string target) {
        if (!Remove(target, 1, 0)) {
            int error = Marshal.GetLastWin32Error();
            if (error != 1168) throw new Win32Exception(error);
        }
    }
    [DllImport("advapi32.dll")]
    static extern void CredFree(IntPtr credential);
    public static byte[] Lookup(string target) {
        IntPtr pointer;
        if (!Read(target, 1, 0, out pointer)) {
            int error = Marshal.GetLastWin32Error();
            if (error == 1168) return null;
            throw new Win32Exception(error);
        }
        try {
            var credential = (Credential)Marshal.PtrToStructure(pointer, typeof(Credential));
            var bytes = new byte[credential.CredentialBlobSize];
            Marshal.Copy(credential.CredentialBlob, bytes, 0, bytes.Length);
            return bytes;
        } finally { CredFree(pointer); }
    }
    public static void Store(string target, byte[] bytes) {
        if (bytes.Length > 2560) throw new ArgumentException("Credential exceeds WinCred limit.");
        IntPtr blob = Marshal.AllocHGlobal(bytes.Length);
        try {
            Marshal.Copy(bytes, 0, blob, bytes.Length);
            var credential = new Credential { Type = 1, TargetName = target,
                CredentialBlobSize = (uint)bytes.Length, CredentialBlob = blob,
                Persist = 2, UserName = "Comick MCP" };
            if (!Write(ref credential, 0)) throw new Win32Exception(Marshal.GetLastWin32Error());
        } finally {
            for (int i = 0; i < bytes.Length; i++) Marshal.WriteByte(blob, i, 0);
            Marshal.FreeHGlobal(blob);
            Array.Clear(bytes, 0, bytes.Length);
        }
    }
}
'@
  $request = [Console]::In.ReadToEnd() | ConvertFrom-Json
  if ($request.operation -eq 'store') {
    [ComickCredentials]::Store($request.target, [Convert]::FromBase64String($request.secret))
  } elseif ($request.operation -eq 'lookup') {
    $bytes = [ComickCredentials]::Lookup($request.target)
    if ($null -ne $bytes) { [Console]::Out.Write([Convert]::ToBase64String($bytes)) }
  } elseif ($request.operation -eq 'clear') {
    [ComickCredentials]::Delete($request.target)
  } else { exit 1 }
} catch { exit 1 }
`;
function keyring(operation: 'lookup' | 'store' | 'clear', id: string, secret?: string): Promise<string | null> {
  if (process.platform !== 'linux' && process.platform !== 'win32') throw new ComickError('unsupported_platform', 'Comick keyring requires Windows Credential Manager or Linux Secret Service. No plaintext fallback is used.');
  const windows = process.platform === 'win32';
  if (windows && secret !== undefined && Buffer.byteLength(secret, 'utf8') > 2560) {
    throw new ComickError('credential_too_large', 'Comick credentials exceed the Windows Credential Manager limit of 2560 bytes. Existing credentials were not changed.');
  }
  const args = operation === 'store' ? ['store', '--label=Comick MCP OAuth'] : [operation];
  args.push('service', 'comick-mcp', 'issuer', issuer, 'client_id', id);
  const command = windows ? 'powershell.exe' : 'secret-tool';
  const input = windows ? JSON.stringify({
    operation, target: `comick-mcp:${createHash('sha256').update(`${issuer}\0${id}`).digest('hex')}`,
    secret: secret === undefined ? undefined : Buffer.from(secret, 'utf8').toString('base64'),
  }) : secret;
  const commandArgs = windows ? ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(windowsKeyring, 'utf16le').toString('base64')] : args;
  return new Promise((resolve, reject) => {
    const child = execFile(command, commandArgs, { timeout: 30_000, maxBuffer: 1024 * 1024, windowsHide: true }, (error, stdout, stderr) => {
      if (error) {
        if (!windows && operation !== 'store' && (error as { code?: string | number }).code === 1 && !stdout && !stderr) return resolve(null);
        reject(new ComickError('credential_store_failed', `Comick OS keyring ${operation} failed. ${windows ? 'Ensure Windows Credential Manager is available for this Windows user.' : 'Ensure secret-tool is installed and the desktop Secret Service keyring is available and unlocked.'} No plaintext fallback is used.`));
        return;
      }
      resolve((windows ? Buffer.from(stdout.trim(), 'base64').toString('utf8') : stdout.trim()) || null);
    });
    // Never put credentials in command arguments or include subprocess errors in tool output.
    child.stdin?.on('error', () => reject(new ComickError('credential_store_failed', 'Could not send credentials to the OS keyring. No plaintext fallback is used.')));
    child.stdin?.end(input);
  });
}

async function load(id: string): Promise<StoredToken | null> {
  const secret = await keyring('lookup', id);
  if (secret === null) return null;
  let parsed;
  try {
    parsed = storedSchema.safeParse(JSON.parse(secret));
  } catch {
    throw new ComickError('reconnect_required', 'Invalid Comick credentials in OS keyring. Reconnect with comick_connect.');
  }
  if (!parsed.success || parsed.data.client_id !== id) throw new ComickError('reconnect_required', 'Invalid Comick credentials in OS keyring. Reconnect with comick_connect.');
  return parsed.data;
}

async function save(tokens: StoredToken) {
  await keyring('store', tokens.client_id, JSON.stringify(tokens));
}

async function exchange(parameters: Record<string, string>, id: string): Promise<StoredToken> {
  let response: Response;
  try {
    response = await fetch(`${issuer}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ ...parameters, client_id: id, resource }),
      signal: AbortSignal.timeout(20_000),
      redirect: 'error', credentials: 'omit',
    });
  } catch {
    throw new ComickError('reconnect_required', 'Comick token exchange could not be confirmed. Reconnect with npm run login; do not retry an old code or refresh token.');
  }
  if (!response.ok) throw new ComickError('reconnect_required', `Comick token exchange failed (HTTP ${response.status}). Reconnect with npm run login; do not retry an old code or refresh token.`);
  let body: unknown;
  try { body = await response.json(); }
  catch { throw new ComickError('reconnect_required', 'Invalid Comick token response. Reconnect with npm run login.'); }
  const parsed = tokenSchema.safeParse(body);
  if (!parsed.success) throw new ComickError('reconnect_required', 'Invalid Comick token response or library:read not granted. Reconnect with npm run login.');
  const { expires_in, ...tokens } = parsed.data;
  return { ...tokens, client_id: id, expires_at: Date.now() + expires_in * 1000 };
}

let tokenQueue: Promise<unknown> = Promise.resolve();
export async function accessToken(rejectedToken?: string, requiredScope = 'library:read') {
  const waitMs = Number(process.env.COMICK_TOKEN_QUEUE_TIMEOUT_MS ?? 30_000);
  if (!Number.isInteger(waitMs) || waitMs < 1 || waitMs > 300_000) {
    throw new ComickError('configuration_required', 'COMICK_TOKEN_QUEUE_TIMEOUT_MS must be an integer between 1 and 300000.');
  }
  let expired = false;
  let timer: ReturnType<typeof setTimeout>;
  const timeoutError = new ComickError('credentials_busy', 'Timed out waiting for queued Comick token access. No API request was sent.');
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => { expired = true; reject(timeoutError); }, waitMs);
  });
  const request = tokenQueue.then(() => {
    if (expired) throw timeoutError;
    clearTimeout(timer);
    return locked(async () => {
      const id = clientId();
      const tokens = await load(id);
      if (!tokens) throw new ComickError('reconnect_required', 'No Comick credentials in OS keyring. Use comick_connect or npm run login first.');
      if (!tokens.scope.split(' ').includes(requiredScope)) throw new ComickError('write_permission_required', 'library:write was not granted. Enable library writes for the app, then reconnect and explicitly allow writes. Read-only access still works.');
      if (tokens.expires_at > Date.now() + 30_000 && tokens.access_token !== rejectedToken) return tokens.access_token;
      if (!tokens.refresh_token) throw new ComickError('reconnect_required', 'Comick session expired or revoked. Reconnect with npm run login.');
      const { refresh_token, ...withoutRefresh } = tokens;
      // A refresh may consume the old token even if its response is lost; never reuse it.
      await save({ ...withoutRefresh, expires_at: 0 });
      const replacement = await exchange({ grant_type: 'refresh_token', refresh_token }, id);
      await save(replacement);
      if (!replacement.scope.split(' ').includes(requiredScope)) throw new ComickError('write_permission_required', 'library:write is no longer granted. Reconnect and explicitly allow writes; read-only access still works.');
      return replacement.access_token;
    });
  });
  tokenQueue = request.then(() => undefined, () => undefined);
  return Promise.race([request, timeout]).finally(() => clearTimeout(timer));
}

export async function login(onAuthorize?: (url: string) => void) {
  const id = clientId();
  const callback = new URL(process.env.COMICK_REDIRECT_URI ?? 'http://127.0.0.1:8787/callback');
  if (callback.protocol !== 'http:' || callback.hostname !== '127.0.0.1' || !callback.port || callback.username || callback.password || callback.search || callback.hash) {
    throw new Error('COMICK_REDIRECT_URI must be an HTTP 127.0.0.1 URL with an explicit port and no credentials, query or fragment.');
  }
  return locked(async () => {
    const verifier = randomBytes(32).toString('base64url');
    const state = randomBytes(32).toString('base64url');
    const authorize = new URL(`${issuer}/authorize`);
    authorize.search = new URLSearchParams({
      response_type: 'code', client_id: id, redirect_uri: callback.href,
      scope: 'library:read library:write offline_access', resource, state,
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
          const code = codes[0];
          const denied = url.searchParams.has('error');
          if (!denied && (codes.length !== 1 || !code)) {
            response.writeHead(400).end('Missing or duplicate authorization code.');
            return;
          }
          consumed = true;
          clearTimeout(timer);
          if (denied || !code) {
            response.writeHead(400).end('Authorization denied.');
            reject(new Error('Comick authorization denied.'));
            return;
          }
          response.setHeader('Content-Type', 'text/html; charset=utf-8');
          response.setHeader('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'");
          response.end(`<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#151821"><title>Comick MCP — Authorization received</title>
<style>
  :root { color-scheme: dark; font: 16px/1.55 system-ui, sans-serif; background: #151821; color: #e6e9f0; }
  body { box-sizing: border-box; min-height: 100vh; min-height: 100svh; max-width: 36rem; margin: 0 auto; padding: 1rem; display: flex; flex-direction: column; justify-content: center; text-align: center; }
  h1 { font-size: 1.5rem; margin: 0 0 1.25rem; }
  p { margin: 0; padding: 1rem; background: #202531; border: 1px solid #394151; border-radius: .75rem; }
</style>
<h1>Comick MCP</h1>
<p>Authorization received. Sign-in is still in progress. Return to your MCP client or connection page and check the connection status before using Comick tools.</p>
</html>`);
          accept(code);
        });
        console.error(`Open this URL in your browser to connect Comick:\n${authorize.href}`);
        try {
          onAuthorize?.(authorize.href);
        } catch (error) {
          clearTimeout(timer);
          reject(error);
        }
      });
      const tokens = await exchange({ grant_type: 'authorization_code', code, redirect_uri: callback.href, code_verifier: verifier }, id);
      await save(tokens);
      console.error(`Comick connected (${tokens.scope}).${tokens.refresh_token ? '' : ' Offline access declined; login again when the access token expires.'}`);
      return { scope: tokens.scope, expires_at: tokens.expires_at, refresh_available: Boolean(tokens.refresh_token) };
    } finally {
      server.closeAllConnections();
      await new Promise<void>((accept, reject) => server.close(error => error ? reject(error) : accept()));
    }
  });
}

function openBrowser(url: string): Promise<{ browser_opened: boolean; browser_message?: string }> {
  // ponytail: automatic launch uses Linux xdg-open; add platform launchers for macOS/Windows.
  if (process.platform !== 'linux') return Promise.resolve({ browser_opened: false, browser_message: 'Open authorization_url manually in your browser.' });
  return new Promise(resolve => {
    execFile('xdg-open', [url], { timeout: 10_000 }, error => resolve(error
      ? { browser_opened: false, browser_message: 'Could not open the system browser. Open authorization_url manually on the MCP server machine.' }
      : { browser_opened: true }));
  });
}

export type ConnectionStatus = {
  status: 'idle' | 'pending' | 'failed' | 'connected' | 'saved' | 'disconnected';
  authorization_url?: string;
  expires_in_seconds?: number;
  scope?: string;
  expires_at?: number;
  expired?: boolean;
  refresh_available?: boolean;
  message?: string;
  last_login_error?: string;
  browser_opened?: boolean;
  browser_message?: string;
};

let pendingLogin: Promise<void> | undefined;
let connection: ConnectionStatus = { status: 'idle' };

export async function connect(action: 'start' | 'status', open_browser = true): Promise<ConnectionStatus> {
  if (action === 'status') {
    if (connection.status === 'pending') return connection;
    const id = clientId();
    const saved = await load(id);
    if (!saved) return connection.status === 'failed' ? connection : { status: 'disconnected' };
    return { status: connection.status === 'connected' ? 'connected' : 'saved', scope: saved.scope, expires_at: saved.expires_at, expired: saved.expires_at <= Date.now() + 30_000, refresh_available: Boolean(saved.refresh_token),
      ...(connection.status === 'failed' ? { last_login_error: connection.message } : {}) };
  }
  if (pendingLogin) return connection;
  let ready!: () => void;
  let failed!: (error: unknown) => void;
  const started = new Promise<void>((resolve, reject) => { ready = resolve; failed = reject; });
  connection = { status: 'pending' };
  pendingLogin = login(url => {
    connection = { status: 'pending', authorization_url: url, expires_in_seconds: 300 };
    ready();
  }).then(summary => {
    connection = { status: 'connected', ...summary };
  }, error => {
    connection = { status: 'failed', message: error instanceof Error ? error.message : 'Comick login failed.' };
    failed(error);
  }).finally(() => { pendingLogin = undefined; });
  await started;
  if (open_browser && connection.authorization_url) {
    const browser = await openBrowser(connection.authorization_url);
    if (connection.status === 'pending') connection = { ...connection, ...browser };
  }
  return connection;
}

export const disconnectOutput = z.object({
  status: z.literal('disconnected'),
  local_deleted: z.literal(true),
  revocation: z.enum(['complete', 'partial', 'failed', 'not_needed']),
  warnings: z.array(z.string()),
});

export async function disconnect() {
  if (pendingLogin) throw new ComickError('credentials_busy', 'Comick credentials are busy. Finish the pending login before disconnecting.');
  return locked(async () => {
    const id = clientId();
    const tokens = await load(id);
    const warnings: string[] = [];
    const credentials = tokens ? [
      { token: tokens.access_token, token_type_hint: 'access_token' },
      ...(tokens.refresh_token ? [{ token: tokens.refresh_token, token_type_hint: 'refresh_token' }] : []),
    ] : [];
    let revoked = 0;
    for (const credential of credentials) {
      try {
        const response = await fetch(`${issuer}/revoke`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ client_id: id, ...credential }),
          signal: AbortSignal.timeout(20_000), redirect: 'error', credentials: 'omit',
        });
        if (response.ok) revoked++;
        else warnings.push(`Could not revoke ${credential.token_type_hint} (HTTP ${response.status}).`);
      } catch {
        warnings.push(`Could not confirm revocation of ${credential.token_type_hint}; no automatic retry was made.`);
      }
    }
    await keyring('clear', id);
    connection = { status: 'disconnected' };
    if (revoked < credentials.length) warnings.push('Local credentials were deleted, but server access may remain. Disconnect this app at https://comick.dev/user/connected-apps.');
    return disconnectOutput.parse({
      status: 'disconnected', local_deleted: true,
      revocation: credentials.length === 0 ? 'not_needed' : revoked === credentials.length ? 'complete' : revoked ? 'partial' : 'failed',
      warnings,
    });
  });
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  login(url => {
    void openBrowser(url).then(result => {
      if (!result.browser_opened) console.error(result.browser_message);
    });
  }).catch(error => {
    console.error(error instanceof Error ? error.message : 'Comick login failed.');
    process.exitCode = 1;
  });
}
