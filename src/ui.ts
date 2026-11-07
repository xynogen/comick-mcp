import { createServer } from 'node:http';
import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';
import { connect, ComickError } from './oauth.js';

const clientScript = readFileSync(new URL('./ui-client.js', import.meta.url), 'utf8');

const page = `<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#151821">
<title>Comick MCP — Connect</title>
<style>
  :root {
    color-scheme: dark;
    font: 16px/1.55 system-ui, sans-serif;
    background: #151821;
    color: #e6e9f0;
  }
  body {
    box-sizing: border-box;
    width: 100%;
    max-width: 36rem;
    min-height: 100vh;
    min-height: 100svh;
    margin: 0 auto;
    padding: 1rem;
    display: flex;
    flex-direction: column;
    justify-content: center;
  }
  h1 {
    font-size: 1.5rem;
    margin: 0 0 1.25rem;
    text-align: center;
  }
  #message {
    margin: 0;
    overflow-wrap: anywhere;
    white-space: pre-wrap;
    background: #202531;
    border: 1px solid #394151;
    border-radius: .75rem;
    padding: 1rem;
  }
  #actions {
    margin: 1rem 0 0;
    display: flex;
    justify-content: center;
    gap: .5rem;
    flex-wrap: wrap;
  }
  button {
    font: inherit;
    color: #e6e9f0;
    background: #292f3d;
    border: 1px solid #50596d;
    border-radius: .5rem;
    padding: .55rem .9rem;
    cursor: pointer;
  }
  button:hover { background: #394151; }
  button:focus-visible, a:focus-visible {
    outline: 2px solid #a0baff;
    outline-offset: 3px;
  }
  button:disabled { opacity: .5; cursor: not-allowed; }
  a { color: #a0baff; overflow-wrap: anywhere; }
  #link:not(:empty) { margin: 1rem 0 0; text-align: center; }
  #link:empty { display: none; }
  p:last-of-type { color: #aeb6c6; margin: 1.5rem 0 0; font-size: .875rem; text-align: center; }
</style>
<h1>Comick MCP</h1>
<p id="message" role="status" aria-live="polite">Loading status…</p>
<p id="actions">
  <button id="reload" type="button">Reload status</button>
  <button id="start" type="button">Connect Comick</button>
</p>
<p id="link"></p>
<p>After approving access on Comick, return here and click Reload status. Tokens are stored in your OS keyring, not in your browser.</p>
<script type="module" nonce="NONCE">CLIENT_SCRIPT</script>
</html>`;

export function createUiServer() {
  const server = createServer(async (request, response) => {
    const origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('X-Content-Type-Options', 'nosniff');
    response.setHeader('Referrer-Policy', 'no-referrer');
    response.setHeader('X-Frame-Options', 'DENY');

    if (request.headers.host !== new URL(origin).host || request.url?.includes('?')) {
      response.writeHead(404).end('Not found.');
      return;
    }

    if (request.method === 'GET' && request.url === '/') {
      const nonce = Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString('base64');
      response.setHeader('Content-Security-Policy',
        `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'`);
      response.setHeader('Content-Type', 'text/html; charset=utf-8');
      response.end(page.replace('NONCE', nonce).replace('CLIENT_SCRIPT', () => clientScript));
      return;
    }

    if ((request.method === 'GET' && request.url === '/status')
      || (request.method === 'POST' && request.url === '/connect')) {
      response.setHeader('Content-Type', 'application/json; charset=utf-8');
      if (request.method === 'POST'
        && (request.headers.origin !== origin || request.headers['content-type'] !== 'application/json')) {
        response.writeHead(403).end(JSON.stringify({ error: 'Forbidden.' }));
        return;
      }
      try {
        response.end(JSON.stringify(await connect(request.method === 'POST' ? 'start' : 'status', false)));
      } catch (error) {
        response.writeHead(error instanceof ComickError && error.code === 'configuration_required' ? 503 : 500)
          .end(JSON.stringify({ error: error instanceof ComickError
            ? error.code === 'credentials_busy'
              ? 'Another sign-in process is still running. Close it and try again.'
              : error.message
            : 'Could not check Comick connection.' }));
      }
      return;
    }

    response.writeHead(404).end('Not found.');
  });
  return server;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const port = Number(process.env.COMICK_UI_PORT ?? 8788);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error('COMICK_UI_PORT must be between 1 and 65535.');
  }
  createUiServer().listen(port, '127.0.0.1', () => console.log(`Comick connect UI: http://127.0.0.1:${port}/`));
}
