import { createServer } from 'node:http';
import { fileURLToPath } from 'node:url';
import { connect, ComickError } from './oauth.js';

const page = `<!doctype html>
<html lang="id">
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
<p id="message" role="status" aria-live="polite">Memuat status…</p>
<p id="actions">
  <button id="reload" type="button">Reload status</button>
  <button id="start" type="button">Connect Comick</button>
</p>
<p id="link"></p>
<p>Setelah izin diberikan di Comick, kembali ke sini dan klik Reload status. Token disimpan di OS keyring, bukan di browser.</p>
<script nonce="NONCE">
  const message = document.getElementById('message');
  const link = document.getElementById('link');
  const start = document.getElementById('start');

  async function request(path, method = 'GET') {
    const response = await fetch(path, {
      method,
      headers: method === 'POST' ? { 'Content-Type': 'application/json' } : {},
      cache: 'no-store',
    });
    const body = await response.json();
    if (!response.ok) throw Error(body.error || 'Permintaan gagal.');
    return body;
  }

  function show(status) {
    const states = {
      connected: 'Terhubung',
      saved: 'Terhubung (sesi tersimpan)',
      disconnected: 'Belum terhubung',
      pending: 'Menunggu izin Comick',
      failed: 'Gagal',
    };
    const expiry = status.expired
      ? status.refresh_available
        ? ' — token kedaluwarsa; akan diperbarui saat dipakai'
        : ' — token kedaluwarsa; connect ulang'
      : '';
    const detail = status.message?.startsWith('Comick credentials are busy.')
      ? 'Proses login lain masih berjalan. Tutup proses tersebut lalu coba lagi.'
      : status.message;
    message.textContent = 'Status: ' + (states[status.status] || status.status)
      + expiry + (detail ? ' — ' + detail : '');
    start.disabled = status.status === 'pending';
    link.replaceChildren();

    if (status.status === 'pending' && status.authorization_url) {
      const url = new URL(status.authorization_url);
      if (url.origin === 'https://comick.dev') {
        const a = document.createElement('a');
        a.href = url.href;
        a.rel = 'noopener noreferrer';
        a.target = '_blank';
        a.textContent = 'Buka halaman izin Comick';
        link.append(a);
      }
    }
  }

  async function run(path, method) {
    try {
      show(await request(path, method));
    } catch (error) {
      message.textContent = 'Gagal: ' + error.message;
      start.disabled = false;
    }
  }

  document.getElementById('reload').addEventListener('click', () => run('/status'));
  start.addEventListener('click', () => run('/connect', 'POST'));
  run('/status');
</script>
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
      response.end(page.replace('NONCE', nonce));
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
              ? 'Proses login lain masih berjalan. Tutup proses tersebut lalu coba lagi.'
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
