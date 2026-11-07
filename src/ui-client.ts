type Status = Pick<import('./oauth.js').ConnectionStatus,
  'status' | 'message' | 'last_login_error' | 'authorization_url' | 'expired' | 'refresh_available'>;

const message = document.getElementById('message');
const link = document.getElementById('link');
const start = document.getElementById('start');
const reload = document.getElementById('reload');
if (!message || !link || !(start instanceof HTMLButtonElement) || !reload) {
  throw new Error('Connection page is missing its controls.');
}
const messageElement = message;
const linkElement = link;
const startButton = start;
const states: Record<Status['status'], string> = {
  idle: 'Not connected', connected: 'Connected', saved: 'Connected (saved session)',
  disconnected: 'Not connected', pending: 'Waiting for Comick authorization', failed: 'Failed',
};

function validateStatus(value: unknown): asserts value is Status {
  if (!value || typeof value !== 'object' || !('status' in value)
    || typeof value.status !== 'string' || !Object.hasOwn(states, value.status)) {
    throw new Error('Invalid connection status.');
  }
  for (const [key, field] of Object.entries(value)) {
    if (['message', 'last_login_error', 'authorization_url'].includes(key) && typeof field !== 'string') {
      throw new Error('Invalid connection status.');
    }
    if (['expired', 'refresh_available'].includes(key) && typeof field !== 'boolean') {
      throw new Error('Invalid connection status.');
    }
  }
}

async function request(path: string, method = 'GET'): Promise<Status> {
  const response = await fetch(path, {
    method, headers: method === 'POST' ? { 'Content-Type': 'application/json' } : {}, cache: 'no-store',
  });
  const body: unknown = await response.json();
  if (!response.ok) {
    const error = body && typeof body === 'object' && 'error' in body && typeof body.error === 'string'
      ? body.error : 'Request failed.';
    throw new Error(error);
  }
  validateStatus(body);
  return body;
}

function show(status: Status): void {
  const expiry = status.expired
    ? status.refresh_available ? ' — token expired; it will be refreshed when used' : ' — token expired; reconnect'
    : '';
  const detail = status.message?.startsWith('Comick credentials are busy.')
    ? 'Another sign-in process is still running. Close it and try again.'
    : status.last_login_error ? 'Last sign-in attempt failed: ' + status.last_login_error : status.message;
  messageElement.textContent = 'Status: ' + states[status.status] + expiry + (detail ? ' — ' + detail : '');
  startButton.disabled = status.status === 'pending';
  linkElement.replaceChildren();
  if (status.status === 'pending' && status.authorization_url) {
    const url = new URL(status.authorization_url);
    if (url.origin === 'https://comick.dev') {
      const anchor = document.createElement('a');
      anchor.href = url.href;
      anchor.rel = 'noopener noreferrer';
      anchor.target = '_blank';
      anchor.textContent = 'Open Comick authorization page';
      linkElement.append(anchor);
    }
  }
}

async function run(path: string, method?: string): Promise<void> {
  try { show(await request(path, method)); }
  catch (error) {
    messageElement.textContent = 'Failed: ' + (error instanceof Error ? error.message : 'Request failed.');
    startButton.disabled = false;
  }
}

reload.addEventListener('click', () => { void run('/status'); });
startButton.addEventListener('click', () => { void run('/connect', 'POST'); });
void run('/status');
