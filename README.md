# Comick MCP

Search Comick titles and read or update your library through a local stdio MCP server. All account and catalog requests use the official OAuth integration API and require login. Search returns five short results by default; request details only for titles you choose.

## Install from GitHub

Requires Node.js 22.16+, npm, and Git. Put this in your MCP client config (Pi: `~/.pi/agent/mcp.json` or a trusted project's `.pi/mcp.json`):

```json
{
  "mcpServers": {
    "comick": {
      "command": "npx",
      "args": ["-y", "github:xynogen/comick-mcp"],
      "env": {
        "COMICK_CLIENT_ID": "YOUR_PUBLIC_CLIENT_ID",
        "COMICK_REDIRECT_URI": "http://127.0.0.1:8787/callback"
      }
    }
  }
}
```

In Pi, run `pi mcp list` to check the connection. To pin a version, use `github:xynogen/comick-mcp#COMMIT_HASH`. Keep the `env` block: catalog reads also require OAuth.

## Get a Comick client ID

OAuth access requires a verified Comick account and your own public app:

1. Sign in at [Comick My apps](https://comick.dev/developers/apps) and create an app.
2. Select a **public browser/native** client, not a confidential backend client.
3. Enter a name, description, and access reason explaining that the app reads your library and saved progress. See [Comick's required field lengths](https://comick.dev/docs/register-app).
4. Register the exact callback `http://127.0.0.1:8787/callback` (including `/callback`; no wildcards). If you change `COMICK_REDIRECT_URI`, register the replacement URL too.
5. Copy the app's `client_id` into `COMICK_CLIENT_ID` in the config above. Public clients do **not** use a client secret.

Call `comick_connect` with `action: "start"`, approve access in your browser, then call it with `action: "status"`. The app requests `library:read library:write offline_access`; enable writes in app settings and explicitly approve them to use library save/remove. Declining writes keeps read-only access. On Windows, open the returned `authorization_url` on the same machine. Use `comick_disconnect` to revoke tokens and remove local credentials. **Pi's `/mcp login` is not used** for this stdio server.

## Optional browser connect page

The `npx` MCP command does **not** start an HTTP server. For the separate localhost UI, use a local checkout: copy `.env.example` to `.env`, fill in `COMICK_CLIENT_ID`, then run:

```bash
npm ci
npm run ui
```

Open `http://127.0.0.1:8788/`. Click **Connect Comick**, approve access, then **Reload status**. The OAuth callback temporarily listens on `127.0.0.1:8787`; both ports must be free. `COMICK_UI_PORT` defaults to `8788` and changes only the UI port. `npm start` runs the stdio MCP server instead.

## Tools

| Tools | Purpose |
|:---|:---|
| `comick_connect`, `comick_disconnect` | Start/check OAuth login; revoke tokens and delete local credentials. |
| `comick_search`, `comick_title` | Search title/alternative-title keywords; read title metadata by HID. Requires `library:read`. |
| `comick_me`, `comick_library`, `comick_library_entry` | Read your account, library pages, and saved progress for one title. Requires `library:read`. |
| `comick_library_save`, `comick_library_remove` | Update/upsert a library entry, or explicitly unfollow with `confirm:true`. Requires `library:write`. |

MCP responses contain JSON. Use **search → selected title HID → title/library entry**. Search takes `query` (2–100 characters), `media_type` (`manga` by default), `limit` (1–20, default 5), and `detailed` (default false). Title takes `hid`, not a slug. `detailed:true` includes the metadata supplied by the integration API. Search has no pagination or genre/group filters. Chapters, chapter images, scanlation groups, and related-work recommendations are not supported.

Library calls default to 5 entries. Use `{}` or `cursor:null` for page one, copy `next_cursor` unchanged with the same filters for later pages, and stop when it is null. Status: 1 reading/watching, 2 completed, 3 on hold, 4 dropped, 5 planned.

Library save defaults to `action:"update"` (PATCH existing); `action:"upsert"` (PUT) requires a status. Omitted fields stay unchanged; `progress:null` or `rating:null` clears only that field. Removal deletes saved progress, notes, rating, and custom-list memberships. Avoid parallel writes. If a write outcome is unknown, read the entry before retrying.

The UI's `GET /`, `GET /status`, and `POST /connect` are loopback-only HTTP routes, **not** an MCP HTTP endpoint. A failed sign-in attempt does not hide an existing saved session; status includes `last_login_error` when applicable.

## Security and development

OAuth tokens live in Windows Credential Manager or, on Linux, an unlocked Secret Service keyring with `secret-tool`; there is no plaintext fallback. `.env` is ignored by Git and is only for the local checkout—GitHub `npx` reads variables from the MCP config. `COMICK_CLIENT_ID` is public, but never put access tokens or a client secret there.

Token access is queued within each process; a filesystem lock also protects refresh rotation across processes. `COMICK_TOKEN_QUEUE_TIMEOUT_MS` limits queue waiting (default `30000`, integer range `1`–`300000` ms). Expired queued calls do not access credentials or send API requests. Once token work starts, existing keyring/network timeouts apply; it is not cancelled mid-refresh. Reduce concurrency first if queue waits persist.

The server has MCP and optional HTTP UI entry points, operations/schema validation in `src/integration.ts`, authenticated API transport in `src/api.ts`, and OAuth/credential handling in `src/oauth.ts`. No dependency-injection framework or unused ports are added. Tests use mocked credentials/upstream responses and real loopback/MCP transports; they do not prove live API behavior.

```bash
npm ci
npm test       # builds TypeScript and runs Node tests
npm run build
```

## License

[MIT](LICENSE). This license covers this server, not Comick content or third-party services.
