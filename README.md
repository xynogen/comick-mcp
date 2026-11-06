# Comick MCP

Search Comick titles and chapters, or read your library progress through a local stdio MCP server. Public search needs no login. Search returns five short results by default; request details only for titles you choose.

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

For public catalog tools only, remove the `env` block. In Pi, run `pi mcp list` to check the connection. To pin a version, use `github:xynogen/comick-mcp#COMMIT_HASH`.

## Get a Comick client ID

Library tools require a verified Comick account and your own public app:

1. Sign in at [Comick My apps](https://comick.dev/developers/apps) and create an app.
2. Select a **public browser/native** client, not a confidential backend client.
3. Enter a name, description, and access reason explaining that the app reads your library and saved progress. See [Comick's required field lengths](https://comick.dev/docs/register-app).
4. Register the exact callback `http://127.0.0.1:8787/callback` (including `/callback`; no wildcards). If you change `COMICK_REDIRECT_URI`, register the replacement URL too.
5. Copy the app's `client_id` into `COMICK_CLIENT_ID` in the config above. Public clients do **not** use a client secret.

Call `comick_connect` with `action: "start"`, approve `library:read offline_access` in your browser, then call it with `action: "status"`. On Windows, open the returned `authorization_url` on the same machine. Use `comick_disconnect` to revoke tokens and remove local credentials. **Pi's `/mcp login` is not used** for this stdio server.

## Optional browser connect page

The `npx` MCP command does **not** start an HTTP server. For the separate localhost UI, use a local checkout: copy `.env.example` to `.env`, fill in `COMICK_CLIENT_ID`, then run:

```bash
npm ci
npm run ui
```

Open `http://127.0.0.1:8788/`. Click **Connect Comick**, approve access, then **Reload status**. The OAuth callback temporarily listens on `127.0.0.1:8787`; both ports must be free. `COMICK_UI_PORT` defaults to `8788` and changes only the UI port. `npm start` runs the stdio MCP server instead.

## Tools

| Public, no login | Library/account |
|:---|:---|
| `comick_search` (5 titles: HID, slug, name), `comick_title` (selected title's genres, synopsis and related works), `comick_filters`, `comick_chapters` | `comick_connect`, `comick_disconnect`, `comick_me`, `comick_library`, `comick_library_entry` |

MCP responses contain JSON. Follow **search → selected title → related works**; use `detailed: true` on search or title only when more fields are needed. Search has `page` and `limit` but no total count. The UI's `GET /`, `GET /status`, and `POST /connect` are loopback-only HTTP routes, **not** an MCP HTTP endpoint.

## Security and development

OAuth tokens live in Windows Credential Manager or, on Linux, an unlocked Secret Service keyring with `secret-tool`; there is no plaintext fallback. `.env` is ignored by Git and is only for the local checkout—GitHub `npx` reads variables from the MCP config. `COMICK_CLIENT_ID` is public, but never put access tokens or a client secret there.

```bash
npm ci
npm test       # builds TypeScript and runs Node tests
npm run build
```

No license has been declared for this repository; do not assume permission to redistribute it.
