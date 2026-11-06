# Comick MCP

A local MCP server for searching Comick titles, reading title and chapter details, and checking your Comick library progress. It uses stdio for MCP and provides a separate, optional loopback-only browser page for account connection. Search works without an account; library tools require Comick OAuth.

Search returns five short entries by default. Request details only for selected titles to keep tool responses small. Tokens stay in Windows Credential Manager or Linux Secret Service, not in the MCP configuration or browser.

## Requirements

- Node.js 22.16 or newer and npm; Git for the GitHub `npx` install.
- For account features: a verified Comick account and a public browser/native app registered at https://comick.dev/developers/apps with callback `http://127.0.0.1:8787/callback`. No client secret is needed.
- Windows Credential Manager on Windows, or `secret-tool` and an unlocked Secret Service keyring on Linux. Public catalog tools need neither.

## Create a Comick app ID

Public catalog searches need no app ID. For OAuth and library tools, create one app under your own Comick account:

1. Sign in with a verified account and open [My apps](https://comick.dev/developers/apps). Select the option to create an app.
2. Choose a **public browser/native client** (not a confidential backend client). Comick does not let you change the client type later.
3. Enter a name (3–80 characters), a description (10–2,000 characters), and a reason for access (10–2,000 characters). Explain that this local MCP reads your library and saved progress.
4. Register the **exact callback URL** `http://127.0.0.1:8787/callback`. Include `/callback`; Comick does not accept wildcards. If you change `COMICK_REDIRECT_URI`, register that exact URL instead.
5. Save the app and copy its `client_id`. Put it in `COMICK_CLIENT_ID` under the MCP configuration's `env` object below. This ID is public; **do not** put a client secret in the config. The MCP requests `library:read offline_access` when you connect.

Comick's [registration guide](https://comick.dev/docs/register-app) describes the app fields and callback rules. Finish the OAuth consent by using `comick_connect`, not Pi's `/mcp login`.

## Quick start: MCP from GitHub

Add this server to your MCP client's configuration (Pi: `~/.pi/agent/mcp.json`, or `.pi/mcp.json` in a trusted project). Replace `YOUR_PUBLIC_DESKTOP_APP_CLIENT_ID` with the `client_id` copied above. The GitHub command works **after these changes are pushed** to that repository; it does not run unpushed local changes.

```json
{
  "mcpServers": {
    "comick": {
      "command": "npx",
      "args": ["-y", "github:xynogen/comick-mcp"],
      "env": {
        "COMICK_CLIENT_ID": "YOUR_PUBLIC_DESKTOP_APP_CLIENT_ID",
        "COMICK_REDIRECT_URI": "http://127.0.0.1:8787/callback"
      }
    }
  }
}
```

`npx` downloads the GitHub source, builds it during installation, and runs the MCP executable. It does **not** start the browser UI. In Pi, run `pi mcp list` to check the connection or use `/mcp` in a session. Use `comick_connect` with `action: "start"` to authorize your account; on Windows, open its returned `authorization_url` on the same computer, then check `action: "status"`. For reproducible installs, append a commit hash to the GitHub spec (for example, `github:xynogen/comick-mcp#COMMIT_HASH`).

## Local checkout and browser UI

The browser page is separate from the MCP stdio process. To run it from a checkout, set the public client ID in your shell environment or copy `.env.example` to `.env` and fill in `COMICK_CLIENT_ID`:

```bash
npm ci
npm run build
npm run ui
```

Open `http://127.0.0.1:8788/`, click **Connect Comick**, approve access in the browser, then click **Reload status**. The OAuth callback uses `http://127.0.0.1:8787/callback`; both ports must be available. The page cannot be opened remotely and does not store tokens. `npm start` runs the MCP stdio server from a checkout; do not open its output as a web page.

## Environment configuration

The MCP client's `env` object supplies the public app ID and callback URI to the stdio process. These are not OAuth access tokens. `.env` is only a local checkout convenience; it is **not** read by the GitHub `npx` command.

| Variable | Default | Purpose |
|:---|---:|:---|
| `COMICK_CLIENT_ID` | Unset | Public app ID; required for OAuth/account tools, not public search. |
| `COMICK_REDIRECT_URI` | `http://127.0.0.1:8787/callback` | Exact loopback callback registered with your Comick app. |
| `COMICK_UI_PORT` | `8788` | Port for the optional local browser page and callback return link. |

The CLI does not accept a client secret. Access and refresh tokens are written to the OS credential store; no plaintext token fallback exists. Keep `.env` out of Git and provide deployment variables through the platform's environment settings. Public search can be used with no `env` block.

## Authentication

`comick_connect` starts OAuth PKCE with `library:read offline_access`. It accepts `start` and `status`; `comick_disconnect` revokes stored tokens and clears local credentials. Pi's `/mcp login` is **not** the login method for this stdio server. The local UI handles the same Comick OAuth flow; it does not authenticate the MCP transport.

## Tools and local HTTP routes

MCP tools return JSON, including `structuredContent` where supported. Search has no invented total count; use `page` and `limit` to request another page.

| Group | Tools or routes |
|:---|:---|
| Public catalog | `comick_search` (5 short results by default, `detailed: true` opt-in), `comick_title`, `comick_filters`, `comick_chapters` |
| Account | `comick_connect`, `comick_disconnect`, `comick_me`, `comick_library`, `comick_library_entry` |
| Optional loopback UI | `GET /` (connect page), `GET /status`, `POST /connect` on port `8788`; temporary OAuth `GET /callback` on port `8787` during login |

The local HTTP routes are not an MCP HTTP endpoint. The UI binds to `127.0.0.1` only.

## Development

Use the existing npm scripts to build and verify changes:

```bash
npm ci
npm test
npm run ui
```

`npm test` builds TypeScript and runs the Node test suite. The GitHub install uses npm's `prepare` script to build `dist/`; no container workflow or served API documentation is included.

## License

No license has been declared for this repository. Do not assume permission to redistribute it.
