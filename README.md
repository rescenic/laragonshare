# Laragon → ngrok

<img width="1002" height="712" alt="image" src="https://github.com/user-attachments/assets/023de5b1-3c22-4af8-b2e5-fbf46a58f2f1" />

A small Windows GUI that lists the Apache vhosts from Laragon's `sites-enabled` folder and shares
the one you pick through an [ngrok](https://ngrok.com) agent endpoint, then checks that the public
URL really serves the same page as the local site.

Single file, Python standard library only (Tkinter).

## What it does

- Reads every `*.conf` in `sites-enabled` (default `D:\laragon\etc\apache2\sites-enabled`),
  expanding Laragon's `define SITE` / `define ROOT` variables, and lists each vhost with its
  ports and document root or proxy target.
- **Check locally** – requests `/` from `127.0.0.1` with the vhost's `Host` header (and SNI for
  HTTPS) and shows the status, title and the start of the body. Double-clicking a row does the same.
- **Share via ngrok** – checks locally first, then starts in the background:
  - `ngrok http 80 --host-header=<vhost>` for normal vhosts, or
  - `ngrok http https://<vhost>:443 --host-header=<vhost>` when port 80 only redirects to HTTPS.
- Reads the public URL from ngrok's JSON log (falling back to that agent's own
  `/api/tunnels`), requests it and compares it with the local response. It reports ngrok error
  pages (e.g. `ERR_NGROK_8012`) and apps that redirect to their local `.ic`/`.test` base URL.
- **Rewrite links** (on by default) – see [Link rewriting](#link-rewriting).
- Several vhosts can be shared at once. Each share is its own ngrok agent with its own public
  URL, shown in the **Shared** column.
- **Stop sharing** stops only the selected vhost's share; **Stop all** or closing the window
  stops every share the app started. ngrok processes started outside the app are never touched.

No auth, rate limiting or traffic policy is added. Vhosts whose names look like database/admin
tools (`*-db`, `adminer`, `phpmyadmin`, …) ask for confirmation before being made public.

## Link rewriting

Many apps build absolute URLs from a configured base URL (CodeIgniter `base_url`, WordPress
`siteurl`, Laravel `APP_URL`, ...), so menus on the public page still point at `http://<site>.ic/`.
With **Rewrite links** on, ngrok forwards to a small proxy inside the app
(`ngrok http http://127.0.0.1:<random port>`) instead of straight to Apache. The proxy:

- sends the request to Apache on 127.0.0.1 as the vhost (Host header, and SNI for HTTPS)
- replaces `http(s)://<vhost>`, `//<vhost>`, JSON-escaped `http:\/\/<vhost>` and URL-encoded
  `http%3A%2F%2F<vhost>` with the public URL in HTML, CSS, JS, JSON, XML and SVG responses, and
  in `Location`, `Content-Location`, `Refresh` and `Link` headers
- drops `Domain=<vhost>` from cookies so the browser keeps them on the public host
- maps the public origin in `Origin` / `Referer` back to the vhost, so CSRF/origin checks pass
- sets `X-Forwarded-Host` to the public host

Limits: binary files pass through untouched, responses that Apache compresses anyway aren't
rewritten, bare hostnames without a scheme or `//` are left alone, and WebSockets aren't
proxied. For a WebSocket app, untick the option, or set the app's base URL from the request
host instead (e.g. derive CodeIgniter's `base_url` from `$_SERVER['HTTP_X_FORWARDED_HOST'] ??
$_SERVER['HTTP_HOST']`).

## Requirements

- Windows with [Laragon](https://laragon.org) (Apache)
- ngrok 3.x, already authenticated (`ngrok config add-authtoken <token>`; check with
  `ngrok config check`)
- Python 3.8+ with Tkinter to run from source (not needed for the `.exe`)

ngrok is looked up in this order:

1. `ngrok.exe` next to the script / `.exe`
2. `ngrok` on `PATH`
3. `D:\laragon\bin\ngrok\ngrok.exe`

## Run from source

```powershell
pythonw laragon_share.py                     # default sites-enabled folder
pythonw laragon_share.py "E:\laragon\etc\apache2\sites-enabled"
```

## Build a portable .exe

```powershell
python -m venv .venv
.venv\Scripts\pip install pyinstaller
.venv\Scripts\pyinstaller --noconfirm --clean --onefile --windowed --name LaragonShare laragon_share.py
```

The result is `dist\LaragonShare.exe`. To carry it to another PC, put `ngrok.exe` in the same
folder and run `ngrok config add-authtoken <token>` there once. Don't copy `ngrok.yml`; it
contains your authtoken.

The `.exe` is unsigned, so SmartScreen or antivirus may warn on first run. Use `--onedir` instead
of `--onefile` for faster startup and fewer false positives.

## Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| `ERR_NGROK_8012` on the public URL | ngrok can't reach Apache: Apache stopped, or wrong upstream (try the other HTTP/HTTPS option). |
| `ERR_NGROK_334` / endpoint already online | Another ngrok agent is already using your dev domain. Stop it first. |
| Public page links or redirects to `http://<site>.ic/...` | The app has its own base URL. Share with **Rewrite links** on; the log reports any links still left. |
| Local check returns 503 | The vhost proxies to a backend (e.g. a Node app) that isn't running. |
| ngrok keeps running after a crash | `taskkill /IM ngrok.exe /F` (stops every ngrok process). |

`--host-header` still works in ngrok 3.39 but is no longer listed in `ngrok http --help`; a future
ngrok release may drop it.
