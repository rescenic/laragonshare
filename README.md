# Laragon → ngrok

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
- Several vhosts can be shared at once. Each share is its own ngrok agent with its own public
  URL, shown in the **Shared** column.
- **Stop sharing** stops only the selected vhost's share; **Stop all** or closing the window
  stops every share the app started. ngrok processes started outside the app are never touched.

No auth, rate limiting or traffic policy is added. Vhosts whose names look like database/admin
tools (`*-db`, `adminer`, `phpmyadmin`, …) ask for confirmation before being made public.

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
| Public URL redirects to `http://<site>.ic/...` | The app has its own base URL (e.g. WordPress `siteurl`, Laravel `APP_URL`). |
| Local check returns 503 | The vhost proxies to a backend (e.g. a Node app) that isn't running. |
| ngrok keeps running after a crash | `taskkill /IM ngrok.exe /F` (stops every ngrok process). |

`--host-header` still works in ngrok 3.39 but is no longer listed in `ngrok http --help`; a future
ngrok release may drop it.
