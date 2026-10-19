"""Laragon vhost -> ngrok share.

Lists the Apache vhosts in Laragon's sites-enabled folder and shares the selected one through an
ngrok agent endpoint (`ngrok http 80 --host-header=<vhost>`), then checks the public URL against
the local response. Optionally a built-in proxy sits between ngrok and Apache and rewrites the
site's own absolute links (http://<vhost>/...) to the public URL.

Standard library only. Run with:  pythonw laragon_share.py  [sites-enabled dir]
"""

import gzip
import http.client
import http.server
import json
import os
import queue
import re
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
import tkinter as tk
import urllib.request
import webbrowser
from dataclasses import dataclass
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from urllib.parse import urlsplit

DEFAULT_SITES_DIR = r"D:\laragon\etc\apache2\sites-enabled"
LARAGON_NGROK = r"D:\laragon\bin\ngrok\ngrok.exe"
TIMEOUT = 15
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
# ngrok logs these at error level on every start (e.g. when launched through a Scoop shim); they aren't failures.
BENIGN_NGROK_ERRORS = ("binary path for symlinks",)
# Names that usually mean a DB admin UI or similar; sharing one gets an extra confirmation.
RISKY_NAME = re.compile(r"(^|[-.])(db|pma|phpmyadmin|adminer|admin)([-.]|$)", re.I)


# ---------------------------------------------------------------------------------------------
# vhost parsing
# ---------------------------------------------------------------------------------------------

@dataclass
class VHost:
    site: str
    conf: str
    ports: list
    target: str            # DocumentRoot or proxy upstream
    http_redirects: bool   # port 80 only redirects to https


def parse_sites(sites_dir):
    hosts = {}
    for conf in sorted(Path(sites_dir).glob("*.conf")):
        text = conf.read_text(encoding="utf-8", errors="replace")
        defines = dict(re.findall(r'(?im)^\s*define\s+(\w+)\s+"?([^"\r\n]*)"?', text))
        expand = lambda s: re.sub(r"\$\{(\w+)\}", lambda m: defines.get(m.group(1), m.group(0)), s)
        text = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))

        for addr, body in re.findall(r"(?is)<VirtualHost\s+([^>]+)>(.*?)</VirtualHost>", text):
            name = re.search(r"(?im)^\s*ServerName\s+(\S+)", body)
            if not name:
                continue
            site = expand(name.group(1)).strip('"')
            port = int(m.group(1)) if (m := re.search(r":(\d+)", addr)) else 80
            vh = hosts.setdefault(site, VHost(site, conf.name, [], "", False))
            vh.ports = sorted(set(vh.ports) | {port})

            root = re.search(r'(?im)^\s*DocumentRoot\s+"?([^"\r\n]+)"?', body)
            proxies = dict(re.findall(r"(?im)^\s*ProxyPass\s+(\S+)\s+(\S+)", body))
            if proxies:
                vh.target = "proxy -> " + expand(proxies.get("/") or next(iter(proxies.values())))
            elif root and not vh.target:
                vh.target = expand(root.group(1))
            if port == 80 and not root and re.search(r"(?im)^\s*(RewriteRule|Redirect)\b.*https://", body):
                vh.http_redirects = True
    return sorted(hosts.values(), key=lambda v: v.site)


# ---------------------------------------------------------------------------------------------
# HTTP probes
# ---------------------------------------------------------------------------------------------

class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Dials a fixed address but sends the vhost name as SNI, like a browser would."""

    def __init__(self, server_name, port, dial_host, ctx, **kw):
        super().__init__(server_name, port, context=ctx, **kw)
        self._dial_host, self._ctx = dial_host, ctx

    def connect(self):
        sock = socket.create_connection((self._dial_host, self.port), self.timeout)
        self.sock = self._ctx.wrap_socket(sock, server_hostname=self.host)


APACHE_PORTS = {"http": 80, "https": 443}


def upstream_conn(vhost, scheme, timeout):
    """Connection to Apache on 127.0.0.1 that presents itself as the vhost (SNI for https)."""
    port = APACHE_PORTS[scheme]
    if scheme == "https":
        ctx = ssl.create_default_context()
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE  # Laragon's self-signed cert
        return _PinnedHTTPSConnection(vhost, port, "127.0.0.1", ctx, timeout=timeout)
    return http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)


@dataclass
class Probe:
    status: int = 0
    reason: str = ""
    location: str = ""
    title: str = ""
    body: str = ""
    ngrok_error: str = ""
    error: str = ""

    def summary(self):
        if self.error:
            return f"ERROR {self.error}"
        s = f"{self.status} {self.reason}"
        if self.location:
            s += f"  -> {self.location}"
        return s


def probe(host, scheme, dial_host=None, headers=None):
    """GET / without following redirects. With dial_host the request goes to local Apache as `host`."""
    hdrs = {"Host": host, "User-Agent": "laragon-share/1.0", "Accept": "*/*", **(headers or {})}
    try:
        if dial_host:
            conn = upstream_conn(host, scheme, TIMEOUT)
        elif scheme == "https":
            conn = http.client.HTTPSConnection(host, 443, context=ssl.create_default_context(), timeout=TIMEOUT)
        else:
            conn = http.client.HTTPConnection(host, 80, timeout=TIMEOUT)
        conn.request("GET", "/", headers=hdrs)
        resp = conn.getresponse()
        raw = resp.read(64 * 1024)
        conn.close()
    except Exception as e:  # noqa: BLE001 - shown to the user verbatim
        return Probe(error=f"{type(e).__name__}: {e}")

    body = raw.decode("utf-8", errors="replace")
    title = re.search(r"(?is)<title[^>]*>(.*?)</title>", body)
    ngrok_err = resp.getheader("ngrok-error-code") or (m.group(0) if (m := re.search(r"ERR_NGROK_\d+", body)) else "")
    return Probe(
        status=resp.status,
        reason=resp.reason,
        location=resp.getheader("Location") or "",
        title=re.sub(r"\s+", " ", title.group(1)).strip() if title else "",
        body=body,
        ngrok_error=ngrok_err,
    )


def snippet(text, n=240):
    return re.sub(r"\s+", " ", text).strip()[:n]


# ---------------------------------------------------------------------------------------------
# Link-rewriting proxy (ngrok -> this proxy -> Apache)
# ---------------------------------------------------------------------------------------------

HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "proxy-connection",
              "te", "trailer", "trailers", "transfer-encoding", "upgrade"}
REWRITE_TYPES = re.compile(r"text/|json|javascript|xml|svg|manifest", re.I)
MAX_REWRITE_BYTES = 32 * 1024 * 1024


class LinkRewriter:
    """Maps the vhost's absolute URLs to the public ngrok URL in responses, and the public origin
    back to the vhost in request headers (so Origin/Referer checks still pass)."""

    def __init__(self, vhost, scheme):
        self.vhost, self.scheme = vhost, scheme
        self.public_host = None
        self._rules = []

    def set_public(self, url):
        pub = urlsplit(url).hostname.encode()
        host = re.escape(self.vhost.encode())
        tail = rb"(?::(?:80|443))?(?![\w.-])"  # not a longer hostname such as <vhost>.example
        self._rules = [
            (re.compile(rb"https?://" + host + tail, re.I), b"https://" + pub),
            (re.compile(rb"https?:\\/\\/" + host + tail, re.I), b"https:\\/\\/" + pub),      # JSON-escaped
            (re.compile(rb"https?%3A%2F%2F" + host + tail, re.I), b"https%3A%2F%2F" + pub),  # URL-encoded
            (re.compile(rb"//" + host + tail, re.I), b"//" + pub),                           # protocol-relative
            (re.compile(rb"\\/\\/" + host + tail, re.I), b"\\/\\/" + pub),
        ]
        self._back = re.compile(r"https?://" + re.escape(pub.decode()) + r"(?![\w.-])", re.I)
        self.public_host = pub.decode()

    def to_public(self, data):
        for pattern, repl in self._rules:
            data = pattern.sub(lambda _m, r=repl: r, data)
        return data

    def to_public_str(self, text):
        return self.to_public(text.encode("latin-1")).decode("latin-1")

    def to_local(self, text):
        return self._back.sub(f"{self.scheme}://{self.vhost}", text) if self.public_host else text

    def strip_cookie_domain(self, cookie):
        return re.sub(r";\s*domain=\.?" + re.escape(self.vhost) + r"\s*(?=;|$)", "", cookie, flags=re.I)


class _ProxyHandler(http.server.BaseHTTPRequestHandler):
    # HTTP/1.0: one request per connection, so bodies of unknown length can simply run to EOF.
    server_version = "laragon-share"

    def log_message(self, *args):
        pass

    def do_proxy(self):
        px = self.server.px
        rw = px.rewriter
        try:
            body = self._request_body()
            conn = upstream_conn(px.vhost, px.scheme, timeout=300)
            conn.putrequest(self.command, self.path, skip_host=True, skip_accept_encoding=True)
            conn.putheader("Host", px.vhost)
            for k, v in self.headers.items():
                lk = k.lower()
                # Accept-Encoding is dropped so Apache answers uncompressed and the body can be rewritten.
                if lk in HOP_BY_HOP or lk in ("host", "accept-encoding", "content-length"):
                    continue
                if lk in ("origin", "referer"):
                    v = rw.to_local(v)
                conn.putheader(k, v)
            if rw.public_host and "X-Forwarded-Host" not in self.headers:
                conn.putheader("X-Forwarded-Host", rw.public_host)
            if body is not None:
                conn.putheader("Content-Length", str(len(body)))
            conn.endheaders(body)
            resp = conn.getresponse()
        except Exception as e:  # noqa: BLE001
            self.send_error(502, f"Laragon upstream unreachable: {e}")
            return
        try:
            self._relay(resp, rw)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass
        finally:
            conn.close()

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = do_proxy

    def _request_body(self):
        if "chunked" in self.headers.get("Transfer-Encoding", "").lower():
            chunks = []
            while size := int(self.rfile.readline().split(b";")[0].strip() or b"0", 16):
                chunks.append(self.rfile.read(size))
                self.rfile.readline()
            while self.rfile.readline().strip():  # trailers
                pass
            return b"".join(chunks)
        length = self.headers.get("Content-Length")
        return self.rfile.read(int(length)) if length is not None else None

    def _relay(self, resp, rw):
        ctype = resp.getheader("Content-Type", "")
        encoding = (resp.getheader("Content-Encoding") or "identity").lower()
        rewrite = (rw.public_host and self.command != "HEAD" and resp.status not in (204, 304)
                   and REWRITE_TYPES.search(ctype) and encoding == "identity"
                   and int(resp.getheader("Content-Length") or 0) <= MAX_REWRITE_BYTES)

        self.send_response_only(resp.status, resp.reason)
        for k, v in resp.getheaders():
            lk = k.lower()
            if lk in HOP_BY_HOP or (rewrite and lk == "content-length"):
                continue
            if rw.public_host and lk in ("location", "content-location", "refresh", "link"):
                v = rw.to_public_str(v)
            elif lk == "set-cookie":
                v = rw.strip_cookie_domain(v)
            self.send_header(k, v)

        if rewrite:
            data = rw.to_public(resp.read())
            if len(data) > 1024 and "gzip" in self.headers.get("Accept-Encoding", ""):
                data = gzip.compress(data, 6)
                self.send_header("Content-Encoding", "gzip")
                self.send_header("Vary", "Accept-Encoding")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        else:
            self.end_headers()
            if self.command != "HEAD":
                while chunk := resp.read(64 * 1024):
                    self.wfile.write(chunk)
        self.close_connection = True


class RewriteProxy:
    """Local HTTP proxy on 127.0.0.1:<random port> that forwards to Apache as the vhost."""

    def __init__(self, vhost, scheme):
        self.vhost, self.scheme = vhost, scheme
        self.rewriter = LinkRewriter(vhost, scheme)
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _ProxyHandler)
        self.httpd.px = self
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def stop(self):
        # shutdown() waits for the serve loop, so keep it off the UI thread.
        threading.Thread(target=lambda: (self.httpd.shutdown(), self.httpd.server_close()), daemon=True).start()


# ---------------------------------------------------------------------------------------------
# ngrok
# ---------------------------------------------------------------------------------------------

def find_ngrok():
    # A portable copy can carry its own ngrok.exe next to it.
    app_dir = Path(sys.executable if getattr(sys, "frozen", False) else __file__).resolve().parent
    beside = app_dir / "ngrok.exe"
    if beside.exists():
        return str(beside)
    return shutil.which("ngrok") or (LARAGON_NGROK if os.path.exists(LARAGON_NGROK) else None)


def ngrok_version(exe):
    try:
        out = subprocess.run([exe, "version"], capture_output=True, text=True, timeout=10, creationflags=NO_WINDOW)
        return out.stdout.strip() or out.stderr.strip()
    except Exception as e:  # noqa: BLE001
        return f"unavailable ({e})"


class NgrokSession:
    """One `ngrok http` agent process for one vhost. Each share runs its own agent, so they stop independently."""

    def __init__(self, exe, vhost, scheme, rewrite, post):
        self.vhost, self.scheme, self.rewrite, self.post = vhost, scheme, rewrite, post
        self.proxy = RewriteProxy(vhost, scheme) if rewrite else None
        if self.proxy:
            # The proxy sets the Host header and speaks http/https to Apache itself.
            upstream = [f"http://127.0.0.1:{self.proxy.port}"]
        else:
            upstream = ["80" if scheme == "http" else f"https://{vhost}:443", f"--host-header={vhost}"]
        self.cmd = [exe, "http", *upstream, "--log", "stdout", "--log-format", "json"]
        self.url = None
        self.web_addr = None
        self.last_error = ""
        self.stopping = False  # set by stop(), so the exit that follows isn't reported as a failure
        try:
            self.proc = subprocess.Popen(
                self.cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                text=True, encoding="utf-8", errors="replace", creationflags=NO_WINDOW,
            )
        except OSError:
            if self.proxy:
                self.proxy.stop()
            raise
        threading.Thread(target=self._read, daemon=True).start()
        threading.Thread(target=self._api_fallback, daemon=True).start()

    def _read(self):
        for line in self.proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                self.post("log", f"[{self.vhost}] {line}")
                if "ERR_NGROK" in line or line.upper().startswith("ERROR"):
                    self.last_error = line
                continue
            self._handle(rec)
        code = self.proc.wait()
        if self.proxy:
            self.proxy.stop()
        self.post("exited", (self, code))

    def _got_url(self, url):
        if self.url:
            return
        if self.proxy:
            self.proxy.rewriter.set_public(url)
        self.url = url
        self.post("url", (self, url))

    def _handle(self, rec):
        # Never surface anything token-like, even if a future ngrok version logs it.
        rec = {k: v for k, v in rec.items() if "token" not in k.lower()}
        lvl, msg = rec.pop("lvl", "info"), rec.pop("msg", "")
        rec.pop("t", None)
        if any(b in msg for b in BENIGN_NGROK_ERRORS):
            return
        if lvl in ("eror", "error", "crit"):
            self.last_error = f"{msg}: {rec['err']}" if rec.get("err") else msg
        if msg == "starting web service" and rec.get("addr"):
            self.web_addr = rec["addr"]
        url = rec.get("url")
        if isinstance(url, str) and url.startswith("https://"):
            self._got_url(url)
        extras = " ".join(f"{k}={v}" for k, v in rec.items() if k not in ("obj", "pg", "id") and v is not None)
        self.post("log", f"[{self.vhost}] [{lvl}] {msg} {extras}".rstrip())

    def _api_fallback(self):
        """If the log never names the URL, ask this agent's own inspection API (4040, 4041, ...)."""
        for _ in range(20):
            time.sleep(1)
            if self.url or self.proc.poll() is not None:
                return
            if not self.web_addr:
                continue
            try:
                with urllib.request.urlopen(f"http://{self.web_addr}/api/tunnels", timeout=3) as r:
                    tunnels = json.load(r).get("tunnels", [])
            except Exception:  # noqa: BLE001
                continue
            for t in tunnels:
                if str(t.get("public_url", "")).startswith("https://"):
                    self._got_url(t["public_url"])
                    return

    def stop(self):
        self.stopping = True
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()


# ---------------------------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------------------------

class App(tk.Tk):
    def __init__(self, sites_dir):
        super().__init__()
        self.title("Laragon -> ngrok")
        self.geometry("1000x680")
        self.minsize(760, 520)
        self.events = queue.Queue()
        self.vhosts = {}
        self.sessions = {}    # site -> NgrokSession
        self.pending = set()  # sites whose pre-share local check is still running
        self.ngrok = find_ngrok()

        self.sites_dir = tk.StringVar(value=sites_dir)
        self.filter = tk.StringVar()
        self.scheme = tk.StringVar(value="http")
        self.rewrite = tk.BooleanVar(value=True)
        self.public_url = tk.StringVar()
        self.status = tk.StringVar(value="Pick a vhost.")

        self._build()
        self.filter.trace_add("write", lambda *_: self._fill_tree())
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(100, self._pump)
        self.reload()
        threading.Thread(target=lambda: self.post("ngrok_version", ngrok_version(self.ngrok) if self.ngrok else "ngrok not found"),
                         daemon=True).start()

    # -- layout --------------------------------------------------------------------------------

    def _build(self):
        top = ttk.Frame(self, padding=(8, 8, 8, 0))
        top.pack(fill="x")
        ttk.Label(top, text="sites-enabled:").pack(side="left")
        ttk.Entry(top, textvariable=self.sites_dir).pack(side="left", fill="x", expand=True, padx=4)
        ttk.Button(top, text="Browse...", command=self._browse).pack(side="left")
        ttk.Button(top, text="Reload", command=self.reload).pack(side="left", padx=(4, 0))

        panes = ttk.PanedWindow(self, orient="horizontal")
        panes.pack(fill="both", expand=True, padx=8, pady=8)

        left = ttk.Frame(panes)
        frow = ttk.Frame(left)
        frow.pack(fill="x", pady=(0, 4))
        ttk.Label(frow, text="Filter:").pack(side="left")
        ttk.Entry(frow, textvariable=self.filter).pack(side="left", fill="x", expand=True, padx=4)
        cols = ("site", "ports", "local", "shared", "target")
        self.tree = ttk.Treeview(left, columns=cols, show="headings", selectmode="browse")
        for c, w in zip(cols, (170, 70, 80, 230, 200)):
            self.tree.heading(c, text=c.capitalize())
            self.tree.column(c, width=w, stretch=c == "target")
        sb = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="left", fill="y")
        self.tree.bind("<<TreeviewSelect>>", lambda _: self._on_select())
        self.tree.bind("<Double-1>", lambda _: self.check_local())
        panes.add(left, weight=3)

        right = ttk.Frame(panes, padding=(8, 0, 0, 0))
        self.sel_label = ttk.Label(right, text="No vhost selected", font=("Segoe UI", 12, "bold"))
        self.sel_label.pack(anchor="w")
        self.sel_detail = ttk.Label(right, text="", foreground="#666", wraplength=330, justify="left")
        self.sel_detail.pack(anchor="w", pady=(0, 6))

        up = ttk.LabelFrame(right, text="Upstream", padding=6)
        up.pack(fill="x")
        ttk.Radiobutton(up, text="HTTP  (ngrok http 80 --host-header=...)", variable=self.scheme, value="http").pack(anchor="w")
        ttk.Radiobutton(up, text="HTTPS (ngrok http https://<vhost>:443 ...)", variable=self.scheme, value="https").pack(anchor="w")
        ttk.Checkbutton(up, text="Rewrite links to <vhost> to the public URL (built-in proxy)",
                        variable=self.rewrite).pack(anchor="w", pady=(4, 0))

        btns = ttk.Frame(right)
        btns.pack(fill="x", pady=8)
        self.btn_check = ttk.Button(btns, text="Check locally", command=self.check_local)
        self.btn_share = ttk.Button(btns, text="Share via ngrok", command=self.share)
        self.btn_stop = ttk.Button(btns, text="Stop sharing", command=self.stop, state="disabled")
        self.btn_stop_all = ttk.Button(btns, text="Stop all", command=self.stop_all, state="disabled")
        for b in (self.btn_check, self.btn_share, self.btn_stop, self.btn_stop_all):
            b.pack(side="left", padx=(0, 4))

        urlf = ttk.LabelFrame(right, text="Public URL", padding=6)
        urlf.pack(fill="x")
        ttk.Entry(urlf, textvariable=self.public_url, state="readonly").pack(fill="x")
        ub = ttk.Frame(urlf)
        ub.pack(fill="x", pady=(4, 0))
        self.btn_copy = ttk.Button(ub, text="Copy", command=self._copy_url, state="disabled")
        self.btn_open = ttk.Button(ub, text="Open", command=lambda: webbrowser.open(self.public_url.get()), state="disabled")
        self.btn_verify = ttk.Button(ub, text="Verify again", command=self.verify, state="disabled")
        for b in (self.btn_copy, self.btn_open, self.btn_verify):
            b.pack(side="left", padx=(0, 4))

        ttk.Label(right, text="Log").pack(anchor="w", pady=(8, 0))
        logf = ttk.Frame(right)
        logf.pack(fill="both", expand=True)
        self.log = tk.Text(logf, height=12, wrap="word", state="disabled", font=("Consolas", 9))
        lsb = ttk.Scrollbar(logf, orient="vertical", command=self.log.yview)
        self.log.configure(yscrollcommand=lsb.set)
        self.log.pack(side="left", fill="both", expand=True)
        lsb.pack(side="left", fill="y")
        panes.add(right, weight=2)

        bar = ttk.Frame(self, padding=(8, 0, 8, 6))
        bar.pack(fill="x")
        ttk.Label(bar, textvariable=self.status).pack(side="left")
        self.ngrok_label = ttk.Label(bar, text="", foreground="#666")
        self.ngrok_label.pack(side="right")

    # -- plumbing ------------------------------------------------------------------------------

    def post(self, kind, payload=None):
        self.events.put((kind, payload))

    def _pump(self):
        try:
            while True:
                kind, payload = self.events.get_nowait()
                getattr(self, f"_ev_{kind}")(payload)
        except queue.Empty:
            pass
        self.after(100, self._pump)

    def _log(self, line):
        self.log.configure(state="normal")
        self.log.insert("end", line + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _selected(self):
        sel = self.tree.selection()
        return self.vhosts.get(sel[0]) if sel else None

    # -- vhost list ----------------------------------------------------------------------------

    def _browse(self):
        d = filedialog.askdirectory(initialdir=self.sites_dir.get())
        if d:
            self.sites_dir.set(d)
            self.reload()

    def reload(self):
        try:
            hosts = parse_sites(self.sites_dir.get())
        except OSError as e:
            messagebox.showerror("Can't read sites-enabled", str(e))
            return
        self.vhosts = {v.site: v for v in hosts}
        self._fill_tree()
        self.status.set(f"{len(hosts)} vhosts in {self.sites_dir.get()}")

    def _fill_tree(self):
        prev = self.tree.selection()
        local = {i: self.tree.set(i, "local") for i in self.tree.get_children()}
        self.tree.delete(*self.tree.get_children())
        needle = self.filter.get().strip().lower()
        for v in self.vhosts.values():
            if needle and needle not in v.site.lower():
                continue
            ports = ",".join(map(str, v.ports)) + (" (80->443)" if v.http_redirects else "")
            self.tree.insert("", "end", iid=v.site, values=(v.site, ports, local.get(v.site, ""), self._shared_text(v.site), v.target))
        if prev and self.tree.exists(prev[0]):
            self.tree.selection_set(prev[0])

    def _shared_text(self, site):
        s = self.sessions.get(site)
        return "" if not s else (s.url or "starting...")

    def _update_site(self, site):
        """Refresh one site's Shared cell, the panel and the button states after a share changes."""
        if self.tree.exists(site):
            self.tree.set(site, "shared", self._shared_text(site))
        self._refresh_panel()

    def _refresh_panel(self):
        v = self._selected()
        s = self.sessions.get(v.site) if v else None
        self.public_url.set(s.url or "" if s else "")
        busy = bool(v) and (v.site in self.pending or s is not None)
        self.btn_share.configure(state="disabled" if busy or not v else "normal")
        self.btn_stop.configure(state="normal" if s else "disabled")
        for b in (self.btn_copy, self.btn_open, self.btn_verify):
            b.configure(state="normal" if s and s.url else "disabled")
        self.btn_stop_all.configure(state="normal" if self.sessions else "disabled")

    def _on_select(self):
        v = self._selected()
        if not v:
            return
        self.sel_label.configure(text=v.site)
        self.sel_detail.configure(text=f"{v.conf}\n{v.target}")
        s = self.sessions.get(v.site)
        self.scheme.set(s.scheme if s else "https" if v.http_redirects or 80 not in v.ports else "http")
        if s:
            self.rewrite.set(s.rewrite)
        self._refresh_panel()

    # -- actions -------------------------------------------------------------------------------

    def check_local(self):
        v = self._selected()
        if not v:
            return
        scheme = self.scheme.get()
        self._log(f"> local check: {scheme}://127.0.0.1 with Host: {v.site}")

        def work():
            self.post("local", (v.site, scheme, probe(v.site, scheme, dial_host="127.0.0.1")))

        threading.Thread(target=work, daemon=True).start()

    def share(self):
        v = self._selected()
        if not v:
            messagebox.showinfo("Share", "Select a vhost first.")
            return
        if not self.ngrok:
            messagebox.showerror("ngrok not found", f"Put ngrok on PATH or install it at {LARAGON_NGROK}.")
            return
        if RISKY_NAME.search(v.site) and not messagebox.askyesno(
            "Public without auth",
            f"{v.site} looks like a database/admin tool.\n\nThe ngrok URL is public and has no auth. Share anyway?",
            icon="warning",
        ):
            return
        if v.site in self.sessions or v.site in self.pending:
            return

        scheme, rewrite = self.scheme.get(), self.rewrite.get()
        self.pending.add(v.site)
        self._log(f"> local check before sharing: {scheme}://127.0.0.1  Host: {v.site}")
        self.status.set(f"Checking {v.site} locally...")
        self._refresh_panel()

        def work():
            p = probe(v.site, scheme, dial_host="127.0.0.1")
            self.post("local", (v.site, scheme, p))
            self.post("start", (v.site, scheme, rewrite, p))

        threading.Thread(target=work, daemon=True).start()

    def _ev_start(self, payload):
        site, scheme, rewrite, local = payload
        self.pending.discard(site)
        if local.error and not messagebox.askyesno(
            "Local check failed", f"{site} doesn't answer locally:\n{local.error}\n\nStart ngrok anyway?"
        ):
            self.status.set(f"{site} not shared.")
            self._refresh_panel()
            return
        try:
            s = NgrokSession(self.ngrok, site, scheme, rewrite, self.post)
        except OSError as e:
            self._refresh_panel()
            messagebox.showerror("Couldn't start ngrok", str(e))
            return
        self.sessions[site] = s
        if s.proxy:
            self._log(f"> link-rewriting proxy 127.0.0.1:{s.proxy.port} -> {scheme}://{site} (Apache)")
        self._log("> " + " ".join(s.cmd))
        self.status.set(f"Starting ngrok for {site}...")
        self._update_site(site)

    def stop(self):
        v = self._selected()
        if v:
            self._stop_site(v.site)

    def stop_all(self):
        for site in list(self.sessions):
            self._stop_site(site)

    def _stop_site(self, site):
        s = self.sessions.pop(site, None)
        if not s:
            return
        self._log(f"> stopping ngrok for {site}")
        s.stop()
        self._update_site(site)
        self.status.set(f"Stopped sharing {site}. {len(self.sessions)} still shared.")

    def verify(self, s=None):
        if s is None:
            v = self._selected()
            s = self.sessions.get(v.site) if v else None
        if not (s and s.url):
            return
        url = s.url
        host = urlsplit(url).hostname
        self._log(f"> verifying {s.vhost}: {url}")

        def work():
            pub = probe(host, "https", headers={"ngrok-skip-browser-warning": "1"})
            loc = probe(s.vhost, s.scheme, dial_host="127.0.0.1")
            self.post("verified", (s, url, loc, pub))

        threading.Thread(target=work, daemon=True).start()

    def _copy_url(self):
        self.clipboard_clear()
        self.clipboard_append(self.public_url.get())
        self.status.set("URL copied.")

    def _on_close(self):
        for s in self.sessions.values():
            s.stop()
        self.destroy()

    # -- events from worker threads ------------------------------------------------------------

    def _ev_ngrok_version(self, text):
        self.ngrok_label.configure(text=f"{text}  ({self.ngrok or '-'})")

    def _ev_log(self, line):
        self._log(line)

    def _ev_local(self, payload):
        site, scheme, p = payload
        if self.tree.exists(site):
            self.tree.set(site, "local", f"{scheme} {p.status or 'ERR'}")
        self._log(f"  local {scheme}: {p.summary()}")
        if not p.error:
            self._log(f"  title: {p.title or '-'}   body: {snippet(p.body)!r}")
        self.status.set(f"{site}: local {p.summary()}")

    def _ev_url(self, payload):
        s, url = payload
        if self.sessions.get(s.vhost) is not s:
            return
        self._update_site(s.vhost)
        self.status.set(f"{s.vhost} is online at {url}")
        self.verify(s)

    def _ev_verified(self, payload):
        s, url, loc, pub = payload
        if self.sessions.get(s.vhost) is not s:
            return
        self._log(f"  {s.vhost} public: {pub.summary()}")
        if not pub.error:
            self._log(f"  title: {pub.title or '-'}   body: {snippet(pub.body)!r}")
        if pub.error:
            verdict = f"Public URL failed: {pub.error}"
        elif pub.ngrok_error:
            hint = " (ngrok can't reach Apache - wrong port/scheme or Apache stopped)" if "8012" in pub.ngrok_error else ""
            verdict = f"ngrok error page {pub.ngrok_error}{hint}"
        elif pub.status != loc.status:
            verdict = f"Mismatch: public {pub.status} vs local {loc.status or loc.error}"
        else:
            same_title = pub.title == loc.title
            verdict = f"OK: public {pub.status} matches local {loc.status}" + ("" if same_title else " (titles differ)")
        if pub.location and urlsplit(pub.location).hostname not in (None, urlsplit(url).hostname):
            verdict += f"  [redirects to {pub.location} - the app has its own base URL]"
        left = len(re.findall(r"(?://|\\/\\/)" + re.escape(s.vhost) + r"(?![\w.-])", pub.body))
        if left:
            fix = "rewritten only in text responses" if s.rewrite else "share again with link rewriting on"
            verdict += f"  [{left} link(s) to {s.vhost} on the page - {fix}]"
        self._log(f"  => {s.vhost}: {verdict}")
        self.status.set(f"{s.vhost}: {verdict}")

    def _ev_exited(self, payload):
        s, code = payload
        if s.stopping:  # our own Stop; Windows reports exit code 1 for a terminated process
            self._log(f"  ngrok for {s.vhost} stopped.")
            return
        msg = f"ngrok for {s.vhost} exited unexpectedly (code {code})" + (f": {s.last_error}" if s.last_error else "")
        self._log("  " + msg)
        if self.sessions.get(s.vhost) is s:
            del self.sessions[s.vhost]
            self._update_site(s.vhost)
        self.status.set(msg)
        messagebox.showerror("ngrok stopped", msg)


if __name__ == "__main__":
    App(sys.argv[1] if len(sys.argv) > 1 else DEFAULT_SITES_DIR).mainloop()
