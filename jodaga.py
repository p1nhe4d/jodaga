#!/usr/bin/env python3
"""
JODAGA - Joint Offensive Detection & Advanced Global Assessment
Advanced Recon Scanner v1.1

Changes vs v1.0:
  * URL normalization: parse_target() + build_url() -> no more
    "https://https://..." or "missing scheme" errors.
  * Async DNS subdomain enumeration (dns.asyncresolver + gather).
  * Vhost / Host-header fuzzing (-V) with auto-baseline and size/word
    filters, plus an /etc/hosts helper line for the vhosts that hit.
  * Web-app recon: authenticated session (cookie / header / form login),
    JS + endpoint crawler (-C), and API discovery (--api) for
    Swagger/OpenAPI/GraphQL.
  * Fixes: per-request UA rotation, ANSI-safe padding, 'except Exception',
    size in bytes, removed dead parameter, duplicate import.

Usage:
  python3 scanner.py -t target.htb -w list.txt
  python3 scanner.py -t 10.10.11.50 -w list.txt -V -d target.htb --vhost-wordlist subs.txt
  python3 scanner.py -t target.htb -w list.txt -C --api --cookie "session=abc123"
"""

import argparse
import asyncio
import json
import os
import random
import re
import sys
import uuid
from datetime import datetime
from urllib.parse import urljoin

import aiohttp

try:
    import dns.asyncresolver

    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    from playwright.async_api import async_playwright

    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

# ============ CONFIG ============
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/537.36",
]

MAX_CONCURRENT = 60
TIMEOUT = 10
SEM = asyncio.Semaphore(MAX_CONCURRENT)

# Auth injected into every request (set once from CLI args)
AUTH_HEADERS = {}


# ============ TERMINAL COLORS ============
class Colors:
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    RED = "\033[91m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    RESET = "\033[0m"


def color_status(status):
    if status == 200:
        return f"{Colors.GREEN}{status}{Colors.RESET}"
    if status == 403:
        return f"{Colors.YELLOW}{status}{Colors.RESET}"
    if status == 302:
        return f"{Colors.BLUE}{status}{Colors.RESET}"
    if status == 401:
        return f"{Colors.MAGENTA}{status}{Colors.RESET}"
    return f"{Colors.RED}{status}{Colors.RESET}"


def pad_status(status, width=8):
    """Colorize the status AFTER padding, so ANSI codes don't break alignment."""
    raw = str(status)
    padding = " " * max(0, width - len(raw))
    return color_status(status) + padding


def rand_headers(host_header=None):
    """Fresh header dict with a random UA per request, plus any auth headers."""
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    headers.update(AUTH_HEADERS)
    if host_header:
        headers["Host"] = host_header
    return headers


def print_banner():
    banner = """
    ╔══════════════════════════════════════════╗
    ║  JODAGA - Joint Offensive Detection      ║
    ║  & Advanced Global Assessment            ║
    ║   Advanced Recon Scanner v1.1            ║
    ╚══════════════════════════════════════════╝
"""
    print(banner)


# ============ URL NORMALIZATION ============
def parse_target(raw):
    """
    'https://target.htb:8443/admin' -> {'scheme':'https','host':'target.htb','port':8443}
    'target.htb'                     -> {'scheme':None,'host':'target.htb','port':None}
    '10.10.11.50:80'                 -> {'scheme':None,'host':'10.10.11.50','port':80}
    """
    raw = raw.strip()
    scheme = None
    if "://" in raw:
        scheme, raw = raw.split("://", 1)
        scheme = scheme.lower()
    raw = raw.split("/")[0]  # drop path/query

    host = raw
    port = None
    # host:port, but leave IPv6 alone (more than one colon)
    if raw.count(":") == 1:
        maybe_host, maybe_port = raw.split(":")
        if maybe_port.isdigit():
            host, port = maybe_host, int(maybe_port)

    return {"scheme": scheme, "host": host, "port": port}


def build_url(host, port=None, scheme=None):
    """Assemble a URL in a controlled way; https for 443/8443 if scheme omitted."""
    if scheme is None:
        scheme = "https" if port in (443, 8443) else "http"
    if port and port not in (80, 443):
        return f"{scheme}://{host}:{port}"
    return f"{scheme}://{host}"


async def resolve_ip(host):
    """Return the A record for host; None on failure (e.g. .htb without /etc/hosts)."""
    # Already an IP -> return as-is
    parts = host.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return host
    if not DNS_AVAILABLE:
        return None
    try:
        ans = await dns.asyncresolver.resolve(host, "A")
        return ans[0].to_text()
    except Exception:
        return None


# ============ AUTH / SESSION ============
def parse_kv_string(raw, pair_sep):
    """'a=1; b=2' or 'a=1&b=2' -> dict."""
    out = {}
    for chunk in raw.split(pair_sep):
        chunk = chunk.strip()
        if "=" in chunk:
            k, v = chunk.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def build_auth(args):
    """
    Populate AUTH_HEADERS and return (session_cookies dict) from CLI args.
    Supports: --cookie "a=1; b=2", -H "Name: value" (repeatable).
    """
    cookies = {}
    if args.cookie:
        cookies = parse_kv_string(args.cookie, ";")
    if args.header:
        for h in args.header:
            if ":" in h:
                name, value = h.split(":", 1)
                AUTH_HEADERS[name.strip()] = value.strip()

    if cookies:
        print(f"{Colors.CYAN}[*] Auth: {len(cookies)} cookie(s) loaded{Colors.RESET}")
    if AUTH_HEADERS:
        print(f"{Colors.CYAN}[*] Auth: {len(AUTH_HEADERS)} custom header(s) loaded{Colors.RESET}")
    return cookies


async def form_login(session, login_url, login_data):
    """
    POST form credentials and let the cookie jar capture the session.
    login_data is 'user=admin&pass=secret' (form-encoded).
    """
    data = parse_kv_string(login_data, "&")
    print(f"{Colors.BLUE}[*] Logging in at {login_url}...{Colors.RESET}")
    try:
        async with session.post(
            login_url, data=data, headers=rand_headers(),
            timeout=TIMEOUT, ssl=False, allow_redirects=True,
        ) as resp:
            # Report whatever cookies the server set
            cookie_names = [c.key for c in session.cookie_jar]
            if cookie_names:
                print(f"{Colors.GREEN}[+] Login response {resp.status}, "
                      f"session cookies: {', '.join(cookie_names)}{Colors.RESET}")
            else:
                print(f"{Colors.YELLOW}[!] Login response {resp.status}, "
                      f"no cookies set (check creds/field names){Colors.RESET}")
    except Exception as e:
        print(f"{Colors.RED}[-] Login failed: {type(e).__name__}: {e}{Colors.RESET}")


# ============ SUBDOMAIN ENUMERATION (async) ============
SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1",
    "webdisk", "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m",
    "imap", "test", "ns", "blog", "pop3", "dev", "www2", "admin", "forum",
    "news", "vpn", "ns3", "mail2", "new", "mysql", "old", "lists", "support",
    "mobile", "mx", "static", "docs", "beta", "shop", "sql", "secure", "demo",
    "cp", "calendar", "wiki", "web", "media", "email", "images", "img", "www1",
    "intranet", "help", "ns4", "download", "dns", "api", "app", "gateway",
    "apps", "data", "remote", "svn", "git", "crm", "panel", "portal",
    "monitor", "fw", "proxy", "webserver",
]


async def _resolve_sub(sub, domain):
    full = f"{sub}.{domain}"
    try:
        ans = await dns.asyncresolver.resolve(full, "A")
        return {"subdomain": full, "ip": ans[0].to_text()}
    except Exception:
        return None


async def enumerate_subdomains(domain):
    """Parallel DNS subdomain enumeration."""
    print(f"{Colors.BLUE}[*] Enumerating subdomains for {domain}...{Colors.RESET}")

    if not DNS_AVAILABLE:
        print(f"{Colors.YELLOW}[!] dnspython not installed, skipping.{Colors.RESET}")
        return []

    tasks = [_resolve_sub(sub, domain) for sub in SUBDOMAIN_WORDLIST]
    results = await asyncio.gather(*tasks)
    found = [r for r in results if r is not None]

    for item in found:
        print(f"  {Colors.GREEN}[+]{Colors.RESET} {item['subdomain']} -> {item['ip']}")
    print(f"{Colors.CYAN}[*] Found {len(found)} subdomains{Colors.RESET}")
    return found


# ============ VHOST / HOST-HEADER FUZZING ============
async def _vhost_probe(session, base_url, host_header):
    """Single vhost request; return (status, size_bytes, word_count) or None."""
    try:
        async with session.get(
            base_url,
            headers=rand_headers(host_header=host_header),
            timeout=TIMEOUT,
            ssl=False,
            allow_redirects=False,
        ) as resp:
            body = await resp.read()
            text = body.decode("utf-8", errors="ignore")
            return (resp.status, len(body), len(text.split()))
    except Exception:
        return None


async def vhost_fuzz(
    session, ip, port, domain, wordlist,
    filter_size=None, filter_words=None,
):
    """
    Send the same IP:port with different 'Host: <sub>.<domain>' and filter by
    deviation from the baseline (or explicit -fs/-fw filters).
    """
    scheme = "https" if port in (443, 8443) else "http"
    base_url = build_url(ip, port, scheme)

    print(f"\n{Colors.BLUE}[*] VHOST FUZZING -> {base_url} (domain: {domain}){Colors.RESET}")

    # 1) Baseline with a random vhost that definitely does not exist
    bogus = f"{uuid.uuid4().hex[:12]}.{domain}"
    baseline = await _vhost_probe(session, base_url, bogus)
    if baseline is None:
        print(f"{Colors.RED}[-] Baseline request failed, aborting vhost fuzz.{Colors.RESET}")
        return []
    b_status, b_size, b_words = baseline
    print(
        f"{Colors.CYAN}[*] Baseline: status={b_status} size={b_size}B "
        f"words={b_words}{Colors.RESET}"
    )

    # If the user gave no filters, auto-filter the baseline size/words
    auto_size = {b_size} if filter_size is None else set(filter_size)
    auto_words = {b_words} if filter_words is None else set(filter_words)

    # 2) Load wordlist
    if isinstance(wordlist, str):
        try:
            with open(wordlist) as f:
                subs = [
                    ln.strip() for ln in f
                    if ln.strip() and not ln.startswith("#")
                ]
        except FileNotFoundError:
            print(f"{Colors.RED}[-] Vhost wordlist not found: {wordlist}{Colors.RESET}")
            return []
    else:
        subs = wordlist

    # 3) Fuzz
    async def probe(sub):
        async with SEM:
            host_header = f"{sub}.{domain}"
            res = await _vhost_probe(session, base_url, host_header)
            if res is None:
                return None
            status, size, words = res
            # hit = deviates from baseline size AND word count
            if size in auto_size and words in auto_words:
                return None
            return {
                "vhost": host_header,
                "status": status,
                "size": size,
                "words": words,
            }

    results = await asyncio.gather(*[probe(s) for s in subs])
    hits = [r for r in results if r is not None]
    hits.sort(key=lambda x: x["size"])

    if hits:
        print(f"\n{Colors.BLUE}{'VHOST':<40} {'STATUS':<8} {'SIZE':<10} {'WORDS':<8}{Colors.RESET}")
        print(f"{Colors.BLUE}{'-' * 70}{Colors.RESET}")
        for h in hits:
            print(
                f"{h['vhost']:<40} {pad_status(h['status'])} "
                f"{str(h['size']) + 'B':<10} {h['words']:<8}"
            )
        # /etc/hosts helper
        print(f"\n{Colors.CYAN}[*] /etc/hosts line:{Colors.RESET}")
        names = " ".join(h["vhost"] for h in hits)
        print(f"  {ip}\t{names}")
    else:
        print(f"{Colors.YELLOW}[!] No vhost hits (all == baseline).{Colors.RESET}")

    print(f"{Colors.GREEN}[+] Vhost fuzz done: {len(hits)} hits{Colors.RESET}")
    return hits


# ============ JS + ENDPOINT CRAWLER ============
# Patterns to pull paths/endpoints out of JS bundles and HTML
JS_ENDPOINT_PATTERNS = [
    re.compile(r"""['"](/[a-zA-Z0-9_\-/.]{2,})['"]"""),
    re.compile(r"""(?:fetch|axios|\.get|\.post|\.put|\.patch|\.delete)\s*\(\s*['"]([^'"\s]+)['"]"""),
    re.compile(r"""url\s*[:=]\s*['"]([^'"\s]+)['"]"""),
]
STATIC_EXT = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".ico", ".woff",
              ".woff2", ".ttf", ".map")


def _looks_useful(path):
    """Filter out static assets and junk from extracted paths."""
    if not path or len(path) < 2:
        return False
    low = path.lower().split("?")[0]
    if low.endswith(STATIC_EXT):
        return False
    return True


async def _fetch_text(session, url):
    try:
        async with session.get(
            url, headers=rand_headers(), timeout=TIMEOUT, ssl=False
        ) as resp:
            return await resp.text(), resp.status
    except Exception:
        return None, None


def extract_from_html(html, base_url):
    """Pull links, forms and JS file URLs out of an HTML page."""
    links = set()
    js_files = set()

    for attr_val in re.findall(r"""(?:href|src|action)\s*=\s*['"]([^'"]+)['"]""", html, re.I):
        absolute = urljoin(base_url, attr_val)
        if absolute.lower().split("?")[0].endswith(".js"):
            js_files.add(absolute)
        elif _looks_useful(attr_val):
            links.add(absolute)

    forms = []
    for m in re.finditer(r"<form\b([^>]*)>(.*?)</form>", html, re.I | re.S):
        attrs, body = m.group(1), m.group(2)
        action = re.search(r"""action\s*=\s*['"]([^'"]*)['"]""", attrs, re.I)
        method = re.search(r"""method\s*=\s*['"]([^'"]*)['"]""", attrs, re.I)
        inputs = re.findall(r"""name\s*=\s*['"]([^'"]+)['"]""", body, re.I)
        forms.append({
            "action": urljoin(base_url, action.group(1)) if action else base_url,
            "method": (method.group(1).upper() if method else "GET"),
            "inputs": sorted(set(inputs)),
        })

    return links, js_files, forms


def extract_endpoints_from_js(js_text):
    """Regex endpoints/paths out of a JS bundle."""
    endpoints = set()
    for pat in JS_ENDPOINT_PATTERNS:
        for match in pat.findall(js_text):
            if _looks_useful(match) and ("/" in match):
                endpoints.add(match.split("?")[0])
    return endpoints


async def crawl(session, base_url, max_js=50):
    """Crawl the base page, follow its JS, and extract endpoints."""
    print(f"\n{Colors.BLUE}[*] CRAWLING {base_url} (links, forms, JS endpoints){Colors.RESET}")

    html, status = await _fetch_text(session, base_url)
    if html is None:
        print(f"{Colors.RED}[-] Could not fetch {base_url}{Colors.RESET}")
        return {"links": [], "forms": [], "js_files": [], "endpoints": []}

    links, js_files, forms = extract_from_html(html, base_url)

    js_list = list(js_files)[:max_js]
    endpoints = set()

    async def mine(js_url):
        async with SEM:
            text, _ = await _fetch_text(session, js_url)
            if text:
                return extract_endpoints_from_js(text)
            return set()

    if js_list:
        for ep_set in await asyncio.gather(*[mine(j) for j in js_list]):
            endpoints |= ep_set

    endpoints |= extract_endpoints_from_js(html)

    result = {
        "links": sorted(links),
        "forms": forms,
        "js_files": sorted(js_files),
        "endpoints": sorted(endpoints),
    }

    print(f"  {Colors.GREEN}[+]{Colors.RESET} {len(links)} links, "
          f"{len(forms)} forms, {len(js_files)} JS files, "
          f"{len(endpoints)} endpoints")
    if forms:
        for f in forms[:10]:
            print(f"    {Colors.CYAN}form{Colors.RESET} {f['method']} {f['action']} "
                  f"inputs={f['inputs']}")
    if endpoints:
        print(f"  {Colors.BLUE}[*] Endpoints from JS/HTML:{Colors.RESET}")
        for ep in sorted(endpoints)[:40]:
            print(f"    {ep}")
        if len(endpoints) > 40:
            print(f"    ... (+{len(endpoints) - 40} more in JSON output)")

    return result


# ============ API DISCOVERY (Swagger / OpenAPI / GraphQL) ============
API_PATHS = [
    "swagger.json", "openapi.json", "swagger/v1/swagger.json",
    "v2/api-docs", "v3/api-docs", "api-docs", "api/swagger.json",
    "swagger-ui.html", "swagger/index.html", "api/docs",
    ".well-known/openapi.json", ".well-known/security.txt",
    "graphql", "api/graphql", "graphiql", "v1/graphql",
]
INTROSPECTION_QUERY = {"query": "{__schema{queryType{name} types{name}}}"}


async def _probe_api_path(session, base_url, path):
    url = f"{base_url.rstrip('/')}/{path}"
    try:
        async with session.get(
            url, headers=rand_headers(), timeout=TIMEOUT, ssl=False
        ) as resp:
            if resp.status not in (200, 401, 403):
                return None
            body = (await resp.text())[:2000].lower()
            hint = None
            if any(k in body for k in ('"swagger"', '"openapi"', '"paths"')):
                hint = "openapi-spec"
            elif "swagger" in body or "redoc" in body:
                hint = "swagger-ui"
            elif "graphql" in body or "graphiql" in body:
                hint = "graphql-ui"
            return {"path": path, "url": url, "status": resp.status, "hint": hint}
    except Exception:
        return None


async def _graphql_introspection(session, base_url):
    """POST an introspection query and see if the schema leaks."""
    hits = []
    for gpath in ("graphql", "api/graphql", "v1/graphql", "query"):
        url = f"{base_url.rstrip('/')}/{gpath}"
        try:
            async with session.post(
                url, json=INTROSPECTION_QUERY, headers=rand_headers(),
                timeout=TIMEOUT, ssl=False,
            ) as resp:
                text = await resp.text()
                if "__schema" in text or '"types"' in text or "queryType" in text:
                    hits.append({"url": url, "status": resp.status,
                                 "note": "introspection enabled"})
        except Exception:
            pass
    return hits


async def discover_api(session, base_url):
    """Look for Swagger/OpenAPI specs and GraphQL (incl. introspection)."""
    print(f"\n{Colors.BLUE}[*] API DISCOVERY on {base_url}{Colors.RESET}")

    probes = await asyncio.gather(
        *[_probe_api_path(session, base_url, p) for p in API_PATHS]
    )
    found = [p for p in probes if p is not None]
    graphql = await _graphql_introspection(session, base_url)

    for item in found:
        tag = f" [{item['hint']}]" if item["hint"] else ""
        print(f"  {Colors.GREEN}[+]{Colors.RESET} {pad_status(item['status'])} "
              f"{item['url']}{tag}")
    for g in graphql:
        print(f"  {Colors.MAGENTA}[!]{Colors.RESET} GraphQL introspection: "
              f"{g['url']} ({g['status']})")

    if not found and not graphql:
        print(f"{Colors.YELLOW}[!] No API docs / GraphQL endpoints found.{Colors.RESET}")

    return {"specs": found, "graphql": graphql}


# ============ PORT SCAN ============
async def port_scan_python(target, ports="1-1000"):
    """Port scan via Python sockets."""
    print(f"{Colors.BLUE}[*] Scanning {target} (ports: {ports}){Colors.RESET}")

    if "-" in ports:
        start, end = ports.split("-")
        port_list = range(int(start), int(end) + 1)
    else:
        port_list = [int(p.strip()) for p in ports.split(",")]

    sem = asyncio.Semaphore(200)

    async def check_port(port):
        async with sem:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target, port), timeout=1.5
                )
                writer.close()
                await writer.wait_closed()
                return {
                    "port": port,
                    "service": "unknown",
                    "protocol": "tcp",
                    "state": "open",
                }
            except Exception:
                return None

    results = await asyncio.gather(*[check_port(p) for p in port_list])
    open_ports = [r for r in results if r is not None]

    print(f"{Colors.GREEN}[+] Found {len(open_ports)} open ports{Colors.RESET}")
    return open_ports


# ============ TECH STACK DETECTION ============
async def detect_tech(session, base_url):
    """Detect technologies from the response."""
    try:
        async with session.get(
            base_url, headers=rand_headers(), timeout=TIMEOUT, ssl=False
        ) as response:
            tech = {
                "server": response.headers.get("Server", "unknown"),
                "powered_by": response.headers.get("X-Powered-By", "unknown"),
                "cms": "unknown",
                "framework": "unknown",
                "cdn": "unknown",
            }

            html = await response.text()
            if "wp-content" in html or "wp-includes" in html:
                tech["cms"] = "WordPress"
            elif "Drupal" in html or "drupal" in html:
                tech["cms"] = "Drupal"
            elif "Joomla" in html:
                tech["cms"] = "Joomla"
            elif "laravel" in html or "Laravel" in html:
                tech["framework"] = "Laravel"

            if "CF-RAY" in response.headers:
                tech["cdn"] = "Cloudflare"
            elif "x-amz-request-id" in response.headers:
                tech["cdn"] = "AWS CloudFront"
            elif (
                "x-served-by" in response.headers
                and "fastly" in response.headers["x-served-by"].lower()
            ):
                tech["cdn"] = "Fastly"

            return tech
    except Exception:
        return None


# ============ HEADER CHECK ============
async def get_headers(session, base_url):
    """Check security headers."""
    try:
        async with session.get(
            base_url, headers=rand_headers(), timeout=TIMEOUT, ssl=False
        ) as response:
            headers = response.headers
            critical = [
                "Content-Security-Policy",
                "Strict-Transport-Security",
                "X-Frame-Options",
                "X-Content-Type-Options",
                "Referrer-Policy",
                "Permissions-Policy",
            ]
            header_res = []
            print(f"\n{Colors.BLUE}[*] HEADERS FOR {base_url}{Colors.RESET}")
            for h in critical:
                if h in headers:
                    print(f"  {Colors.GREEN}[+]{Colors.RESET} {h}: {headers.get(h)}")
                    header_res.append(
                        {"header": h, "value": headers.get(h), "status": "implemented"}
                    )
                else:
                    print(f"  {Colors.RED}[-]{Colors.RESET} {h}: MISSING")
                    header_res.append({"header": h, "value": None, "status": "missing"})
            return header_res
    except Exception as e:
        print(f"{Colors.RED}[-] Error fetching headers: {type(e).__name__}: {e}{Colors.RESET}")
        return None


# ============ PATH CHECK ============
async def check_path(session, url, path):
    """Check a single path (with semaphore)."""
    async with SEM:
        try:
            full_url = f"{url.rstrip('/')}/{path}"
            async with session.get(
                full_url, headers=rand_headers(), timeout=TIMEOUT, ssl=False
            ) as response:
                if response.status in [200, 403, 302, 401]:
                    content_length = response.headers.get("Content-Length")
                    try:
                        size = int(content_length)
                        size_str = f"{size}B"
                    except (TypeError, ValueError):
                        size_str = ""
                    return {
                        "path": path,
                        "status": response.status,
                        "size": size_str,
                        "url": full_url,
                    }
        except Exception:
            pass
    return None


# ============ FILE SCANNER ============
async def find_files(session, url, wordlist):
    """Main file/directory scanner."""
    try:
        if isinstance(wordlist, str):
            with open(wordlist, "r") as f:
                lines = [
                    line.strip()
                    for line in f.readlines()
                    if line.strip() and not line.startswith("#")
                ]
        else:
            lines = wordlist

        if not lines:
            print(f"{Colors.RED}[-] No valid paths found!{Colors.RESET}")
            return []

        print(
            f"\n{Colors.BLUE}[*] Scanning {len(lines)} paths with "
            f"{MAX_CONCURRENT} parallel requests...{Colors.RESET}\n"
        )

        tasks = [check_path(session, url, line) for line in lines]
        start_time = datetime.now()
        results = await asyncio.gather(*tasks)
        elapsed = (datetime.now() - start_time).total_seconds()

        found = [r for r in results if r is not None]
        found.sort(key=lambda x: x["status"])

        print(f"{Colors.BLUE}{'PATH':<45} {'STATUS':<8} {'SIZE':<10}{Colors.RESET}")
        print(f"{Colors.BLUE}{'-' * 65}{Colors.RESET}")
        for item in found:
            print(f"{item['path']:<45} {pad_status(item['status'])} {item['size']:<10}")

        print(f"\n{Colors.GREEN}[+] Found {len(found)} paths in {elapsed:.2f}s{Colors.RESET}")
        return found

    except FileNotFoundError:
        print(f"{Colors.RED}[-] File not found: {wordlist}{Colors.RESET}")
        return []
    except Exception as e:
        print(f"{Colors.RED}[-] Error: {e}{Colors.RESET}")
        return []


# ============ SCREENSHOTS ============
async def take_screenshot(url, output_dir="screenshots"):
    if not PLAYWRIGHT_AVAILABLE:
        print("Playwright not installed")
        return None

    os.makedirs(output_dir, exist_ok=True)
    filename = (
        url.replace("https://", "")
        .replace("http://", "")
        .replace("/", "_")
        .replace(":", "_")
    )
    filepath = f"{output_dir}/{filename}.png"

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True, args=["--no-sandbox"])
            page = await browser.new_page()
            await page.goto(url, timeout=15000, wait_until="load")
            await page.screenshot(path=filepath, full_page=True)
            await browser.close()
            print(f"[+] Screenshot saved: {filepath}")
            return filepath
    except Exception as e:
        print(f"[-] Screenshot failed: {e}")
        return None


# ============ SAVE RESULTS ============
def save_json(results, filename):
    with open(filename, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"{Colors.GREEN}[+] Results saved to {filename}{Colors.RESET}")


# ============ SCAN TARGET ============
async def scan_target(target, wordlist, args, session_cookies):
    """Scan a single target."""
    print(f"\n{Colors.CYAN}{'=' * 70}{Colors.RESET}")
    print(f"{Colors.CYAN}[*] SCANNING: {target}{Colors.RESET}")
    if args.proxy:
        print(f"{Colors.YELLOW}[*] Proxy: {args.proxy}{Colors.RESET}")
    print(f"{Colors.CYAN}{'=' * 70}{Colors.RESET}")

    # --- Normalize once, up top ---
    parsed = parse_target(target)
    host = parsed["host"]
    scheme = parsed["scheme"]
    port = parsed["port"]
    base_url = build_url(host, port, scheme)
    ip = await resolve_ip(host)

    print(f"{Colors.CYAN}[*] host={host} ip={ip or 'n/a'} base_url={base_url}{Colors.RESET}")

    scan_results = {
        "target": target,
        "host": host,
        "ip": ip,
        "base_url": base_url,
        "timestamp": datetime.now().isoformat(),
        "subdomains": [],
        "ports": [],
        "tech_stack": {},
        "headers": [],
        "paths": [],
        "vhosts": [],
        "crawl": {},
        "api": {},
        "screenshots": [],
    }

    connector = aiohttp.TCPConnector(ssl=False)

    async with aiohttp.ClientSession(
        connector=connector, proxy=args.proxy, cookies=session_cookies or None
    ) as session:
        if args.login_url and args.login_data:
            await form_login(session, args.login_url, args.login_data)

        is_ip = ip == host
        if not args.no_subdomains and not is_ip:
            scan_results["subdomains"] = await enumerate_subdomains(host)

        tech = await detect_tech(session, base_url)
        if tech:
            scan_results["tech_stack"] = tech
            print(f"{Colors.BLUE}[*] Tech stack:{Colors.RESET}")
            for key, value in tech.items():
                print(f"  {key}: {value}")

        ports_result = await port_scan_python(host, args.ports)
        scan_results["ports"] = ports_result
        for p in ports_result:
            print(f"  Port {p['port']}/{p['protocol']}: {p['service']}")

        headers_result = await get_headers(session, base_url)
        if headers_result:
            scan_results["headers"] = headers_result

        web_ports = [p for p in ports_result if p["port"] in [80, 443, 8080, 8443]]
        all_paths = []

        if web_ports:
            for wp in web_ports:
                proto = "https" if wp["port"] in [443, 8443] else "http"
                web_url = build_url(host, wp["port"], proto)
                print(f"{Colors.BLUE}[*] Scanning paths on {web_url}{Colors.RESET}")
                paths_result = await find_files(session, web_url, wordlist)
                for path in paths_result:
                    path["port"] = wp["port"]
                all_paths.extend(paths_result)
        else:
            print(f"{Colors.YELLOW}[!] No web ports found, trying base_url...{Colors.RESET}")
            all_paths = await find_files(session, base_url, wordlist)

        scan_results["paths"] = all_paths

        if args.crawl:
            scan_results["crawl"] = await crawl(session, base_url)

        if args.api:
            scan_results["api"] = await discover_api(session, base_url)

        if args.vhost:
            domain = args.domain or host
            vhost_wl = args.vhost_wordlist or SUBDOMAIN_WORDLIST
            vhost_ip = ip or host
            vhost_port = web_ports[0]["port"] if web_ports else (port or 80)
            fs = [int(x) for x in args.vhost_fs.split(",")] if args.vhost_fs else None
            fw = [int(x) for x in args.vhost_fw.split(",")] if args.vhost_fw else None
            scan_results["vhosts"] = await vhost_fuzz(
                session, vhost_ip, vhost_port, domain, vhost_wl,
                filter_size=fs, filter_words=fw,
            )

        if args.screenshots and all_paths:
            print(f"{Colors.BLUE}[*] Taking screenshots...{Colors.RESET}")
            for path in all_paths:
                if path["status"] == 200:
                    shot = await take_screenshot(
                        path["url"], output_dir=f"{args.screenshot_dir}/{host}"
                    )
                    if shot:
                        path["screenshot"] = shot
                        scan_results["screenshots"].append(shot)

    return scan_results


# ============ MAIN ============
async def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="JODAGA - Advanced Recon Scanner v1.1",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 scanner.py -t target.htb -w list.txt
  python3 scanner.py -t target.htb -w list.txt -p 80,443,8080 -o results.json
  python3 scanner.py -t 10.10.11.50 -w list.txt -V -d target.htb --vhost-wordlist subs.txt
  python3 scanner.py -t target.htb -w list.txt -C --api --cookie "session=abc123"
  python3 scanner.py -t target.htb -w list.txt -C --login-url https://target.htb/login --login-data "user=admin&pass=pw"
  python3 scanner.py -t target.htb -w list.txt --proxy http://127.0.0.1:8080
  python3 scanner.py -t target.htb -w list.txt --screenshots
        """,
    )

    parser.add_argument("-t", "--target", required=True,
                        help="Target domain/IP or a file with a list of targets (.txt)")
    parser.add_argument("-w", "--wordlist", default="list.txt",
                        help="Wordlist for path scanning (default: list.txt)")
    parser.add_argument("-p", "--ports", default="1-1000",
                        help="Port range (default: 1-1000)")
    parser.add_argument("-o", "--output", default="results.json",
                        help="Output JSON (default: results.json)")
    parser.add_argument("--proxy", default=None,
                        help="Proxy URL (e.g. http://127.0.0.1:8080 for Burp)")
    parser.add_argument("--screenshots", action="store_true",
                        help="Screenshot found pages (needs playwright)")
    parser.add_argument("--screenshot-dir", default="screenshots",
                        help="Folder for screenshots (default: screenshots)")
    parser.add_argument("--no-subdomains", action="store_true",
                        help="Skip subdomain enumeration")

    # --- Vhost mode ---
    parser.add_argument("-V", "--vhost", action="store_true",
                        help="Enable vhost / Host-header fuzzing")
    parser.add_argument("-d", "--domain", default=None,
                        help="Base domain for the Host header (e.g. target.htb)")
    parser.add_argument("--vhost-wordlist", default=None,
                        help="Wordlist for vhost (default: built-in subdomain list)")
    parser.add_argument("--vhost-fs", default=None,
                        help="Filter vhost by size (bytes, comma-sep)")
    parser.add_argument("--vhost-fw", default=None,
                        help="Filter vhost by word count (comma-sep)")

    # --- Web-app recon ---
    parser.add_argument("-C", "--crawl", action="store_true",
                        help="Crawl links/forms and mine endpoints from JS")
    parser.add_argument("--api", action="store_true",
                        help="API discovery: Swagger/OpenAPI + GraphQL introspection")

    # --- Auth ---
    parser.add_argument("--cookie", default=None,
                        help='Raw cookie string, e.g. "session=abc; role=user"')
    parser.add_argument("-H", "--header", action="append", default=None,
                        help='Custom header (repeatable), e.g. -H "Authorization: Bearer X"')
    parser.add_argument("--login-url", default=None,
                        help="URL to POST credentials to (form login)")
    parser.add_argument("--login-data", default=None,
                        help='Form login data, e.g. "user=admin&pass=secret"')

    args = parser.parse_args()

    if args.screenshots and not PLAYWRIGHT_AVAILABLE:
        print(f"{Colors.YELLOW}[!] Playwright not installed. Screenshots off.{Colors.RESET}")
        args.screenshots = False

    session_cookies = build_auth(args)

    if args.target.endswith(".txt"):
        with open(args.target, "r") as f:
            targets = [
                line.strip() for line in f if line.strip() and not line.startswith("#")
            ]
    else:
        targets = [args.target]

    print(f"{Colors.CYAN}{'=' * 70}{Colors.RESET}")
    print(f"{Colors.CYAN}[*] JODAGA Recon Scanner v1.1{Colors.RESET}")
    print(f"{Colors.CYAN}[*] Targets: {len(targets)} | Wordlist: {args.wordlist} "
          f"| Ports: {args.ports}{Colors.RESET}")
    if args.vhost:
        print(f"{Colors.CYAN}[*] Vhost fuzzing: ON (domain: {args.domain or 'auto'}){Colors.RESET}")
    if args.crawl:
        print(f"{Colors.CYAN}[*] Crawl + JS endpoints: ON{Colors.RESET}")
    if args.api:
        print(f"{Colors.CYAN}[*] API discovery: ON{Colors.RESET}")
    print(f"{Colors.CYAN}{'=' * 70}{Colors.RESET}")

    sem = asyncio.Semaphore(3)

    async def scan_with_semaphore(target):
        async with sem:
            return await scan_target(target, args.wordlist, args, session_cookies)

    all_results = await asyncio.gather(*[scan_with_semaphore(t) for t in targets])

    final_results = {
        "scanner": "JODAGA",
        "version": "1.1",
        "timestamp": datetime.now().isoformat(),
        "total_targets": len(targets),
        "results": all_results,
    }

    save_json(final_results, args.output)

    print(f"\n{Colors.CYAN}{'=' * 70}{Colors.RESET}")
    print(f"{Colors.GREEN}[+] SCAN COMPLETE!{Colors.RESET}")
    print(f"{Colors.CYAN}[*] Summary:{Colors.RESET}")
    for i, result in enumerate(all_results):
        crawl_eps = len(result.get("crawl", {}).get("endpoints", []))
        api_specs = len(result.get("api", {}).get("specs", []))
        print(
            f"  {i + 1}. {result['target']}: "
            f"{len(result['paths'])} paths, {len(result['ports'])} ports, "
            f"{len(result['subdomains'])} subs, {len(result['vhosts'])} vhosts, "
            f"{crawl_eps} js-endpoints, {api_specs} api-specs"
        )
    print(f"{Colors.CYAN}{'=' * 70}{Colors.RESET}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[-] Scan interrupted by user{Colors.RESET}")
        sys.exit(0)
