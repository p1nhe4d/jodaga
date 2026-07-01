#!/usr/bin/env python3
"""
JODAGA - Joint Offensive Detection & Advanced Global Assessment
Advanced Recon Scanner v1.0
Usage: python3 scanner.py -t target.org -w lista.txt -o results.json --screenshot
"""

import argparse
import asyncio
import json
import os
import random
import sys
from datetime import datetime

import aiohttp
import dns.resolver

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


def print_banner():
    banner = """
    ╔══════════════════════════════════════════╗
    ║  JODAGA - Joint Offensive Detection      ║
    ║  & Advanced Global Assessment            ║
    ║   Advanced Recon Scanner v1.0            ║
    ╚══════════════════════════════════════════╝
"""
    print(banner)


# ============ SUBDOMAIN ENUMERATION ============
SUBDOMAIN_WORDLIST = [
    "www",
    "mail",
    "ftp",
    "localhost",
    "webmail",
    "smtp",
    "pop",
    "ns1",
    "webdisk",
    "ns2",
    "cpanel",
    "whm",
    "autodiscover",
    "autoconfig",
    "m",
    "imap",
    "test",
    "ns",
    "blog",
    "pop3",
    "dev",
    "www2",
    "admin",
    "forum",
    "news",
    "vpn",
    "ns3",
    "mail2",
    "new",
    "mysql",
    "old",
    "lists",
    "support",
    "mobile",
    "mx",
    "static",
    "docs",
    "beta",
    "shop",
    "sql",
    "secure",
    "demo",
    "cp",
    "calendar",
    "wiki",
    "web",
    "media",
    "email",
    "images",
    "img",
    "www1",
    "intranet",
    "help",
    "ns4",
    "download",
    "dns",
    "api",
    "app",
    "gateway",
    "apps",
    "data",
    "remote",
    "svn",
    "git",
    "crm",
    "panel",
    "portal",
    "monitor",
    "fw",
    "proxy",
    "webserver",
]


async def enumerate_subdomains(domain):
    """Subdomain enumeration using DNS"""
    print(f"{Colors.BLUE}[*] Enumerating subdomains for {domain}...{Colors.RESET}")

    found_subdomains = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 2

    for sub in SUBDOMAIN_WORDLIST:
        full = f"{sub}.{domain}"
        try:
            answers = resolver.resolve(full, "A")
            ip = answers[0].to_text()
            print(f"  {Colors.GREEN}[+]{Colors.RESET} {full} -> {ip}")
            found_subdomains.append({"subdomain": full, "ip": ip})
        except:
            pass

    print(f"{Colors.CYAN}[*] Found {len(found_subdomains)} subdomains{Colors.RESET}")
    return found_subdomains


# ============ PORT SCAN ============
async def port_scan_python(target, ports="1-1000"):
    """Port scan using Python sockets"""
    print(f"{Colors.BLUE}[*] Scanning {target} (ports: {ports}){Colors.RESET}")

    if "-" in ports:
        start, end = ports.split("-")
        port_list = range(int(start), int(end) + 1)
    else:
        port_list = [int(p.strip()) for p in ports.split(",")]

    open_ports = []
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
            except:
                return None

    tasks = [check_port(port) for port in port_list]
    results = await asyncio.gather(*tasks)
    open_ports = [r for r in results if r is not None]

    print(f"{Colors.GREEN}[+] Found {len(open_ports)} open ports{Colors.RESET}")
    return open_ports


# ============ TECH STACK DETECTION ============
async def detect_tech(session, url):
    """Detect technologies from server response"""
    try:
        async with session.get(url, timeout=TIMEOUT, ssl=False) as response:
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
    except:
        return None


# ============ HEADER CHECK ============
async def get_headers(session, url):
    """Check security headers"""
    try:
        async with session.get(url, timeout=TIMEOUT, ssl=False) as response:
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
            print(f"\n{Colors.BLUE}[*] HEADERS FOR {url}{Colors.RESET}")
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
        print(
            f"{Colors.RED}[-] Error fetching headers: {type(e).__name__}: {e}{Colors.RESET}"
        )
        return None


# ============ PATH CHECK ============
async def check_path(session, url, path):
    """Check a single path with semaphore"""
    async with SEM:
        try:
            full_url = f"{url.rstrip('/')}/{path}"
            async with session.get(full_url, timeout=TIMEOUT) as response:
                if response.status in [200, 403, 302, 401]:
                    content_length = response.headers.get("Content-Length", 0)
                    try:
                        size = int(content_length) // 1024
                        size_str = f"{size}KB" if size > 0 else ""
                    except:
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
async def find_files(session, url, ext_file, wordlist):
    """Main file/directory scanner"""
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
            f"\n{Colors.BLUE}[*] Scanning {len(lines)} paths with {MAX_CONCURRENT} parallel requests...{Colors.RESET}\n"
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
            status_colored = color_status(item["status"])
            print(f"{item['path']:<45} {status_colored:<8} {item['size']:<10}")

        print(
            f"\n{Colors.GREEN}[+] Found {len(found)} paths in {elapsed:.2f}s{Colors.RESET}"
        )
        return found

    except FileNotFoundError:
        print(f"{Colors.RED}[-] File not found: {wordlist}{Colors.RESET}")
        return []
    except Exception as e:
        print(f"{Colors.RED}[-] Error: {e}{Colors.RESET}")
        return []


# ============ SCREENSHOTS ============
async def take_screenshot(url, output_dir="screenshots"):
    try:
        from playwright.async_api import async_playwright
    except ImportError:
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
    """Save results to JSON"""
    with open(filename, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"{Colors.GREEN}[+] Results saved to {filename}{Colors.RESET}")


# ============ SCAN TARGET ============
async def scan_target(
    target,
    wordlist,
    ports="1-500",
    output="results.json",
    proxy=None,
    screenshots=False,
    screenshot_dir="screenshots",
):
    """Scan a single target"""
    print(f"\n{Colors.CYAN}{'=' * 70}{Colors.RESET}")
    print(f"{Colors.CYAN}[*] SCANNING: {target}{Colors.RESET}")
    if proxy:
        print(f"{Colors.YELLOW}[*] Proxy: {proxy}{Colors.RESET}")
    print(f"{Colors.CYAN}{'=' * 70}{Colors.RESET}")

    domain = target.replace("https://", "").replace("http://", "").split("/")[0]

    scan_results = {
        "target": target,
        "domain": domain,
        "timestamp": datetime.now().isoformat(),
        "subdomains": [],
        "ports": [],
        "tech_stack": {},
        "headers": [],
        "paths": [],
        "screenshots": [],
    }

    session_headers = {"User-Agent": random.choice(USER_AGENTS)}
    connector = aiohttp.TCPConnector(ssl=False)

    async with aiohttp.ClientSession(
        headers=session_headers, connector=connector, proxy=proxy
    ) as session:
        # 1. Subdomains
        subdomains = await enumerate_subdomains(domain)
        scan_results["subdomains"] = subdomains

        # 2. Tech stack
        tech = await detect_tech(session, target)
        if tech:
            scan_results["tech_stack"] = tech
            print(f"{Colors.BLUE}[*] Tech stack:{Colors.RESET}")
            for key, value in tech.items():
                print(f"  {key}: {value}")

        # 3. Port scan
        ports_result = await port_scan_python(domain, ports)
        scan_results["ports"] = ports_result
        if ports_result:
            print(f"{Colors.BLUE}[*] Open ports:{Colors.RESET}")
            for p in ports_result:
                print(f"  Port {p['port']}/{p['protocol']}: {p['service']}")

        # 4. Headers
        headers_result = await get_headers(session, target)
        if headers_result:
            scan_results["headers"] = headers_result

        # 5. Path scan
        web_ports = [p for p in ports_result if p["port"] in [80, 443, 8080, 8443]]
        all_paths = []

        if web_ports:
            for wp in web_ports:
                proto = "https" if wp["port"] in [443, 8443] else "http"
                web_url = f"{proto}://{domain}:{wp['port']}"
                print(f"{Colors.BLUE}[*] Scanning paths on {web_url}{Colors.RESET}")
                paths_result = await find_files(session, web_url, None, wordlist)
                if paths_result:
                    for path in paths_result:
                        path["port"] = wp["port"]
                    all_paths.extend(paths_result)
        else:
            print(
                f"{Colors.YELLOW}[!] No web ports found, trying defaults...{Colors.RESET}"
            )
            for proto in ["https", "http"]:
                url = f"{proto}://{domain}"
                print(f"{Colors.BLUE}[*] Trying {url}{Colors.RESET}")
                paths_result = await find_files(session, url, None, wordlist)
                if paths_result:
                    all_paths = paths_result
                    break

        scan_results["paths"] = all_paths

        # 6. Screenshots
        if screenshots and all_paths:
            print(f"{Colors.BLUE}[*] Taking screenshots...{Colors.RESET}")
            for path in all_paths:
                if path["status"] == 200:
                    screenshot_path = await take_screenshot(
                        path["url"], output_dir=f"{screenshot_dir}/{domain}"
                    )
                    if screenshot_path:
                        path["screenshot"] = screenshot_path
                        scan_results["screenshots"].append(screenshot_path)

    return scan_results


# ============ MAIN ============
async def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="JODAGA - Advanced Recon Scanner v1.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 scanner.py -t target.org -w lista.txt
  python3 scanner.py -t target.org -w lista.txt -p 80,443,8080 -o results.json
  python3 scanner.py -t targets.txt -w lista.txt -o scan_results.json
  python3 scanner.py -t target.org -w lista.txt --proxy http://127.0.0.1:8080
  python3 scanner.py -t target.org -w lista.txt --screenshots
        """,
    )

    parser.add_argument(
        "-t",
        "--target",
        required=True,
        help="Target domain or file with list of targets",
    )
    parser.add_argument(
        "-w",
        "--wordlist",
        default="list.txt",
        help="Wordlist file for path scanning (default: list.txt)",
    )
    parser.add_argument(
        "-p",
        "--ports",
        default="1-1000",
        help="Port range for scanning (default: 1-1000)",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="results.json",
        help="Output JSON file (default: results.json)",
    )
    parser.add_argument(
        "--proxy", default=None, help="Proxy URL (e.g., http://127.0.0.1:8080 for Burp)"
    )
    parser.add_argument(
        "--screenshots",
        action="store_true",
        help="Take screenshots of found pages (requires playwright)",
    )
    parser.add_argument(
        "--screenshot-dir",
        default="screenshots",
        help="Directory for screenshots (default: screenshots)",
    )
    parser.add_argument(
        "--no-subdomains", action="store_true", help="Skip subdomain enumeration"
    )

    args = parser.parse_args()

    if args.screenshots and not PLAYWRIGHT_AVAILABLE:
        print(
            f"{Colors.YELLOW}[!] Playwright not installed. Screenshots disabled.{Colors.RESET}"
        )
        args.screenshots = False
    # Load targets
    if args.target.endswith(".txt"):
        with open(args.target, "r") as f:
            targets = [
                line.strip() for line in f if line.strip() and not line.startswith("#")
            ]
    else:
        targets = [args.target]

    print(f"{Colors.CYAN}{'=' * 70}{Colors.RESET}")
    print(f"{Colors.CYAN}[*] JODAGA Recon Scanner{Colors.RESET}")
    print(f"{Colors.CYAN}[*] Targets: {len(targets)}{Colors.RESET}")
    print(f"{Colors.CYAN}[*] Wordlist: {args.wordlist}{Colors.RESET}")
    print(f"{Colors.CYAN}[*] Ports: {args.ports}{Colors.RESET}")
    print(f"{Colors.CYAN}[*] Output: {args.output}{Colors.RESET}")
    if args.proxy:
        print(f"{Colors.CYAN}[*] Proxy: {args.proxy}{Colors.RESET}")
    if args.screenshots:
        print(f"{Colors.CYAN}[*] Screenshots: enabled{Colors.RESET}")
    print(f"{Colors.CYAN}{'=' * 70}{Colors.RESET}")

    all_results = []
    sem = asyncio.Semaphore(3)

    async def scan_with_semaphore(target):
        async with sem:
            return await scan_target(
                target,
                args.wordlist,
                args.ports,
                args.output,
                args.proxy,
                args.screenshots,
                args.screenshot_dir,
            )

    tasks = [scan_with_semaphore(t) for t in targets]
    all_results = await asyncio.gather(*tasks)

    final_results = {
        "scanner": "JODAGA",
        "version": "1.0",
        "timestamp": datetime.now().isoformat(),
        "total_targets": len(targets),
        "results": all_results,
    }

    save_json(final_results, args.output)

    print(f"\n{Colors.CYAN}{'=' * 70}{Colors.RESET}")
    print(f"{Colors.GREEN}[+] SCAN COMPLETE!{Colors.RESET}")
    print(f"{Colors.CYAN}[*] Summary:{Colors.RESET}")
    for i, result in enumerate(all_results):
        target = result["target"]
        paths = len(result["paths"])
        ports = len(result["ports"])
        subs = len(result["subdomains"])
        print(f"  {i + 1}. {target}: {paths} paths, {ports} ports, {subs} subdomains")
    print(f"{Colors.CYAN}{'=' * 70}{Colors.RESET}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[-] Scan interrupted by user{Colors.RESET}")
        sys.exit(0)
