import asyncio
import random
from datetime import datetime

import aiohttp
import requests

# ============ CONFIG ============
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/537.36",
]

MAX_CONCURRENT = 60
TIMEOUT = 5
OUTPUT_FILE = "routes.txt"
SEM = asyncio.Semaphore(MAX_CONCURRENT)


# ============ TERMINAL COLORS ============
class Colors:
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    RED = "\033[91m"
    MAGENTA = "\033[95m"
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


# ============ FUNKCIJE ============
def check_online(url):
    """Check if online"""
    try:
        req = requests.get(
            url, headers={"User-Agent": random.choice(USER_AGENTS)}, timeout=5
        )
        if req.status_code == 200:
            print(f"{Colors.GREEN} Target online, proceeding...{Colors.RESET}")
            return True
        else:
            print(
                f"{Colors.RED}❌ Target returned status {req.status_code}{Colors.RESET}"
            )
            return False
    except Exception as e:
        print(f"{Colors.RED}❌ Target down: {e}{Colors.RESET}")
        return False


async def get_headers(session, url):
    """Checking headers"""
    try:
        async with session.get(url, timeout=TIMEOUT) as response:
            headers = response.headers
            critical = [
                "Content-Security-Policy",
                "Strict-Transport-Security",
                "X-Frame-Options",
                "X-Content-Type-Options",
                "Referrer-Policy",
            ]

            print(f"\n{Colors.BLUE} Headers for {url}{Colors.RESET}")
            for h in critical:
                if h in headers:
                    print(
                        f"  {Colors.GREEN}Implemented:{Colors.RESET} {h}: {headers.get(h)}"
                    )
                else:
                    print(f"  {Colors.RED}❌ MISSING:{Colors.RESET} {h}")
            return True
    except Exception as e:
        print(f"{Colors.RED}❌ Error fetching headers: {e}{Colors.RESET}")
        return None


async def check_path(session, url, path):
    """Checking path with semaphore"""
    async with SEM:
        try:
            full_url = f"{url.rstrip('/')}/{path}"
            async with session.get(full_url, timeout=TIMEOUT) as response:
                if response.status in [200, 403, 302, 401]:
                    content_length = response.headers.get("Content-Length", 0)
                    try:
                        size = int(content_length) // 1024  # u KB
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


async def find_files(session, url, ext_file, output=OUTPUT_FILE):
    """Main for scanning"""
    try:
        with open(ext_file, "r") as f:
            lines = [
                line.strip()
                for line in f.readlines()
                # if line.strip() and not line.startswith("#")
            ]

        if not lines:
            print(f"{Colors.RED}❌ No valid path!{Colors.RESET}")
            return None

        print(
            f"\n{Colors.BLUE}Scanning {len(lines)} path {MAX_CONCURRENT} parallel requests...{Colors.RESET}\n"
        )

        tasks = [check_path(session, url, line) for line in lines]

        start_time = datetime.now()
        results = await asyncio.gather(*tasks)
        elapsed = (datetime.now() - start_time).total_seconds()

        found = [r for r in results if r is not None]

        found.sort(key=lambda x: x["status"])

        with open(output, "w") as out:
            out.write(f"# Scan started: {start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            out.write(f"# Target: {url}\n")
            out.write(f"# Total paths checked: {len(lines)}\n")
            out.write(f"# Concurrent requests: {MAX_CONCURRENT}\n")
            out.write(f"{'PATH':<45} {'STATUS':<8} {'SIZE':<10}\n")
            out.write("-" * 65 + "\n")

            print(f"{Colors.BLUE}{'PATH':<45} {'STATUS':<8} {'SIZE':<10}{Colors.RESET}")
            print(f"{Colors.BLUE}{'-' * 65}{Colors.RESET}")

            for item in found:
                status_colored = color_status(item["status"])
                print(f"{item['path']:<45} {status_colored:<8} {item['size']:<10}")
                out.write(
                    f"{item['path']:<45} {item['status']:<8} {item['size']:<10}\n"
                )

            out.write("-" * 65 + "\n")
            out.write(f"# Total found: {len(found)}\n")
            out.write(
                f"# Scan finished: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            )
            out.write(f"# Elapsed: {elapsed:.2f} seconds\n")

        status_counts = {}
        for item in found:
            status_counts[item["status"]] = status_counts.get(item["status"], 0) + 1

        print(
            f"\n{Colors.GREEN}Found {len(found)} route in {elapsed:.2f}s{Colors.RESET}"
        )
        print(f"{Colors.BLUE}Stats:{Colors.RESET}")
        for status, count in sorted(status_counts.items()):
            print(f"  {color_status(status)}: {count}")

        print(f"{Colors.BLUE}Results are ready and in: {output}{Colors.RESET}")

        return found

    except FileNotFoundError:
        print(f"{Colors.RED}❌ File {ext_file} not found!{Colors.RESET}")
        return None
    except Exception as e:
        print(f"{Colors.RED}❌ Error: {e}{Colors.RESET}")
        return None


async def main():
    url = "https://test"
    ext_file = "../../tools/SecLists/Discovery/Web-Content/common.txt"

    session_headers = {"User-Agent": random.choice(USER_AGENTS)}

    async with aiohttp.ClientSession(headers=session_headers) as session:
        headers_task = asyncio.create_task(get_headers(session, url))
        files_task = asyncio.create_task(find_files(session, url, ext_file))

        await headers_task
        await files_task

        print("\n" + "=" * 65)
        print(f"{Colors.GREEN}Scan complete!!{Colors.RESET}")
        print("=" * 65)


if __name__ == "__main__":
    url = "https://test"
    if check_online(url):
        asyncio.run(main())
    else:
        print(f"{Colors.RED} Offline. Stopping....{Colors.RESET}")
