import asyncio
import aiohttp
import requests


def check_online(url):
    up = 0
    req = requests.get(url)
    if req.status_code == 200:
        print("Target online, proceeding...")
        up = 1
        return up
    else:
        print("Target down")
        return up


async def get_headers(session, url):
    try:
        async with session.get(url, timeout=5) as response:
            headers = response.headers
            critical = [
                "Content-Security-Policy",
                "Strict-Transport-Security",
                "X-Frame-Options",
                "X-Content-Type-Options",
                "Referrer-Policy",
            ]
            for h in critical:
                if h in headers:
                    print("Implemented: " + str(h) + ": " + str(headers.get(h)))
                else:
                    print("MISSING: " + str(h))
    except Exception as e:
        print(f"Error: {e}")
        return None


async def find_files(url, ext):
    f = open(ext, "r")
    f1 = open("routes.txt", "w+")
    for line in f.readlines():
        req = requests.get(url + "/" + line)
        if req.status_code == 200:
            print(f)
            f1.writelines(f)


async def main():
    url = "https://example.com"
    ext = "../tools/SecLists/Discovery/Web-Content/raft-small-files.txt"

    async with aiohttp.ClientSession() as session:
    
        headers_task = asyncio.create_task(get_headers(session, url))
       
        headers_result = await headers_task
        
        print("\n" + "=" * 50)
        print("DONE:")
        print(f"  Headers: {'Success' if headers_result else 'Err'}")



if __name__ == "__main__":
    url = "https://example.com"
    if check_online(url) == 1:
        asyncio.run(main())
