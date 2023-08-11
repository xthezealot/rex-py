import asyncio
import random
import re

import aiohttp

from config import args
from wordlist import paths_wordlist

common_ports = {
    # 21: "ftp",
    22: "ssh",
    # 23: "telnet",
    80: "http",
    # 443: "http",
    # 445: "smb",
    # 1433: "mssql",
    # 1521: "oracle",
    # 2375: "docker",
    # 3000: "http",
    # 3306: "mysql",
    # 5000: "http",
    # 5432: "postgresql",
    # 8000: "http",
    # 8008: "http",
    # 8080: "http",
    # 8081: "http",
    # 8443: "http",
    # 8888: "http",
    # 9200: "elasticsearch",
    # 10250: "kubernetes",
    # 27017: "mongodb",
}

interesting_content_types = [
    "application/gzip",
    "application/javascript",
    "application/json",
    "application/msword",
    "application/octet-stream",
    "application/pdf",
    "application/vnd.ms-excel",
    "application/vnd.ms-powerpoint",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/xhtml+xml",
    "application/xml",
    "application/zip",
    "text/csv",
    "text/html",
    "text/javascript",
    "text/plain",
    "text/xml",
]

downloadable_content_types = [
    "application/javascript",
    "application/json",
    "application/xhtml+xml",
    "application/xml",
    "text/csv",
    "text/html",
    "text/javascript",
    "text/plain",
    "text/xml",
]

user_agents = [
    "Mozilla/5.0 (iPad; CPU OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.3 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 11) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5.1 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
]


async def port_info_http(
    sem: asyncio.Semaphore,
    info: dict[str, object],
    http_paths: dict[str, dict[str, str | int]],
    session: aiohttp.ClientSession,
    url: str,
):
    async with sem:
        # respect requests per second
        await asyncio.sleep(1)

        headers = {
            "User-Agent": random.choice(user_agents),
        }

        try:
            async with session.get(
                url, headers=headers, ssl=False, timeout=5
            ) as response:
                # stop if too many requests
                if response.status == 429:
                    raise Exception("Error 420 (too many requests)")

                # skip if:
                # - not found
                # - redirection loop
                # - redirected to another domain
                # - final path (after redirects) was already found
                # - content type in uninteresting
                if (
                    response.status == 404
                    or 300 <= response.status <= 399
                    or response.url.host != response.request_info.url.host
                    or response.url.path in http_paths
                    or (
                        response.content_type
                        and response.content_type not in interesting_content_types
                    )
                ):
                    return

                print(
                    f"[\033[32mFOUND\033[0m]  {response.url}  -  {response.status}  -  {response.content_type}"
                )

                http_paths[response.url.path] = {
                    "status": response.status,
                    "content_type": response.content_type,
                }

                # get server version info
                version = response.headers.get("server") or response.headers.get(
                    "x-server"
                )

                if version:
                    info["version"] = version

                # store interesting responses
                if response.content_type in downloadable_content_types:
                    pass  # todo
        except Exception as e:
            if args.verbose:
                print(f"[\033[31mFAILED\033[0m]  {url}  -  {e}")


async def port_info(host: str, port: int):
    # check port is open
    try:
        conn = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(conn, timeout=10)
        print(f"[\033[32mOPEN\033[0m]  {host}:{port}")
    except Exception as e:
        if args.verbose:
            print(f"[\033[31mCLOSED\033[0m]  {host}:{port}  -  {e}")
        return

    info: dict[str, object] = {"name": common_ports.get(port, "unknown")}
    http_paths: dict[str, dict[str, str | int]] = {}

    match port:
        # http
        case 80 | 443 | 3000 | 5000 | 8000 | 8008 | 8080 | 8081 | 8443 | 8888:
            url = f"http{'s' if port == 443 else ''}://{host}:{port}"

            async with aiohttp.ClientSession() as session:
                # scan n paths at a time on this port
                port_info_http_sem = asyncio.Semaphore(args.rps)
                tasks = [
                    port_info_http(
                        port_info_http_sem,
                        info,
                        http_paths,
                        session,
                        f"{url}/{path}",
                    )
                    for path in paths_wordlist
                ]
                await asyncio.gather(*tasks)

        # ftp
        case 21:
            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=2)
                first_line = data.decode(errors="ignore").split("\n", 1)[0]
                if len(first_line) >= 3:
                    info["version"] = first_line[3:].strip()
            except asyncio.TimeoutError:
                pass

        # ssh
        case 22:
            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=2)
                data = data.decode(errors="ignore")
                pattern = re.compile(r"(?im)^.*ssh.*$")
                extract = pattern.search(data)
                if extract:
                    info["version"] = extract.group().strip()
            except asyncio.TimeoutError:
                pass

        # mysql
        case 3306:
            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=2)
                data = data.decode(errors="ignore")
                pattern = re.compile(r"(?m)^[0-9a-zA-Z-_+.]{3,}")
                extract = pattern.search(data)
                if extract:
                    info["version"] = extract.group().strip()
            except asyncio.TimeoutError:
                pass

        case _:
            pass

    if writer:
        writer.close()
        await writer.wait_closed()

    if http_paths:
        info["http"] = http_paths

    return info
