import asyncio
import re

import aiohttp

from wordlist import paths_wordlist

common_ports = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    80: "http",
    443: "http",
    445: "smb",
    1433: "mssql",
    1521: "oracle",
    2375: "docker",
    3000: "http",
    3306: "mysql",
    5000: "http",
    5432: "postgresql",
    8000: "http",
    8008: "http",
    8080: "http",
    8081: "http",
    8443: "http",
    8888: "http",
    9200: "elasticsearch",
    10250: "kubernetes",
    27017: "mongodb",
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


async def port_info(host: str, port: int):
    reader, writer = None, None

    try:
        conn = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(conn, timeout=1)
        print(f"{host}:{port} \033[92mopen\033[0m")
    except (ConnectionRefusedError, OSError):
        return

    info: dict[str, object] = {"name": common_ports.get(port, "unknown")}
    http_paths: dict[str, object] = {}

    match port:
        # http
        case 80 | 443 | 3000 | 5000 | 8000 | 8008 | 8080 | 8081 | 8443 | 8888:
            url = "http"
            if port == 443:
                url += "s"
            url += "://" + host + ":" + str(port)

            # scan_target_sem = asyncio.Semaphore(100)
            try:
                timeout = aiohttp.ClientTimeout(total=10)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    for path in paths_wordlist:
                        async with session.get(url + "/" + path) as response:
                            # stop if too many requests
                            if response.status == 429:
                                print(
                                    f"too many requests (status 429) on {host}:{port}"
                                )
                                break

                            # skip if:
                            # - not found
                            # - redirection loop
                            # - redirected to another domain
                            # - final path (after redirects) was already found
                            # - content type in uninteresting
                            if (
                                response.status == 404
                                or 300 <= response.status <= 399
                                or response.url.host != host
                                or response.url.path in http_paths
                                or (
                                    response.content_type
                                    and response.content_type
                                    not in interesting_content_types
                                )
                            ):
                                continue

                            print(
                                f"found {response.url} ({response.status}, {response.content_type})"
                            )

                            # get server version info
                            version = response.headers.get(
                                "server"
                            ) or response.headers.get("x-server")

                            if version:
                                info["version"] = version

                            # store interesting responses
                            if response.content_type in downloadable_content_types:
                                pass  # todo

            except asyncio.TimeoutError:
                pass

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
