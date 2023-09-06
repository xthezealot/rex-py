import asyncio
import os
import random
import re
import subprocess
from typing import Any, Coroutine

import aiohttp

from config import args
from wordlist import (
    downloadable_content_types,
    interesting_content_types,
    paths_wordlist,
    user_agents,
)


class Path:
    def __init__(self, host: str, port: int, value: str) -> None:
        self.host = host
        self.port_number = port
        self.value = value
        self.status: int | None = None
        self.content_type: str | None = None
        self.title: str | None = None
        self.xss: str | None = None

    def __str__(self):
        return self.value

    def __eq__(self, other: Any):
        if isinstance(other, Path):
            return self.value == other.value
        else:
            return self.value == other


class Port:
    def __init__(self, host: str, number: int) -> None:
        self.host = host
        self.number = number
        self.open: bool | None = None

    def __str__(self):
        return str(self.number)

    @property
    def name(self) -> str:
        return "unknown"

    async def scan(self):
        try:
            # check port is open
            conn = asyncio.open_connection(self.host, self.number)
            reader, writer = await asyncio.wait_for(conn, timeout=10)
            self.open = True
            print(f"[\033[32mOPEN\033[0m]  {self.host}:{self.number}")

            await self.specific_scan(reader, writer)

            if writer:
                writer.close()
                await writer.wait_closed()

        except TimeoutError:
            self.open = False
            if args.verbose:
                print(f"[\033[31mTIMEOUT\033[0m]  {self.host}:{self.number}")
            return
        except ConnectionRefusedError:
            self.open = False
            if args.verbose:
                print(f"[\033[31mCLOSED\033[0m]  {self.host}:{self.number}")
            return
        except Exception as e:
            self.open = False
            if args.verbose:
                print(f"[\033[31mERROR\033[0m]  {self.host}:{self.number}  -  {e}")
            return

    async def specific_scan(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        pass


class PortDocker(Port):
    @property
    def name(self):
        return "docker"


class PortElasticSearch(Port):
    @property
    def name(self):
        return "elasticsearch"


class PortFTP(Port):
    def __init__(self, host: str, number: int) -> None:
        super().__init__(host, number)
        self.version: str | None = None

    @property
    def name(self):
        return "ftp"

    async def specific_scan(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=2)
            first_line = data.decode(errors="ignore").split("\n", 1)[0]
            if len(first_line) >= 3:
                self.version = first_line[3:].strip()
        except asyncio.TimeoutError:
            pass


class PortHTTP(Port):
    def __init__(self, host: str, number: int) -> None:
        super().__init__(host, number)
        self.version: str | None = None
        self.paths: list[Path] = []

    @property
    def name(self):
        return "http"

    async def specific_scan(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        async with aiohttp.ClientSession() as session:
            # scan n paths at a time on this port
            sem = asyncio.Semaphore(args.rps)
            tasks: list[Coroutine[Any, Any, None]] = []
            for path in paths_wordlist:
                path = Path(self.host, self.number, path)
                tasks.append(self.scan_path(sem, session, path))
            await asyncio.gather(*tasks)

    async def scan_path(
        self,
        sem: asyncio.Semaphore,
        session: aiohttp.ClientSession,
        path: Path,
    ):
        async with sem:
            # respect requests per second
            await asyncio.sleep(1)

            url = f"http{'s' if self.number == 443 else ''}://{self.host}:{self.number}/{path}"
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

                    # clean
                    path.value = response.url.path.rstrip("/") or "/"
                    path.status = response.status
                    path.content_type = response.content_type

                    # skip if:
                    # - not found
                    # - redirection loop
                    # - redirected to another domain
                    # - final path (after redirects) was already found
                    # - content type in uninteresting
                    if (
                        response.status == 404
                        or 300 <= response.status <= 399
                        or response.url.host != self.host
                        or path.value in self.paths  # type:ignore
                        or (
                            response.content_type
                            and response.content_type not in interesting_content_types
                        )
                    ):
                        return

                    print(
                        f"[\033[32mFOUND\033[0m]  {response.url}  ({response.status}, {response.content_type})"
                    )

                    self.paths.append(path)

                    # get server version info
                    version = response.headers.get("server") or response.headers.get(
                        "x-server"
                    )
                    if version:
                        self.version = version

                    # store interesting responses
                    if path.content_type in downloadable_content_types:
                        filepath = path.value.replace("..", "PARENT")
                        if filepath == "/":
                            filepath = "INDEX"
                        filepath = os.path.join(
                            os.getcwd(),
                            "http",
                            self.host + ":" + str(self.number),
                            filepath.lstrip("/"),
                        )

                        dirpath = os.path.dirname(filepath)
                        os.makedirs(dirpath, exist_ok=True)

                        http_version = f"HTTP/{response.version.major}.{response.version.minor}"  # type: ignore
                        status_line = f"{http_version} {response.status} {response.reason}"  # type: ignore
                        raw_headers = "\r\n".join(
                            [f"{k}: {v}" for k, v in response.headers.items()]
                        )
                        body = await response.text()
                        raw_response = f"{status_line}\r\n{raw_headers}\r\n\r\n{body}"

                        if response.content_type == "text/html":
                            title_match = re.search(
                                "<title>(.*?)</title>", body, re.IGNORECASE
                            )
                            if title_match:
                                path.title = title_match.group(1)

                        with open(filepath, "w") as f:
                            f.write(raw_response)

                    # check xss
                    output = subprocess.run(
                        ["dalfox", "url", str(response.url)],
                        check=True,
                        capture_output=True,
                        text=True,
                    ).stdout
                    if output:
                        path.xss = output

                    # todo: if path is /robots.txt, parse file content and add paths to wordlist

                    # todo: read body and try to find secrets

            except TimeoutError:
                if args.verbose:
                    print(f"[\033[31mTIMEOUT\033[0m]  {url}")
            except Exception as e:
                if args.verbose:
                    print(f"[\033[31mERROR\033[0m]  {url}  -  {e}")


class PortKubernetes(Port):
    @property
    def name(self):
        return "kubernetes"


class PortMongoDB(Port):
    @property
    def name(self):
        return "mongodb"


class PortMSSQL(Port):
    @property
    def name(self):
        return "mssql"


class PortMySQL(Port):
    def __init__(self, host: str, number: int) -> None:
        super().__init__(host, number)
        self.version: str | None = None

    @property
    def name(self):
        return "mysql"

    async def specific_scan(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=2)
            data = data.decode(errors="ignore")
            pattern = re.compile(r"(?m)^[0-9a-zA-Z-_+.]{3,}")
            extract = pattern.search(data)
            if extract:
                self.version = extract.group().strip()
        except asyncio.TimeoutError:
            pass


class PortOracle(Port):
    @property
    def name(self):
        return "oracle"


class PortPostgreSQL(Port):
    @property
    def name(self):
        return "postgresql"


class PortSMB(Port):
    @property
    def name(self):
        return "smb"


class PortSSH(Port):
    def __init__(self, host: str, number: int) -> None:
        super().__init__(host, number)
        self.version: str | None = None

    @property
    def name(self):
        return "ssh"

    async def specific_scan(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=2)
            data = data.decode(errors="ignore")
            pattern = re.compile(r"(?im)^.*ssh.*$")
            extract = pattern.search(data)
            if extract:
                self.version = extract.group().strip()
        except asyncio.TimeoutError:
            pass


class PortTelnet(Port):
    @property
    def name(self):
        return "telnet"


interesting_ports: list[tuple[int, type[Port]]] = [
    (21, PortFTP),
    (22, PortSSH),
    (23, PortTelnet),
    (80, PortHTTP),
    (443, PortHTTP),
    (445, PortSMB),
    (1433, PortMSSQL),
    (1521, PortOracle),
    (2375, PortDocker),
    (3000, PortHTTP),
    (3306, PortMySQL),
    (5000, PortHTTP),
    (5432, PortPostgreSQL),
    (8000, PortHTTP),
    (8008, PortHTTP),
    (8080, PortHTTP),
    (8081, PortHTTP),
    (8443, PortHTTP),
    (8888, PortHTTP),
    (9200, PortElasticSearch),
    (10250, PortKubernetes),
    (27017, PortMongoDB),
]
