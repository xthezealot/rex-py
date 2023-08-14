import asyncio
import socket
import subprocess
from typing import Any

import yaml

from hosts import extract_hosts, is_ip
from ports import Port, interesting_ports


class Target:
    def __init__(self, host: str) -> None:
        self.host = host
        self.ports: list[Port] = [cls(host, num) for num, cls in interesting_ports]

    def __str__(self):
        return self.host

    def __eq__(self, other: Any):
        if isinstance(other, Target):
            return self.host == other.host
        else:
            return self.host == other

    async def scan(self, sem: asyncio.Semaphore):
        async with sem:
            try:
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, socket.getaddrinfo, self.host, None)
            except socket.gaierror:
                print(f"[\033[31mERROR\033[0m]  Could not resolve {self}")
                return

            # scan ports concurrently
            tasks = [port.scan() for port in self.ports]
            await asyncio.gather(*tasks)

            # todo: nuclei generic scan


class Hunt:
    filename = "hunt.yml"

    def __init__(self):
        with open(self.filename, "r") as file:
            hunt = yaml.safe_load(file)
            self.scope: list[str] = hunt.get("scope") or []
            self.targets: list[Target] = hunt.get("targets") or []
            self._new_targets: list[Target] = []

    def save(self):
        with open(self.filename, "w") as file:
            yaml.dump(self, file)

    @property
    def new_targets(self):
        return self._new_targets

    @staticmethod
    def make_file():
        with open(Hunt.filename, "w") as file:
            yaml.dump({"scope": [""]}, file)
        print(f"\033[31mFile {Hunt.filename} created\033[0m")

    def add_target(self, host: str):
        if host in self.targets:  # type: ignore
            return
        target = Target(host)
        self.targets.append(target)
        self._new_targets.append(target)
        print(f"[\033[34mNEW TARGET\033[0m]  {target}")

    def scope_to_targets(self):
        """Parse the scope and add new targets."""
        for scope in self.scope:
            for host in extract_hosts(scope):
                self.add_target(host)

    def find_new_subdomains(self):
        """Find unknown subdomains for all new targets that represent a domain."""

        new_domains: list[str] = []

        for target in self._new_targets:
            if not is_ip(target.host):
                new_domains.append(target.host)

        if not new_domains:
            return

        command = ["subfinder", "-all", "-active", "-silent"]
        for domain in new_domains:
            command.extend(["-d", domain])
        output = subprocess.check_output(command, text=True)
        for subdomain in output.splitlines():
            self.add_target(subdomain)

    async def scan_targets(self):
        sem = asyncio.Semaphore(100)  # scan n targets at a time
        tasks = [target.scan(sem) for target in self.targets]
        await asyncio.gather(*tasks)
