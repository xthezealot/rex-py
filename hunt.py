import asyncio
import socket
import subprocess
from typing import Any

import yaml

from hosts import extract_hosts, is_ip
from ports import (
    Path,
    Port,
    PortDocker,
    PortElasticSearch,
    PortFTP,
    PortHTTP,
    PortKubernetes,
    PortMongoDB,
    PortMSSQL,
    PortMySQL,
    PortOracle,
    PortPostgreSQL,
    PortSMB,
    PortSSH,
    PortTelnet,
    interesting_ports,
)
from utils import set_nested


class Target:
    def __init__(self, host: str) -> None:
        self.host = host
        self.ports: list[
            Port
            | PortDocker
            | PortElasticSearch
            | PortFTP
            | PortHTTP
            | PortKubernetes
            | PortMongoDB
            | PortMSSQL
            | PortMySQL
            | PortOracle
            | PortPostgreSQL
            | PortSMB
            | PortSSH
            | PortTelnet
        ] = [cls(host, num) for num, cls in interesting_ports]

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

            self.targets: list[Target] = []

            for host, ports_dict in hunt.get("targets", {}).items():
                target = Target(host)
                for port in target.ports:
                    if port.number in ports_dict:
                        port.open = True
                        port_data = ports_dict[port.number]
                        if hasattr(port, "version") and port_data.get("version"):
                            port.version = port_data.get("version")  # type: ignore
                        if hasattr(port, "paths") and port_data.get("paths"):
                            for path_value, path_data in port_data.get("paths").items():
                                path = Path(host, port.number, path_value)
                                path.status = path_data.get("status")
                                path.content_type = path_data.get("content_type")
                                path.title = path_data.get("title")
                                port.paths.append(path)  # type: ignore
                self.targets.append(target)

            self._new_targets: list[Target] = []

    def to_dict(self) -> dict[str, object]:
        """Represents the hunt as a dictionary (to use on export).

        Returns:
            dict[str, object]: The dictionary representing the hunt.
        """
        targets = {}
        for target in self.targets:
            for port in target.ports:
                if port.open:
                    set_nested(targets, [target.host, port.number, "name"], port.name)
                    if hasattr(port, "version") and port.version:  # type: ignore
                        set_nested(targets, [target.host, port.number, "version"], port.version)  # type: ignore
                    if hasattr(port, "paths") and port.paths:  # type: ignore
                        for path in port.paths:  # type:ignore
                            if hasattr(path, "status") and path.status:  # type: ignore
                                set_nested(targets, [target.host, port.number, "paths", path.value, "status"], path.status)  # type: ignore
                            if hasattr(path, "content_type") and path.content_type:  # type: ignore
                                set_nested(targets, [target.host, port.number, "paths", path.value, "content_type"], path.content_type)  # type: ignore
                            if hasattr(path, "title") and path.title:  # type: ignore
                                set_nested(targets, [target.host, port.number, "paths", path.value, "title"], path.title)  # type: ignore
        return {
            "scope": self.scope,
            "targets": targets,
        }

    def save(self):
        with open(self.filename, "w") as file:
            yaml.dump(self.to_dict(), file)

    @property
    def new_targets(self):
        return self._new_targets

    @staticmethod
    def make_file():
        """Create a base file for a hunt."""
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
        tasks = [target.scan(sem) for target in self._new_targets]
        await asyncio.gather(*tasks)
