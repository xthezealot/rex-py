#!/usr/bin/env python3

import asyncio
import socket
import subprocess

import yaml

from config import args
from hosts import extract_hosts, is_ip
from ports import common_ports, port_info

hunt_filename = "hunt.yml"


try:
    # retreive hunt from file
    with open(hunt_filename, "r") as file:
        hunt = yaml.safe_load(file)
except FileNotFoundError:
    # create hunt file
    with open(hunt_filename, "w") as file:
        yaml.dump({"scope": [""]}, file)
    print(f"\033[31mFile {hunt_filename} created\033[0m")
    exit()

# check scope
if "scope" not in hunt or not hunt["scope"]:
    print(f"\033[31mScope is required in {hunt_filename}\033[0m")
    exit()

# init targets list
if "targets" not in hunt or not hunt["targets"]:
    hunt["targets"] = {}

# add new targets from scope
new_targets: list[str] = []
for scope in hunt["scope"]:
    for target in extract_hosts(scope):
        if target not in hunt["targets"]:
            hunt["targets"][target] = {}
            new_targets.append(target)
            print(f"[\033[34mNEW TARGET\033[0m]  {target}")


if not new_targets:
    print("\033[33mNo new target\033[0m")
    exit()


# find subdomains


if args.subdomains:
    new_domains: list[str] = []
    for target in new_targets:
        if not is_ip(target):
            new_domains.append(target)

    if new_domains:
        try:
            command = ["subfinder", "-all", "-active", "-silent"]
            for domain in new_domains:
                command.extend(["-d", domain])
            output = subprocess.check_output(command, text=True)
            for subdomain in output.splitlines():
                if subdomain not in hunt["targets"]:
                    hunt["targets"][subdomain] = {}
        except subprocess.CalledProcessError as e:
            print(f"[\033[31mFAIL\033[0m]  subfinder failed  -  {e}")


# scan new tragets


async def scan_target_port(target: str, port: int):
    info = await port_info(target, port)
    if info:
        hunt["targets"][target][port] = info


# scan n targets at a time
scan_target_sem = asyncio.Semaphore(100)


async def scan_target(target: str):
    async with scan_target_sem:
        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, socket.getaddrinfo, target, None)
        except socket.gaierror:
            print(f"[\033[31mERROR\033[0m]  Could not resolve {target}")
            return

        # scan ports concurrently
        tasks = [scan_target_port(target, port) for port in common_ports]
        await asyncio.gather(*tasks)

        # todo: nuclei generic scan


async def scan_targets():
    tasks = [scan_target(target) for target in new_targets]
    await asyncio.gather(*tasks)


asyncio.run(scan_targets())


# save hunt


with open(hunt_filename, "w") as file:
    yaml.dump(hunt, file)
