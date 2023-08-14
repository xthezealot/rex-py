#!/usr/bin/env python3

import asyncio
import os
import time
from datetime import datetime

from config import args
from hunt import Hunt


def main():
    try:
        hunt = Hunt()
    except FileNotFoundError:
        Hunt.make_file()
        exit()

    if not hunt.scope:
        print(f"\033[31mScope is required in {Hunt.filename}\033[0m")
        exit()

    hunt.scope_to_targets()

    if not hunt.new_targets:
        print("\033[33mNo new target\033[0m")
        exit()

    if args.subdomains:
        hunt.find_new_subdomains()

    start_time = time.time()
    try:
        pid = os.getpid()
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[\033[34mINFO\033[0m]  Scan started on {current_time} with PID {pid}")

        asyncio.run(hunt.scan_targets())

    finally:
        execution_time = time.time() - start_time
        print(f"[\033[34mINFO\033[0m]  Scan done in {execution_time:.2f} seconds")

        hunt.save()


if __name__ == "__main__":
    main()
