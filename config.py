import argparse

argparser = argparse.ArgumentParser(description="Rex scanner")

argparser.add_argument(
    "--rps", type=int, default=50, help="max requests per second on a target port"
)

argparser.add_argument(
    "-s", "--subdomains", action="store_true", help="find subdomains"
)

args = argparser.parse_args()
