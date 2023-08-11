import argparse

argparser = argparse.ArgumentParser(description="Rex scanner")

argparser.add_argument(
    "--rps", type=int, default=50, help="max requests per second on a target port"
)

argparser.add_argument(
    "-s", "--subdomains", action="store_true", help="find subdomains"
)

argparser.add_argument("-v", "--verbose", action="store_true", help="show more infos")

args = argparser.parse_args()
