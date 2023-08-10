import ipaddress
import re
from ipaddress import ip_network
from urllib.parse import urlparse


def is_valid_domain(domain: str) -> bool:
    """Check if each part of the domain is between 1 and 63 characters and does not contain any special characters."""
    if any(
        len(part) < 1
        or len(part) > 63
        or re.search(r"[!\"#$%&'()*+,/;<=>?@\[\\\]^_`{|}~ ]", part)
        for part in domain.split(".")
    ):
        return False
    return True


def is_ip(input: str) -> bool:
    try:
        ipaddress.ip_address(input)
        return True
    except ValueError:
        return False


def extract_hosts(input: str):
    hosts: list[str] = []

    # check if the input is an email address
    email_pattern = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
    if email_pattern.fullmatch(input):
        domain = input.split("@")[1]
        if is_valid_domain(domain):
            hosts.append(domain)
            return hosts

    # check if the input is an IP address
    ip_pattern = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
    if ip_pattern.fullmatch(input):
        hosts.append(input)
        return hosts

    # check if the input is a CIDR notation
    cidr_pattern = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}\b")
    if cidr_pattern.fullmatch(input):
        network = ip_network(input, strict=False)
        for ip in network.hosts():
            hosts.append(str(ip))
        return hosts

    # check if the input is a URL
    try:
        parsed_url = urlparse(input)
        if parsed_url.netloc:
            hostname = parsed_url.hostname
            if hostname:
                hosts.append(hostname)
            return hosts
    except ValueError:
        pass

    # assume the input is a domain name
    domain_name = input.split(":")[0]  # exclude port if present
    domain_name = domain_name.split("/")[0]  # exclude path if present
    if is_valid_domain(domain_name):
        hosts.append(domain_name)
    return hosts
