import requests
import os
import argparse
import ipaddress
from simple_term_menu import TerminalMenu
from time import sleep
from requests.exceptions import ConnectionError, Timeout, RequestException
from urllib3.exceptions import ConnectionError
from datetime import datetime

from src.do_setup import *
from src.do_keywords import *

def validate_ip(ip_string) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_string)
        return True
    except ValueError as e:
        print(f"Error invalid ip address: {e}")
        return False

def validate_port(port) -> bool:
    try:
        port_int = int(port)
        if port_int > 65535 or port_int < 0:
            print(f"[-] Error invalid port: {port}")
            return False
        return True
    except ValueError as e:
        print(f"[-] Error invalid port: {port}")
        return False


def session_tor_setup(socks_proxy_host_port):
    if ":" not in socks_proxy_host_port:
        print("Error: specify socks proxy in <ip>:<port> format")
        sys.exit(2)

    socks_proxy_parts = socks_proxy_host_port.split(":")
    if not validate_port(socks_proxy_parts[-1]):
        sys.exit(3)
    if not validate_ip(socks_proxy_parts[0]):
        sys.exit(4)
    s = requests.Session()
    s.proxies.update({'http': f'socks5://{socks_proxy_host_port}'})
    return s


def opsec_check(s: requests.Session) -> None:
    pre = s.get("http://icanhazip.com")
    print(f"[+] Current External IP: {pre.content.decode()}", end="")
    user_choice = input("Continue [Y/n]: ").lower()
    if user_choice.strip() == "n" or user_choice.strip() == "no":
        print("Ok, exiting...")
        sys.exit(5)
    
def get_targets() -> list:
    with open ("results.txt", "r") as fp:
        return [line.strip() for line in fp.readlines()]


def do_ssh_scan(s: requests.Session, targets: list, port: str) -> None:
    for target in targets:
        try:
            r = s.get(f"http://{target}:{port}/.ssh/", timeout=10)
            print(Fore.RESET + f"http://{target}:{port}/.ssh/ --> Status Code: {r.status_code}")
            search_keyword(r.content, target)
        except (ConnectionError, Timeout, RequestException):
            print(Fore.RED + f"{target.strip()}, is not responsive")

def search_keyword(content, target: str) -> None:
    match, find = ssh_words(content, target)
    if match:
        print(f"{target} contains:")
        for line in content.decode().split("\n"):
            if ("<a href=\"" in line):
                file = line.split("href=\"")[1].split("\"")[0]
                print("\t" + file)


if __name__ == "__main__":
    banner()
    parser = argparse.ArgumentParser(
        prog='Data Scraper',
        description='Querys shodan for indexable http servers',
        epilog='Made by Aznable and ice-wzl')

    parser.add_argument('-q', '--query', action='store_true', help="Conduct shodan query and update result.txt", dest="query")
    parser.add_argument('-t', '--tor', help="Use socks proxy <ip>:<port> format", required=False, default=False, dest="tor")
    parser.add_argument('-p', '--port', help="Specify port number (Default 8000)", required=True, default="8000", dest="port")
    parser.add_argument('-s', '--scan', action='store_true', help="Conduct scans and enumeration of targets in result.txt", dest="scan")
    args = parser.parse_args()

    if not args.scan and not args.query:
        print("[-] Nothing to do, -s (scan) or -q (query) required")
        sys.exit(1)

    # query the shodan api and write all returned hosts to results.txt
    if args.query:
        do_query(setup_api(), f'Title:"Directory listing for /" port:{args.port}')

    if args.scan:
        if args.tor:
            s = session_tor_setup(args.tor)
        else:
            s = requests.Session()

        opsec_check(s)

        targets = get_targets()
        if len(targets) == 0:
            print("Error: No results returned, perform a new query with -q")
            sys.exit(2)
        do_ssh_scan(s, targets, args.port)