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

# create an automated way to download

def opsec_check(session: requests.Session):
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

def get_targets(proxy, verbose):
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

def main(args):
    banner()

    with open("runtime.log", "a") as fp:
        dt = datetime.now()
        format_date = dt.strftime("%Y-%m-%d %H:%M:%S")
        fp.write(f"started script {format_date}\n")

    session = requests.Session()
    if args.tor:
        session.proxies.update({
            "http":  f"socks5h://{args.tor}",
            "https": f"socks5h://{args.tor}",
        })
    if not args.noninteractive:
        opsec_check(session)

    if args.query and not args.port:
        print("[-] -p port required for a query.")
        return

    if args.query:
        scan = Scan(
            proxy=args.tor,
            port=args.port,
            verbose=args.verbose
        )
        scan.run_query(
            f'Title:"Directory listing for /" port:{args.port}'
        )

    if args.scan:
        get_targets(args.tor, args.verbose)
        get_download_targets(args.tor, args.verbose)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="Data Scraper",
        description="Query Shodan for indexable HTTP servers and enumerate exposed files"
    )

    action_group = parser.add_mutually_exclusive_group(required=True)
    action_group.add_argument("-q", "--query", action="store_true")
    action_group.add_argument("-s", "--scan", action="store_true")

    parser.add_argument("-t", "--tor", help="SOCKS proxy ip:port", default=None)
    parser.add_argument("-p", "--port", help="Target port", required=False)
    parser.add_argument("-n", "--noninteractive", help="Run and do not prompt", required=False, action="store_true")
    parser.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args()
    main(args)
