import requests
import os
import argparse
from simple_term_menu import TerminalMenu
from time import sleep
from requests.exceptions import ConnectionError, Timeout, RequestException
from urllib3.exceptions import ConnectionError
from datetime import datetime

from src.do_setup import *
from src.do_keywords import *

def do_request(reap, notor, port, targ):
    # Setup session
    s = requests.Session()
    pre = requests.get("http://icanhazip.com")
    print(f"Current External IP: {pre.content.decode()}", end="")
    if (notor == False):
        s.proxies.update({'http': 'socks5://127.0.0.1:9050'})
        post = s.get("http://icanhazip.com")
        print(f"TOR External IP: {post.content.decode()}", end="")
        if (post.content == pre.content):
            print("\nERR: With and without tor are same.")
            print("If you are not running tor specify -t")
            exit()

    if (targ == False):
        fp = open("result.txt", "r")
        targets = fp.readlines()
        fp.close()
    else:
        targets = []
        targets.append(targ)
    fp = open("history.txt", "r")
    history = fp.readlines()
    fp.close()
    w_history = open("history.txt", "w+")
    w_history.writelines(history)

    print("Current histfile:")
    lc = 0
    for ip in history:
        # If ip is too short add an extra tab
        if (len(ip) <= 8):
            ext = "\t"
        else:
            ext = ""

        if (lc == 3):
            print(f"{ip.strip()}\t{ext}\n", end="")
            lc = 0
        else:
            print(f"{ip.strip()}\t{ext}\n", end="")
            lc += 1
    for target in targets:
        try:
            if (target.strip() + "\n" not in history):
                r = s.get(f"http://{target.strip()}:{port}/.ssh/", timeout=10)
                print(Fore.RESET + f"http://{target.strip()}:{port}/.ssh/ --> Status Code: {r.status_code}")
                w_history.write(target.strip() + "\n")
                # will return bool True | False depending if key word was found
                key, find = ssh_words(r.content, target.strip())
                if ((key and reap) or (targ and reap)):
                    print(f"{target.strip()} contains:")
                    #            print(r.content.decode().split("\n"))
                    for line in r.content.decode().split("\n"):
                        if ("<a href=\"" in line):
                            file = line.split("href=\"")[1].split("\"")[0]
                            print("\t" + file)
        except (ConnectionError, Timeout, RequestException):
            print(Fore.RED + f"{target.strip()}, is not responsive")
    w_history.close()


if __name__ == "__main__":
    # print the banner
    banner()
    notor = False
    parser = argparse.ArgumentParser(
        prog='Data Scraper',
        description='Querys shodan for indexable http servers',
        epilog='Made by Aznable and ice-wzl')
    parser.add_argument('-q', '--query', action='store_true', help="Conduct shodan query and update result.txt")
    parser.add_argument('-s', '--scan', action='store_true',
                        help="Conduct scans and enumeration of targets in result.txt")
    parser.add_argument('-n', '--notor', action='store_true', help="Dont use tor")
    parser.add_argument('-p', '--port', help="Specify port number (Default 8000)")
    parser.add_argument('-t', '--target', help="Specify a target to Scan/Reap")
    args = parser.parse_args()

    # conduct the shodan query to get the results
    if len(sys.argv) == 2:
        parser.print_help()
        sys.exit(1)

    if (args.query):
        if (args.port):
           do_query(setup_api(), f'Title:"Directory listing for /" port:{args.port}')
        else:
            do_query(setup_api(), 'Title:"Directory listing for /" port:8000')
        sleep(1.0)
    # perform the requests which will loop through the results in results.txt
    if (args.target):
        if (args.port):
            do_request(args.reap, args.notor, True, args.port, args.target)
        else:
            do_request(args.reap, args.notor, True, "8000", args.target)
    if (args.scan):
        if (args.port):
            do_request(True, args.notor, args.port, False)
        else:
            do_request(True, args.notor, "8000", False)