#!/usr/bin/python3
# Title:"Directory listing for /" port:{args.port}
import argparse
import shodan
import sys
import requests
import base64
import ipaddress
import sqlite3
import os
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from requests.exceptions import ConnectionError, Timeout, RequestException
from urllib3.exceptions import ConnectionError
from datetime import datetime

# TODO: remove non responsive hosts from the ToScan table
# create an automated way to download

full_word_match = [
    "cobalt",
    "collect",
    "brute",
    "home",
    "root",
    "shadow",
    "wg",
]
merged_list = [
        ".aws",
        ".bash_history",
        ".git",
        ".git-credentials",
        ".msf4",
        ".msf6",
        ".p12",
        ".pem",
        ".pfx",
        ".python_history",
        ".ssh",
        ".viminfo",
        ".wg-easy",
        ".wget-hsts",
        "0day",
        "backup",
        "brute_ratel",
        "bruteforce",
        "cert.crt",
        "cobalt-strike",
        "cobalt_strike",
        "crt.key",
        "crt.pem",
        "crypter",
        "Desktop",
        "Documents",
        "Downloads",
        "dropper_cs.exe",
        "exploit",
        "gorailgun",
        "gost",
        "hack",
        "hacking",
        "havoc",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "id_rsa",
        "key.key",
        "key.pem",
        "lockbit",
        "log4j",
        "malware",
        "metasploit",
        "mrlapis",
        "nessus",
        "ngrok",
        "nmap",
        "notes",
        "nuclei",
        "passwd",
        "password",
        "payload",
        "pp_id_rsa.ppk",
        "priv_key",
        "qakbot",
        "qbot",
        "ransom",
        "ransomware",
        "ratel",
        "redlinestealer",
        "revil",
        "shellcode",
        "sliver",
        "sqlmap",
        "ssh_rsa.pem",
        "tools",
        "victim",
        "wireguard",
        "wormhole"
    ]

def banner():
    print(
        Fore.RED +
        r"""
               ...                            
             ;::::;                           
           ;::::; :;                          
         ;:::::'   :;                         
        ;:::::;     ;.                        
       ,:::::'       ;           OOO\      
       ::::::;       ;          OOOOO\        
       ;:::::;       ;         OOOOOOOO       
      ,;::::::;     ;'         / OOOOOOO      
    ;:::::::::`. ,,,;.        /  / DOOOOOO    
  .';:::::::::::::::::;,     /  /     DOOOO   
 ,::::::;::::::;;;;::::;,   /  /        DOOO  
;`::::::`'::::::;;;::::: ,#/  /          DOOO 
:`:::::::`;::::::;;::: ;::#  /            DOOO
::`:::::::`;:::::::: ;::::# /              DOO
`:`:::::::`;:::::: ;::::::#/               DOO
 :::`:::::::`;; ;:::::::::##                OO
 ::::`:::::::`;::::::::;:::#                OO
 `:::::`::::::::::::;'`:;::#                O 
  `:::::`::::::::;' /  / `:#                  
   ::::::`:::::;'  /  /   `#              v.3.0.0
                                  Made by Aznable,
                                          ice-wzl
    """ + Fore.RESET
    )


def opsec_check(session: requests.Session):
    pre = session.get("http://icanhazip.com", timeout=10)
    print(f"[+] Current External IP: {pre.text}", end="")
    user_choice = input("Continue [Y/n]: ").lower().strip()
    if user_choice in ("n", "no"):
        print("Ok, exiting...")
        sys.exit(5)


class Scan:
    def __init__(self, query, proxy, port, verbose):
        self.query   = query
        self.proxy   = proxy
        self.port    = port
        self.verbose = verbose

        if self.proxy is not None:
            self.session, err = self.session_tor_setup(self.proxy)
            if not self.session:
                print(f"Error: {err}")
                sys.exit(1)
        else:
            self.session = requests.Session()

        if self.query is not None:
            api, err = self.setup_api()
            if api is None:
                print(f"Error: {err}")
                return
            results = self.do_query(api)
            if results is not None:
                self.write_query_results(results)


    def session_tor_setup(self, socks_proxy_host_port):
        if ":" not in socks_proxy_host_port:
            return None, "socks proxy should be in host:port format"

        host, port = socks_proxy_host_port.split(":", 1)

        if not self.validate_port(port):
            return None, "invalid port provided"
        if not self.validate_ip(host):
            return None, "invalid ip provided"

        s = requests.Session()
        s.proxies.update({
            "http":  f"socks5h://{socks_proxy_host_port}",
            "https": f"socks5h://{socks_proxy_host_port}",
        })
        return s, ""


    def setup_api(self):
        try:
            with open("api.txt", "r") as fp:
                api_key = fp.read().strip()
                if self.verbose:
                    print(f"API key used: {api_key}")
            return shodan.Shodan(api_key), ""
        except FileNotFoundError:
            return None, "api.txt not found"


    def do_query(self, api):
        try:
            if self.verbose:
                print(f"Query: {self.query}")
            return api.search(self.query)
        except shodan.exception.APIError as e:
            print(f"Shodan API error: {e}")
            return None


    def write_query_results(self, results):
        conn = sqlite3.connect("db/database.db")
        cursor = conn.cursor()

        for service in results["matches"]:
            try:
                cursor.execute(
                    "INSERT INTO ToScan (ip_addr, port) VALUES (?, ?)",
                    (service["ip_str"], self.port)
                )
                conn.commit()
            except sqlite3.IntegrityError as e:
                # unique contraint will fail, expected
                pass

        conn.close()


    def validate_ip(self, ip_string):
        try:
            ipaddress.ip_address(ip_string)
            return True
        except ValueError:
            return False


    def validate_port(self, port):
        try:
            port = int(port)
            return 0 < port <= 65535
        except ValueError:
            return False


class Target(Scan):
    def __init__(self, host, port, query=None, proxy=None, verbose=False):
        super().__init__(query=query, proxy=proxy, port=port, verbose=verbose)
        self.host = host
        self.port = port
        self.verbose = verbose
        self.visited = set()
        self.targets = set()
        self.results = ""
        self.max_dirs_to_visit = 150
        self.blacklist = ["venv/", ".cache/", ".npm/", "site-packages/", ".cargo/", ".rustup/", ".nvm/"]


    def do_scan(self):
        # we enforce unique entries in schema, provide second validation
        if self.host not in self.targets:
            try:
                url = f"http://{self.host}:{self.port}/"
                r = self.session.get(url, timeout=10)
                print(f"{url} --> Status Code: {r.status_code}")
                self.parse_html(r.content, base_path="")
                self.write_directories_to_db(self.results)
                self.delete_scan_request()
            except (ConnectionError, Timeout, RequestException):
                print(Fore.RED + f"{self.host} not responsive" + Fore.RESET)
        self.targets.add(self.host)

    def do_scan_directory(self, target_uri):
         # 100 directories gives us a good idea of dir contents, recusion protection
        if len(self.visited) > self.max_dirs_to_visit:
            return

        visit_key = target_uri.strip("/")

        if visit_key in self.visited:
            return
        self.visited.add(visit_key)

        try:
            url = f"http://{self.host}:{self.port}/{target_uri}"
            r = self.session.get(url, timeout=10)
            print(f"{url} --> Status Code: {r.status_code}")
            self.parse_html(r.content, base_path=target_uri)
        except (ConnectionError, Timeout, RequestException):
            print(Fore.RED + f"{self.host}/{target_uri} not responsive" + Fore.RESET)


    def parse_html(self, content, base_path):
        soup = BeautifulSoup(content.decode("utf-8", errors="ignore"), "html.parser")

        for li in soup.find_all("li"):
            a = li.find("a")
            if not a:
                continue

            href = a.get("href")
            if not href or href in ("../", "./"):
                continue

            full_path = urljoin(f"/{base_path}", href).lstrip("/")
            print(full_path)
            self.results += full_path + "\n"

            self.keyword_search(full_path)
            self.keyword_search_full_words(full_path)

            if href.endswith("/") and href not in self.blacklist:
                self.do_scan_directory(full_path)


    def write_directories_to_db(self, data: str):
        try:
            conn = sqlite3.connect("db/database.db")
            cursor = conn.cursor()
            results = base64.b64encode(self.results.encode("utf-8"))
            dt = datetime.now()
            sql_datetime = dt.strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute("INSERT INTO Targets (ip_addr, port, scan_date, results) VALUES (?, ?, ?, ?)",
            (self.host, self.port, sql_datetime, results))
            conn.commit()
        except sqlite3.IntegrityError as e:
                print(e)
                pass
        conn.close()  

    def delete_scan_request(self):
        try:
            conn = sqlite3.connect("db/database.db")
            cursor = conn.cursor()
            cursor.execute("DELETE FROM ToScan WHERE ip_addr = ?", (self.host,))
            conn.commit()
        except sqlite3.IntegrityError as e:
            print(e)
            pass
        conn.close()  

    def keyword_search_full_words(self, path: str):
        path_parts = path.split("/")
        if len(path_parts) == 0:
            return 
        for keyword in full_word_match:
            if keyword.lower() in path_parts:
                with open("output.log", "a") as fp:
                    fp.write(f"{self.host}:{self.port}\n")
                    fp.write(f"DETECTED: {keyword}\n")
                    fp.write(f"{path}\n\n")
                return


    def keyword_search(self, path: str):
        for keyword in merged_list:
            if keyword.lower() in path.lower():
                with open("output.log", "a") as fp:
                    fp.write(f"{self.host}:{self.port}\n")
                    fp.write(f"DETECTED: {keyword}\n")
                    fp.write(f"{path}\n\n")
                return


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


def main(args):
    banner()

    session = requests.Session()
    if args.tor:
        session.proxies.update({
            "http":  f"socks5h://{args.tor}",
            "https": f"socks5h://{args.tor}",
        })
    opsec_check(session)

    if args.query:
        Scan(
            query=f'Title:"Directory listing for /" port:{args.port}',
            proxy=args.tor,
            port=args.port,
            verbose=args.verbose
        )

    if args.scan:
        get_targets(args.tor, args.verbose)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="Data Scraper",
        description="Query Shodan for indexable HTTP servers and enumerate exposed files"
    )

    action_group = parser.add_mutually_exclusive_group(required=True)
    action_group.add_argument("-q", "--query", action="store_true")
    action_group.add_argument("-s", "--scan", action="store_true")

    parser.add_argument("-t", "--tor", help="SOCKS proxy ip:port", default=None)
    parser.add_argument("-p", "--port", help="Target port", required=True)
    parser.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args()
    main(args)
