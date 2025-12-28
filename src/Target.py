"""Class Target controls the scanning and parsing of individual targets. It will also protect the scanner from entering
into blacklisted directories, along with establishing recursion protection for the scanner. The target class controls
how the host is interacted with."""
import base64
import requests
from colorama import Fore
from datetime import datetime
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from requests.exceptions import ConnectionError, Timeout, RequestException
from urllib3.exceptions import ConnectionError

from src.Scan import Scan


class Target(Scan):
    def __init__(self, host, port, proxy=None, verbose=False):
        super().__init__(proxy=proxy, port=port, verbose=verbose)

        self.host = host
        self.port = port
        self.verbose = verbose

        self.visited = set()
        self.results = ""
        self.max_dirs_to_visit = 150
        self.blacklist = [
            "venv/", ".cache/", ".npm/", "site-packages/",
            ".cargo/", ".rustup/", ".nvm/"
        ]

    def do_scan(self):
        try:
            url = f"http://{self.host}:{self.port}/"
            r = self.session.get(url, timeout=10)
            print(f"{url} --> Status Code: {r.status_code}")

            self.parse_html(r.content, base_path="")
            self.write_directories_to_db(self.results)

        except (ConnectionError, Timeout, RequestException):
            print(Fore.RED + f"{self.host} not responsive" + Fore.RESET)

        finally:
            self.delete_scan_request()

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
        keyword_found = False
        path_parts = path.split("/")
        if len(path_parts) == 0:
            return 
        for keyword in full_word_match:
            if keyword.lower() in path_parts:
                with open("output.log", "a") as fp:
                    fp.write(f"{self.host}:{self.port}\n")
                    fp.write(f"Perfect match DETECTED: {keyword}\n")
                    fp.write(f"{path}\n\n")
                    keyword_found = True
                    break
        if keyword_found:
            try:
                conn = sqlite3.connect("db/database.db")
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO DownloadTargets (ip_addr, port) VALUES (?, ?)",
                    (self.host, self.port)
                )
                conn.commit()
            except sqlite3.IntegrityError:
                pass
            finally:
                conn.close()
        


    def keyword_search(self, path: str):
        keyword_found = False
        for keyword in merged_list:
            if keyword.lower() in path.lower():
                with open("output.log", "a") as fp:
                    fp.write(f"{self.host}:{self.port}\n")
                    fp.write(f"DETECTED: {keyword}\n")
                    fp.write(f"{path}\n\n")
                    keyword_found = True
                    break
        if keyword_found:
            try:
                conn = sqlite3.connect("db/database.db")
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO DownloadTargets (ip_addr, port) VALUES (?, ?)",
                    (self.host, self.port)
                )
                conn.commit()
            except sqlite3.IntegrityError:
                pass
            finally:
                conn.close()