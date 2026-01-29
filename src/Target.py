"""Target module for scanning and parsing individual HTTP servers.

Protects against blacklisted directories and implements recursion protection.
"""
import base64
import sqlite3
from datetime import datetime
from urllib.parse import urljoin

from bs4 import BeautifulSoup
from colorama import Fore
from requests.exceptions import Timeout, RequestException

from src.Scan import Scan
from src.helper import merged_list, full_word_match


class Target(Scan):
    def __init__(self, host, port, proxy=None, verbose=False): # lizard: ignore
        super().__init__(proxy=proxy, port=port, verbose=verbose)

        self.host = host
        self.port = port
        self.verbose = verbose

        self.visited = set()
        self.results = ""
        self.max_dirs_to_visit = 150
        self.blacklist = [
            "dev/", "venv/", ".cache/", ".npm/", "site-packages/",
            ".cargo/", ".rustup/", ".nvm/", "X11/"
        ]

    def do_scan(self):
        try:
            url = f"http://{self.host}:{self.port}/"
            r = self.session.get(url, timeout=10)
            print(f"{url} --> Status Code: {r.status_code}")

            self.parse_html(r.content, base_path="")
            self.write_directories_to_db()

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
            print(Fore.RED + f"{self.host}:{self.port}/{target_uri} not responsive" + Fore.RESET)


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


    def write_directories_to_db(self):
        """Write scan results to the database."""
        try:
            conn = sqlite3.connect("db/database.db")
            cursor = conn.cursor()
            results = base64.b64encode(self.results.encode("utf-8"))
            dt = datetime.now()
            sql_datetime = dt.strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute(
                "INSERT INTO Targets (ip_addr, port, scan_date, results) VALUES (?, ?, ?, ?)",
                (self.host, self.port, sql_datetime, results)
            )
            conn.commit()
        except sqlite3.IntegrityError as err:
            print(err)
        conn.close()  

    def delete_scan_request(self):
        """Remove the current host from the ToScan table."""
        try:
            conn = sqlite3.connect("db/database.db")
            cursor = conn.cursor()
            cursor.execute("DELETE FROM ToScan WHERE ip_addr = ?", (self.host,))
            conn.commit()
        except sqlite3.IntegrityError as err:
            print(err)
        conn.close()

    def keyword_search_full_words(self, path: str):
        """Search for exact keyword matches in path components."""
        path_parts = path.split("/")
        if len(path_parts) == 0:
            return
        for keyword in full_word_match:
            if keyword.lower() in path_parts:
                try:
                    conn = sqlite3.connect("db/database.db")
                    cursor = conn.cursor()
                    cursor.execute(
                        "INSERT INTO DownloadTargets (ip_addr, port, keyword, path) VALUES (?, ?, ?, ?)",
                        (self.host, self.port, keyword, path)
                    )
                    conn.commit()
                except sqlite3.IntegrityError:
                    pass
                finally:
                    conn.close()
                break

    def keyword_search(self, path: str):
        """Search for partial keyword matches in the path."""
        for keyword in merged_list:
            if keyword.lower() in path.lower():
                try:
                    conn = sqlite3.connect("db/database.db")
                    cursor = conn.cursor()
                    cursor.execute(
                        "INSERT INTO DownloadTargets (ip_addr, port, keyword, path) VALUES (?, ?, ?, ?)",
                        (self.host, self.port, keyword, path)
                    )
                    conn.commit()
                except sqlite3.IntegrityError:
                    pass
                finally:
                    conn.close()
                break
