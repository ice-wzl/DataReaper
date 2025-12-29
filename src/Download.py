import requests
import os
import sqlite3

from requests.exceptions import ConnectionError, Timeout, RequestException

from src.Scan import Scan

class Download(Scan):
    def __init__(self, host, port, path, proxy=None, verbose=False):
        super().__init__(proxy=proxy, port=port, verbose=verbose)
        self.host = host
        self.port = port
        self.path = path
        self.max_dirs_to_visit = 150 # recurse protection
        self.download_directory = os.path.join(os.getcwd(), "downloads")

    def setup_download_directory(self):
        if not os.path.exists(self.download_directory):
            os.mkdir(self.download_directory)

    def setup_host_download_directory(self):
        if not os.path.exists(os.path.join(self.download_directory, self.host)):
            os.mkdir(os.path.join(self.download_directory, self.host))

    def rebuild_directories(self):
        if "/" not in self.path:
            return
        
        directories_to_create = self.path.split("/")
        download_directory_root = os.path.join(self.download_directory, self.host)
        directories_to_create.pop() # remove the last entry which is the file
        directory_chain = []
        for i in directories_to_create:
            directory_chain.append(i)
            if not os.path.exists(download_directory_root + "/" + '/'.join(directory_chain)):
                os.mkdir(download_directory_root + "/" + '/'.join(directory_chain))


    def do_download(self) -> str:
        self.setup_download_directory()
        self.setup_host_download_directory()
        try:
            url = f"http://{self.host}:{self.port}/"
            r = self.session.get(url + self.path, timeout=10)
            print(f"{url + self.path} --> Status Code: {r.status_code}")
            
            self.rebuild_directories()
            
            if self.path.endswith("/"): # we know its a directory
                return    

            self.write_download_data(r.content.decode("utf-8", errors="ignore"))
        except (ConnectionError, Timeout, RequestException):
            print(Fore.RED + f"{url + self.path} not responsive" + Fore.RESET)

        finally:
            self.delete_download_request()

    def write_download_data(self, content: str):
        with open(self.download_directory + "/" + self.host + "/" + self.path, "w") as fp:
            fp.write(content)

    def delete_download_request(self):
        try:
            conn = sqlite3.connect("db/database.db")
            cursor = conn.cursor()
            cursor.execute("DELETE FROM DownloadTargets WHERE ip_addr = ?", (self.host,))
            conn.commit()
        except sqlite3.IntegrityError as e:
            print(e)
            pass
        conn.close()


