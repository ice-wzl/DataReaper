"""Download module for retrieving files from exposed HTTP servers."""
import os
import sqlite3

from colorama import Fore
from requests.exceptions import Timeout, RequestException

from src.Scan import Scan


class Download(Scan):
    """Download handler for retrieving files from HTTP servers."""

    def __init__(self, host, port, path, proxy=None, verbose=False):  # lizard: ignore
        super().__init__(proxy=proxy, port=port, verbose=verbose)
        self.host = host
        self.port = port
        self.path = path
        self.max_dirs_to_visit = 150
        self.download_directory = os.path.join(os.getcwd(), "downloads")

    def setup_download_directory(self):
        """Create the main downloads directory if it doesn't exist."""
        if not os.path.exists(self.download_directory):
            os.mkdir(self.download_directory)

    def setup_host_download_directory(self):
        """Create host-specific subdirectory in downloads."""
        if not os.path.exists(os.path.join(self.download_directory, self.host)):
            os.mkdir(os.path.join(self.download_directory, self.host))

    def rebuild_directories(self):
        """Recreate the directory structure from the remote path."""
        if "/" not in self.path:
            return

        directories_to_create = self.path.split("/")
        download_directory_root = os.path.join(self.download_directory, self.host)
        directories_to_create.pop()
        directory_chain = []
        for i in directories_to_create:
            directory_chain.append(i)
            target_dir = download_directory_root + "/" + "/".join(directory_chain)
            if not os.path.exists(target_dir):
                os.mkdir(target_dir)

    def do_download(self) -> str:
        """Download a file from the target server."""
        self.setup_download_directory()
        self.setup_host_download_directory()
        try:
            url = f"http://{self.host}:{self.port}/"
            r = self.session.get(url + self.path, timeout=10)
            print(f"{url + self.path} --> Status Code: {r.status_code}")

            self.rebuild_directories()

            if self.path.endswith("/"):
                return

            self.write_download_data(r.content.decode("utf-8", errors="ignore"))
        except (ConnectionError, Timeout, RequestException):
            print(Fore.RED + f"{url + self.path} not responsive" + Fore.RESET)

        finally:
            self.delete_download_request()

    def write_download_data(self, content: str):
        """Write downloaded content to local file."""
        file_path = self.download_directory + "/" + self.host + "/" + self.path
        with open(file_path, "w", encoding="utf-8") as fp:
            fp.write(content)

    def delete_download_request(self):
        """Remove completed download from the queue."""
        try:
            conn = sqlite3.connect("db/database.db")
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM DownloadTargets WHERE ip_addr = ?", (self.host,)
            )
            conn.commit()
        except sqlite3.IntegrityError as err:
            print(err)
        conn.close()
