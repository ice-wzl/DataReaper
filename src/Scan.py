"""Class called Scan which handles retrieving of the api key and making a query request to the Shodan api"""
import ipaddress
import sys
import shodan
import sqlite3
import requests

class Scan:
    """
    Scan class for querying the shodan api and setting up the scanning session
    """
    def __init__(self, proxy=None, port=None, verbose=False):
        self.proxy = proxy
        self.port = port
        self.verbose = verbose

        # session setup ONLY
        self.session = requests.Session()
        if self.proxy is not None:
            self.session, err = self.session_tor_setup(self.proxy)
            if not self.session:
                raise RuntimeError(err)

    def run_query(self, query):
        api, err = self.setup_api()
        if api is None:
            raise RuntimeError(err)

        if self.verbose:
            print(f"Query: {query}")

        results = self.do_query(api, query)
        if results is not None:
            self.write_query_results(results)

    def session_tor_setup(self, socks_proxy_host_port):
        """
        Set up a tor session by updating the proxy values in the session
        """
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
        """
        Get the api key from the file in order to query the api later
        """
        try:
            with open("api.txt", "r") as fp:
                api_key = fp.read().strip()
                if self.verbose:
                    print(f"API key used: {api_key}")
            return shodan.Shodan(api_key), ""
        except FileNotFoundError:
            return None, "api.txt not found"

    def do_query(self, api, query):
        try:
            if self.verbose:
                print(f"Query: {query}")
            return api.search(query)
        except shodan.exception.APIError as e:
            print(f"Shodan API error: {e}")
            return None


    def write_query_results(self, results):
        """
        Insert the returned results in the database, only grab the ip and port
        from the Shodan returned results.
        """
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
        """
        Validate the ip address to ensure it is well formed
        """
        try:
            ipaddress.ip_address(ip_string)
            return True
        except ValueError:
            return False


    def validate_port(self, port):
        """
        Ensure the provided port is within the valid range
        """
        try:
            port = int(port)
            return 0 < port <= 65535
        except ValueError:
            return False