#!/usr/bin/python3
"""SSH walker for connecting to and enumerating remote hosts via SSH."""
import argparse
import ipaddress
import os
import posixpath
import socket
import stat

import paramiko
import socks

class Target:
    """SSH target for connecting and enumerating remote hosts."""

    def __init__(self, proxy_host_port, host, port, username,  # lizard: ignore
                 password=None, key=None) -> None:
        self.proxy_host_port = proxy_host_port
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.key = key

    def create_client(self) -> tuple[paramiko.SSHClient(), None]:
        """Create SSH client and optional SOCKS proxy socket."""
        sock = None
        if self.proxy_host_port is not None:
            parts = self.proxy_host_port.split(":")
            sock = socks.socksocket()
            sock.set_proxy(
                proxy_type=socks.SOCKS5,
                addr=parts[0],
                port=int(parts[-1])
            )
            try:
                sock.connect((self.host, self.port))
            except socks.GeneralProxyError:
                print(f"[-] {self.host}:{self.port} - connection refused")
                return None, None

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        return client, sock

    def connect_password(self, client: paramiko.SSHClient, sock) -> bool:
        """Attempt SSH connection using password authentication."""
        try:
            if sock is not None:
                client.connect(
                hostname=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                timeout=10,
                compress=True,
                look_for_keys=False,
                sock=sock
            )
            else:
                client.connect(
                    hostname=self.host,
                    port=self.port,
                    username=self.username,
                    password=self.password,
                    timeout=10,
                    compress=True,
                    look_for_keys=False
                )
            print(f"Success with: {self.host}:{self.port} {self.username} {self.password}")
            self.start_directory_walk(client)
            return True
        except paramiko.ssh_exception.AuthenticationException:
            print(f"[-] {self.host}:{self.port} - authentication failed")
        except paramiko.ssh_exception.SSHException as e:
            print(f"[-] {self.host}:{self.port} - SSH error: {e}")
        except (socket.timeout, socket.error) as e:
            print(f"[-] {self.host}:{self.port} - connection error: {e}")
        except EOFError:
            print(f"[-] {self.host}:{self.port} - connection closed unexpectedly")
        return False

    def connect_key(self, client: paramiko.SSHClient, sock) -> bool:
        """Attempt SSH connection using key-based authentication."""
        try:
            if sock is not None:
                client.connect(
                    hostname=self.host,
                    port=self.port,
                    username=self.username,
                    key_filename=self.key,
                    timeout=10,
                    compress=True,
                    look_for_keys=False,
                    sock=sock
                )
            else:
                client.connect(
                    hostname=self.host,
                    port=self.port,
                    username=self.username,
                    key_filename=self.key,
                    timeout=10,
                    compress=True,
                    look_for_keys=False
                )
            print(f"Success with: {self.host}:{self.port} {self.username} {self.key}")
            self.start_directory_walk(client)
            return True
        except paramiko.ssh_exception.AuthenticationException:
            print(f"[-] {self.host}:{self.port} - authentication failed")
        except paramiko.ssh_exception.SSHException as e:
            print(f"[-] {self.host}:{self.port} - SSH error: {e}")
        except (socket.timeout, socket.error) as e:
            print(f"[-] {self.host}:{self.port} - connection error: {e}")
        except EOFError:
            print(f"[-] {self.host}:{self.port} - connection closed unexpectedly")
        return False

    def start_directory_walk(self, client: paramiko.SSHClient) -> None:
        """Start SFTP directory enumeration from root."""
        sftp = client.open_sftp()
        self.walk_sftp(sftp, "/")
        sftp.close()
        client.close()
    
    def ensure_output_dir():
        if os.path

    def walk_sftp(self, sftp, path) -> None:
        """Recursively walk SFTP directory tree."""
        black_list = ["/proc", "/sys", "/snap", "/dev", "/usr/share", "/usr/src", "/usr/snap"]
        try:
            for entry in sftp.listdir_attr(path):
                full_path = posixpath.join(path, entry.filename)
                if full_path in black_list:
                    continue
                if stat.S_ISDIR(entry.st_mode):
                    print(f"[DIR ] {full_path}")
                    self.walk_sftp(sftp, full_path)
                else:
                    print(f"[FILE] {full_path}")

        except PermissionError:
            print(f"[DENIED] {path}")

def validate_ip(ip_string) -> bool:
    """Validate the ip address to ensure it is well formed."""
    try:
        ipaddress.ip_address(ip_string)
        return True
    except ValueError:
        return False

def validate_port(port) -> bool:
    """Ensure the provided port is within the valid range."""
    try:
        port = int(port)
        return 0 < port <= 65535
    except ValueError:
        return False

def validate_key_path(key_path) -> bool:
    """Check if the key file exists."""
    return os.path.exists(key_path)


def main(args) -> None:
    """Main entry point for standalone SSH walker."""
    if not validate_ip(args.ip_addr):
        print(f"[-] Invalid ip address provided: {args.ip_addr}")
        return
    if not validate_port(args.port):
        print(f"[-] Invalid port provided: {args.port}")
        return

    if args.password:
        target = Target(None, args.ip_addr, args.port, args.username, args.password)
        client, sock = target.create_client()
        if sock is not None:
            target.connect_password(client, sock)
        else:
            target.connect_password(client, None)
    if args.key:
        if not validate_key_path(args.key):
            print(f"[-] No such file or directory: {args.key}")
            return
        target = Target(None, args.ip_addr, args.port, args.username, key=args.key)
        client, sock = target.create_client()
        if sock is not None:
            target.connect_key(client, sock)
        else:
            target.connect_key(client, None)


if __name__ == '__main__':
    opts = argparse.ArgumentParser(description="SSH directory walker")
    opts.add_argument("-i", "--ip_addr", required=True, type=str,
                      help="The IP address to connect to")
    opts.add_argument("-p", "--port", default=22, required=True,
                      help="Remote port [Default: 22]")
    opts.add_argument("-u", "--username", required=True, type=str,
                      help="Username for remote host")
    authentication_group = opts.add_mutually_exclusive_group(required=True)
    authentication_group.add_argument("-P", "--password", type=str,
                                      help="Password for authentication")
    authentication_group.add_argument("-k", "--key", type=str,
                                      help="Private key file path")

    args = opts.parse_args()
    main(args)
