#!/usr/bin/python3
import argparse
import ipaddress
import paramiko
import posixpath
import stat
import os

class Target:
    def __init__(self, host, port, username, password=None, key=None):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.key = key

    def create_client(self):
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            return client

    def connect_password(self, client: paramiko.SSHClient):
        try:
            client.connect(
                hostname=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                timeout=10,
                compress=True,
                look_for_keys=False
            )
            self.start_directory_walk(client)
        except paramiko.ssh_exception.AuthenticationException:
            print("[-] authentication failed")
        except paramiko.ssh_exception.SSHException as e:
            print(f"[-] Error: {e}")

    def connect_key(self, client: paramiko.SSHClient):
        try:
            client.connect(
                hostname=self.host,
                port=self.port,
                username=self.username,
                key_filename=self.key,
                timeout=10,
                compress=True,
                look_for_keys=False
            )
            self.start_directory_walk(client)
        except paramiko.ssh_exception.SSHException as e:
            print("[-] authentication failed")

    def start_directory_walk(self, client: paramiko.SSHClient):
        sftp = client.open_sftp()
        self.walk_sftp(sftp, "/")
        sftp.close()
        client.close()

    def walk_sftp(self, sftp, path):
        try:
            for entry in sftp.listdir_attr(path):
                full_path = posixpath.join(path, entry.filename)

                if stat.S_ISDIR(entry.st_mode):
                    print(f"[DIR ] {full_path}")
                    self.walk_sftp(sftp, full_path)
                else:
                    print(f"[FILE] {full_path}")

        except PermissionError:
            print(f"[DENIED] {path}")

def validate_ip(ip_string):
    """
    Validate the ip address to ensure it is well formed
    """
    try:
        ipaddress.ip_address(ip_string)
        return True
    except ValueError:
        return False

def validate_port(port):
    """
    Ensure the provided port is within the valid range
    """
    try:
        port = int(port)
        return 0 < port <= 65535
    except ValueError:
        return False

def validate_key_path(key_path):
    if os.path.exists(key_path):
        return True
    return False

def main(args):
    if not validate_ip(args.ip_addr):
        print(f"[-] Invalid ip address provided: {args.ip_addr}")
        return
    if not validate_port(args.port):
        print(f"[-] Invalid port provided: {port}")
        return
    
    if args.password:
        target = Target(args.ip_addr, args.port, args.username, args.password)
        client = target.create_client()
        target.connect_password(client)
    if args.key:
        if not validate_key_path(args.key):
            print(f"[-] No such file or directory: {args.key}")
            return 
        target = Target(args.ip_addr, args.port, args.username, args.key)
        client = target.create_client()
        target.connect_key(client)


if __name__ == '__main__':
    opts = argparse.ArgumentParser(description="Tool to walk directories in a remote host")
    opts.add_argument("-i", "--ip_addr", help="The ip address to connect to", required=True, type=str)
    opts.add_argument("-p", "--port", help="The remote port to connect to [Default: 22]", default=22, required=True)
    opts.add_argument("-u", "--username", help="The username to use on the remote host", required=True, type=str)
    authentication_group = opts.add_mutually_exclusive_group(required=True)
    authentication_group.add_argument("-P", "--password", help="The password to use", type=str)
    authentication_group.add_argument("-k", "--key", help="The private key to use", type=str)

    args = opts.parse_args()

    main(args)
