#!/usr/bin/python3
"""Shadow file processor for extracting password hashes."""
import os
import sqlite3

from parsers.parser_helpers import ensure_downloads
from parsers.parser_helpers import test_ipaddress
from parsers.parser_helpers import get_directories

def get_all_targets():
    """Get all valid IP targets from the downloads directory."""
    if not ensure_downloads():
        print("[-] No downloads directory found. Run a scan with -e first to download files.")
        return
    valid_targets = []
    for target in os.listdir("downloads"):
        if test_ipaddress(target):
            valid_targets.append(target)
    return valid_targets

def search_shadow_files(targets: list):
    """Search for shadow files in each target's downloads."""
    for target in targets:
        downloaded_files = get_directories(os.path.join("downloads", target))
        # pass to host file parser
        test_shadow_file(target, downloaded_files)

def test_shadow_file(ip_addr: str, list_files: list):
    """Check if any files are shadow files and process them."""
    for file in list_files:
        if "/" in str(file):
            file_parts = str(file).split("/")
            if file_parts[-1] == "shadow" and file_parts[-2] == "etc":
                shadow_cont = read_shadow(str(file))
                search_hashes(ip_addr, shadow_cont)

def read_shadow(shadow_file: str):
    """Read and remove shadow file, returning its contents."""
    with open(shadow_file, "r", encoding="utf-8") as fp:
        contents = fp.readlines()
        os.remove(shadow_file)
    return [x.strip() for x in contents]


def search_hashes(ip_addr: str, shadow_cont: list):
    """Extract password hashes from shadow file contents."""
    for line in shadow_cont:
        line_parts = line.split(":")
        if "!" in line_parts[1] or "*" in line_parts[1]:
            continue
        username = line_parts[0]
        pw_hash = line_parts[1]
        write_results_to_text(line)
        write_results_to_db(ip_addr, username, pw_hash)

def write_results_to_db(ip_addr: str, username: str, pw_hash: str):
    """Write hash results to the database."""
    conn = sqlite3.connect("db/database.db")
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO Hashes (ip_addr, username, hash) VALUES (?, ?, ?)",
        (ip_addr, username, pw_hash)
    )
    conn.commit()
    conn.close()


def write_results_to_text(pw_hash: str):
    """Append hash to the hashes.txt output file."""
    with open("hashes.txt", "a", encoding="utf-8") as fp:
        fp.write(pw_hash + "\n")


if __name__ == '__main__':
    valid_targets = get_all_targets()
    search_shadow_files(valid_targets)
