#!/usr/bin/python3
import os
import sys
import sqlite3

from parser_helpers import ensure_downloads
from parser_helpers import test_ipaddress
from parser_helpers import get_directories

def get_all_targets():
    if not ensure_downloads():
        print("[-] No downloads directory found. Run a scan with -e first to download files.")
        return
    valid_targets = []
    for target in os.listdir("downloads"):
        if test_ipaddress(target):
            valid_targets.append(target)
    return valid_targets

def search_shadow_files(targets: list):
    for target in targets:
        downloaded_files = get_directories(os.path.join("downloads", target))
        # pass to host file parser
        test_shadow_file(target, downloaded_files)


def test_shadow_file(ip_addr: str, list_files: list):
    for file in list_files:
        if "/" in str(file):
            file_parts = str(file).split("/")
            if file_parts[-1] == "shadow" and file_parts[-2] == "etc":
                shadow_cont = read_shadow(str(file))
                search_hashes(ip_addr, shadow_cont)


def read_shadow(shadow_file: str):
    with open(shadow_file, "r") as fp:
        contents = fp.readlines()
    return [x.strip() for x in contents]
 
def search_hashes(ip_addr: str, shadow_cont: list):
    for line in shadow_cont:
        line_parts = line.split(":")
        if "!" in line_parts[1] or "*" in line_parts[1]:
            continue
        username = line_parts[0]
        pw_hash = line_parts[1]
        write_results_to_text(line)
        write_results_to_db(ip_addr, username, pw_hash)


def write_results_to_db(ip_addr: str, username: str, hash: str):
    conn = sqlite3.connect("db/database.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO Hashes (ip_addr, username, hash) VALUES (?, ?, ?)", 
        (ip_addr, username, hash))
    conn.commit()
    conn.close()

def write_results_to_text(hash:str):
    with open("hashes.txt", "a") as fp:
        fp.write(hash + "\n")


if __name__ == '__main__':
    valid_targets = get_all_targets()
    search_shadow_files(valid_targets)
    
    