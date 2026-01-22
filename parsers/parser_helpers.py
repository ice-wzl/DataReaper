#!/usr/bin/python3
import os
import ipaddress
from pathlib import Path

# list all directories starting in the downloads dir 
def get_directories(dir_path_root: str):
    p = Path(dir_path_root)
    return [item for item in p.rglob("*")]

# test if ip address is valid or not
def test_ipaddress(address: str):
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

# ensure the downloads directory exists
def ensure_downloads():
    if not os.path.isdir("downloads"):
        return False
    return True
