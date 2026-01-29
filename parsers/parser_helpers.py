#!/usr/bin/python3
"""Helper functions for file and directory operations in parsers."""
import ipaddress
import os
from pathlib import Path


def get_directories(dir_path_root: str):
    """List all files and directories recursively from the given root."""
    p = Path(dir_path_root)
    return list(p.rglob("*"))


def test_ipaddress(address: str):
    """Validate if the given string is a valid IP address."""
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False


def test_directory(posix_path: Path) -> bool:
    """Check if the given path is a directory."""
    return posix_path.is_dir()


def ensure_downloads():
    """Check if the downloads directory exists."""
    return os.path.isdir("downloads")

