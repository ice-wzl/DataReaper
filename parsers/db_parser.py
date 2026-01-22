import argparse
import base64
import sqlite3
import os
import sys

def confirm_removal():
    targets_file = os.path.join(os.getcwd(), "targets_output.log")
    download_file = os.path.join(os.getcwd(), "download_output.log")
    if os.path.exists(targets_file):
        choice = input(f"{targets_file} detected from past run, remove [Y/n]: ")
        
        if choice.lower() in ("y", "yes", ""):
            os.remove(targets_file)
        elif choice.lower() in ("n", "no"):
            pass
        else:
            confirm_removal()
    if os.path.exists(download_file):
        choice = input(f"{download_file} detected from past run, remove [Y/n]: ")
        if choice.lower() in ("y", "yes", ""):
            os.remove(download_file)
        elif choice.lower() in ("n", "no"):
            pass
        else:
            confirm_removal()

def exec_query(query: str) -> list:
    try:
        conn = sqlite3.connect("db/database.db")
        cursor = conn.cursor()
        cursor.execute(query)
        results = cursor.fetchall()
        return results
    except Exception as e:
        print(f"Error: {e}")
        return []

def get_db_file(query: str) -> list:
    try:
        target_results = exec_query(query)
        return target_results
    except Exception as e:
        print(f"Error: {e}")


def parse_data_targets_with_filter(list_of_files: list) -> str:
    black_list_filter = ["html", "js", "jpg", "ts", "svg"]
    known_good = ''
    for entry in list_of_files:
        # file attributes
        if "/" in entry and "." in entry:
            try:
                file_ext = entry.split(".")[-1]
                if file_ext in black_list_filter:
                    continue
                known_good += entry + "\n"
            except Exception as e:
                print(f"Error processing filter: {e}")
    return known_good


def parse_data_targets(targets: list, filter: bool):
    for target in targets:
        entry = ''
        (_, ip_addr, port, date_seen, data_based) = target
        data = base64.b64decode(data_based)
        entry += f"{ip_addr}:{port}\n"
        entry += f"DATE SEEN: {date_seen}\n"
        if filter:
            list_of_files = data.decode("utf-8").split("\n")
            entry += parse_data_targets_with_filter(list_of_files) + "\n"
        else:
            entry += f"{data.decode("utf-8")}\n\n"
        write_output(entry, "targets_output.log")


def parse_data_download_targets(targets: list):
    for target in targets:
        entry = ''
        (_, ip_addr, port, keyword, path) = target
        entry += f"{ip_addr}:{port}\n"
        entry += f"Keyword match: {keyword}\n"
        entry += f"Path: {path}\n\n"
        write_output(entry, "download_output.log")


def write_output(data: str, file_name: str):
    with open(file_name, "a") as fp:
        fp.write(data + "\n")

def ensure_targets() -> int:
    # ensure there is more than 1 result in the Targets table
    target_count = get_db_file("SELECT COUNT(ip_addr) FROM Targets")
    if isinstance(target_count, list) and len(target_count) > 0:
        count, = target_count[0]
        return count
    return 0


def db_parser_main(filter: bool):
    confirm_removal()
    count = ensure_targets()
    if count == 0:
        print("[-] No results in the Target table, nothing to parse")
        return

    targets = get_db_file("SELECT * FROM Targets")
    if filter:
        parse_data_targets(targets, True)
    else:
        parse_data_targets(targets, False)
    
    download_targets = get_db_file("SELECT * FROM DownloadTargets")
    parse_data_download_targets(download_targets)


if __name__ == '__main__':
    opts = argparse.ArgumentParser(description="A short script to parse out what DataReaper has been seeing")
    opts.add_argument("-f", "--filter", help="Filter out common junk that we dont usually care about", action="store_true")
    args = opts.parse_args()

    if args.filter:
        db_parser_main(True)
    else:
        db_parser_main(False)
