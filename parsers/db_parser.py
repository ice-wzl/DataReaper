import base64
import sqlite3
import os

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
        conn = sqlite3.connect("../db/database.db")
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

def parse_data_targets(targets: list):
    for target in targets:
        entry = ''
        (_, ip_addr, port, date_seen, data_based) = target
        data = base64.b64decode(data_based)
        entry += f"{ip_addr}:{port}\n"
        entry += f"DATE SEEN: {date_seen}\n"
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




if __name__ == '__main__':
    confirm_removal()

    targets = get_db_file("SELECT * FROM Targets")
    parse_data_targets(targets)
    
    download_targets = get_db_file("SELECT * FROM DownloadTargets")
    parse_data_download_targets(download_targets)
