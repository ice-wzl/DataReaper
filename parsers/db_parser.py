"""Database parser for processing and exporting scan results."""
import argparse
import base64
import os
import sqlite3

def confirm_removal():
    """Prompt user to remove output files from previous runs."""
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
    """Execute a SQL query and return results."""
    try:
        conn = sqlite3.connect("db/database.db")
        cursor = conn.cursor()
        cursor.execute(query)
        results = cursor.fetchall()
        return results
    except Exception as e:
        print(f"Error: {e}")
        return []

def get_query_results(query: str) -> list:
    """Get query results with error handling."""
    try:
        return exec_query(query)
    except sqlite3.Error as err:
        print(f"Error: {err}")
        return []

def parse_data_targets_with_filter(list_of_files: list) -> str:
    """Filter out common file types we don't care about."""
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
            except (IndexError, ValueError) as err:
                print(f"Error processing filter: {err}")
    return known_good

def parse_data_targets(targets: list, apply_filter: bool):
    for target in targets:
        entry = ''
        (_, ip_addr, port, date_seen, data_based) = target
        data = base64.b64decode(data_based)
        entry += f"{ip_addr}:{port}\n"
        entry += f"DATE SEEN: {date_seen}\n"
        if apply_filter:
            list_of_files = data.decode("utf-8").split("\n")
            entry += parse_data_targets_with_filter(list_of_files) + "\n"
        else:
            entry += f"{data.decode("utf-8")}\n\n"
        write_output(entry, "targets_output.log")

def write_output(data: str, file_name: str):
    """Append data to the specified output file."""
    with open(file_name, "a", encoding="utf-8") as fp:
        fp.write(data + "\n")

def ensure_targets() -> int:
    """Return count of targets in the database."""
    target_count = get_query_results("SELECT COUNT(ip_addr) FROM Targets")
    if isinstance(target_count, list) and len(target_count) > 0:
        count, = target_count[0]
        return count
    return 0

def db_parser_main(apply_filter: bool):
    """Main entry point for database parsing."""
    confirm_removal()
    count = ensure_targets()
    if count == 0:
        print("[-] No results in the Target table, nothing to parse")
        return

    targets = get_query_results("SELECT * FROM Targets")
    if apply_filter:
        parse_data_targets(targets, True)
    else:
        parse_data_targets(targets, False)


if __name__ == '__main__':
    opts = argparse.ArgumentParser(description="A short script to parse out what DataReaper has been seeing")
    opts.add_argument("-f", "--filter", help="Filter out common junk that we dont usually care about", action="store_true")
    args = opts.parse_args()

    if args.filter:
        db_parser_main(True)
    else:
        db_parser_main(False)
