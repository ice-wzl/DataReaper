"""Database parser for processing and exporting scan results."""
import argparse
import base64
import os
import sqlite3

from datetime import date

BASE_DIR = os.getcwd()
output_dir = os.path.join(BASE_DIR, "scan_results")
DB_PATH = os.path.join(BASE_DIR, "db", "database.db")

def exec_query(query: str) -> list:
    """Execute a SQL query and return results."""
    try:
        conn = sqlite3.connect(DB_PATH)
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

def parse_data_targets(targets: list, apply_filter: bool) -> None:
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
        write_output(entry, os.path.join(output_dir, f"targets_output_{get_current_date()}.log"))

def write_output(data: str, file_name: str) -> None:
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

def get_current_date()-> date:
    return date.today()

def ensure_output_dir():
    if os.path.isdir(output_dir):
        return
    os.mkdir(output_dir)

def get_todays_scan() -> None:
    print(f'SELECT * FROM Targets WHERE scan_date LIKE "{get_current_date()}%"')
    target_results = get_query_results(f'SELECT * FROM Targets WHERE scan_date LIKE "{get_current_date()}%"')
    parse_data_targets(target_results, False)

def db_parser_main(apply_filter: bool, today_only: bool) -> None:
    """Main entry point for database parsing."""
    # problem for cron job 
    count = ensure_targets()
    if count == 0:
        print("[-] No results in the Target table, nothing to parse")
        return
    ensure_output_dir()
    if today_only:
        get_todays_scan()
    else:
        targets = get_query_results("SELECT * FROM Targets")
        if apply_filter:
            parse_data_targets(targets, True)
        else:
            parse_data_targets(targets, False)


if __name__ == '__main__':
    opts = argparse.ArgumentParser(description="A short script to parse out what DataReaper has been seeing")
    opts.add_argument("-f", "--filter", help="Filter out common junk that we dont usually care about", action="store_true")
    opts.add_argument("-t", "--today", help="Only parse out open directory listings from today", action="store_true")
    args = opts.parse_args()

    if args.filter:
        db_parser_main(True, False)
    elif args.today:
        db_parser_main(False, True)
    else:
        db_parser_main(False, False)
