import base64
import sqlite3

# TODO: add in keyword searching 

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

def get_db_file() -> list:
    try:
        target_results = exec_query("SELECT * FROM Targets")
        parse_data(target_results)
    except Exception as e:
        print(f"Error: {e}")

def parse_data(targets: list):
    for target in targets:
        entry = ''
        (_, ip_addr, port, date_seen, data_based) = target
        data = base64.b64decode(data_based)
        entry += f"{ip_addr}:{port}\n"
        entry += f"DATE SEEN: {date_seen}\n"
        entry += f"{data.decode("utf-8")}\n\n"
        write_output(entry)

def write_output(data: str):
    with open("parser_output.log", "a") as fp:
        fp.write(data + "\n")


if __name__ == '__main__':
    get_db_file()