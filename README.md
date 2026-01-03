# DataReaper (DARE)

<p align="center">
  <img src="https://github.com/ice-wzl/DataReaper/assets/75596877/c537207c-1d48-4766-b7e3-91a1f896ec04"/>
</p>

DataReaper is a Python-based reconnaissance tool designed to discover and enumerate publicly accessible HTTP servers with directory listings exposed. It leverages the Shodan API to identify targets and performs automated directory traversal to catalog exposed files and directories.

## Features

- **Shodan Integration**: Query Shodan for HTTP servers with open directory listings and store results in a local SQLite database
- **Automated Enumeration**: Recursively scan and catalog exposed directories and files
- **Proxy Support**: Route traffic through a SOCKS proxy (such as Tor) for anonymized scanning
- **Sensitive File Detection**: Built-in detection for security-relevant files including SSH keys, credentials, configuration files, and more
- **Report Generation**: Generates per-target log files documenting all discovered paths

## Requirements

- Python 3.6 or higher
- A paid Shodan API membership (required for API access)
- Optional: Tor (for anonymous scanning)

## Installation

### Step 1: Clone the Repository

```
git clone https://github.com/ice-wzl/DataReaper.git
cd DataReaper
```

### Step 2: Create a Virtual Environment

It is recommended to use a virtual environment to isolate dependencies.

**Linux/macOS:**
```
python3 -m venv venv
source venv/bin/activate
```

**Windows:**
```
python -m venv venv
venv\Scripts\activate
```

### Step 3: Install Dependencies

```
pip install -r requirements.txt
```

### Step 4: Configure Your Shodan API Key

1. Log in to your Shodan account at https://shodan.io
2. Navigate to your account page to obtain your API key
3. Create a file named `api.txt` in the DataReaper directory
4. Paste your API key as the only content in the file

```
echo "YOUR_API_KEY_HERE" > api.txt
```

### Step 5: Initialize the Database
This has already been done for you, including it here if you ever need to create a new database.
The database schema is located in `db/schema.sql`. If the database does not already exist or you need to reinitialize it:

```
sqlite3 db/database.db < db/schema.sql
```

On Windows (using SQLite command line):
```
sqlite3 db/database.db ".read db/schema.sql"
```

## Usage

DataReaper operates in two primary modes: **query mode** and **scan mode**.

### Command Syntax

```
python DataReaper.py [-h] (-q | -s) [-t TOR] -p PORT [-v]
```

### Arguments

| Argument | Description |
|----------|-------------|
| `-q`, `--query` | Query Shodan for targets with directory listings on the specified port |
| `-s`, `--scan` | Scan all targets stored in the database |
| `-p PORT`, `--port PORT` | Target port number (required) |
| `-t IP:PORT`, `--tor IP:PORT` | SOCKS proxy address for anonymized requests (e.g., `127.0.0.1:9050` for Tor) |
| `-v`, `--verbose` | Enable verbose output |

Note: The `-q` and `-s` options are mutually exclusive. You must choose one per execution.

### Workflow

**1. Query Shodan for Targets**

First, query Shodan to populate your database with potential targets:

```
python DataReaper.py -q -p 8000
```

This searches Shodan for servers on port 8000 with exposed directory listings and stores the results in the SQLite database.

**2. Scan the Discovered Targets**

After populating the database, scan the targets to enumerate their exposed files:

```
python DataReaper.py -s -p 8000
```

### Using Tor for Anonymity

To route your traffic through Tor, first ensure Tor is running on your system.

**Linux:**
```
sudo apt install tor
sudo systemctl start tor
```

**Windows:**

Download and install the Tor Expert Bundle from https://www.torproject.org/download/tor/

Then run DataReaper with the `-t` flag pointing to your Tor SOCKS proxy:

```
python DataReaper.py -s -p 8000 -t 127.0.0.1:9050
```

### Examples

Query Shodan for servers on port 80 and store results:
```
python DataReaper.py -q -p 80
```

Scan stored targets on port 8000 through Tor with verbose output:
```
python DataReaper.py -s -p 8000 -t 127.0.0.1:9050 -v
```

Query Shodan for servers on port 443:
```
python DataReaper.py -q -p 443
```

## Output

- **Database**: Target IPs and ports are stored in `db/database.db`
- **Reports**: Scan results are saved as log files in the `reports/` directory, named by target IP (e.g., `reports/192.168.1.1.log`)

Each report file contains a list of all discovered paths on that target.

## Detected File Types

DataReaper includes built-in detection for security-sensitive files and directories, including:

- SSH keys (`id_rsa`, `id_ed25519`, `id_ecdsa`, etc.)
- AWS credentials (`.aws`)
- Git repositories and credentials (`.git`, `.git-credentials`)
- Certificate files (`.pem`, `.pfx`, `.p12`, `.crt`, `.key`)
- Shell history files (`.bash_history`, `.python_history`)
- System directories (`/etc`, `/home`, `/root`)
- Password files (`passwd`, `shadow`)
- Common offensive security tools directories

## Disclaimer

DataReaper is intended for authorized security research and educational purposes only. Users are solely responsible for ensuring they have proper authorization before scanning any systems. Unauthorized access to computer systems is illegal. The authors assume no liability for misuse of this tool.

## Resources

- Shodan API Documentation: https://developer.shodan.io/api
- Python Requests Library: https://docs.python-requests.org/
- Tor Project: https://www.torproject.org/

## License

See the LICENSE file for details.

## Authors

- Aznable
- ice-wzl
