# DataReaper (DARE)

<p align="center">
  <img src="https://github.com/ice-wzl/DataReaper/assets/75596877/c537207c-1d48-4766-b7e3-91a1f896ec04"/>
</p>

> **Disclaimer:** DataReaper is intended for authorized security research and educational purposes only. Users are solely responsible for ensuring they have proper authorization before scanning any systems. Unauthorized access to computer systems is illegal. The authors assume no liability for misuse of this tool.

DataReaper is a Python-based reconnaissance tool designed to discover and enumerate publicly accessible HTTP servers with directory listings exposed. It leverages the Shodan API to identify targets, performs automated directory traversal to catalog exposed files, downloads sensitive content, and can exploit discovered SSH keys to access remote hosts.

## Features

- **Shodan Integration**: Query Shodan for HTTP servers with open directory listings and store results in a local SQLite database
- **Automated Enumeration**: Recursively scan and catalog exposed directories and files
- **Sensitive File Detection**: Built-in detection for security-relevant files including SSH keys, credentials, configuration files, and more
- **Automated File Download**: Download files matching keyword lists from discovered targets
- **SSH Key Exploitation**: Parse downloaded SSH keys and public key files to extract usernames, then attempt SSH access against targets
- **Bash History Parsing**: Extract potential usernames from downloaded `.bash_history` files for use during SSH exploitation
- **Shadow File Processing**: Extract password hashes from downloaded `/etc/shadow` files and store them for offline cracking
- **Survey Logging**: SSH walker logs full directory trees of accessed hosts to per-IP log files with timestamps
- **Scan Result Export**: Export and filter database scan results to dated log files
- **Proxy Support**: Route traffic through a SOCKS proxy (such as Tor) for anonymized scanning
- **Noninteractive Mode**: Skip all prompts for automated or scheduled execution

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

DataReaper operates in five modes: **query**, **scan**, **exploit**, **shadow**, and **process targets**.

### Command Syntax

```
python DataReaper.py [-h] (-q | -s | -e | -sh | -pt) [-t TOR] [-p PORT] [-n] [-v]
```

### Arguments

| Argument | Description |
|----------|-------------|
| `-q`, `--query` | Query Shodan for targets with directory listings on the specified port |
| `-s`, `--scan` | Scan all targets stored in the database and download matching files |
| `-e`, `--exploit` | Test downloaded SSH keys against discovered targets |
| `-sh`, `--shadow` | Process downloaded shadow files and extract password hashes |
| `-pt`, `--process_targets` | Export scan results from the database to log files |
| `-p PORT`, `--port PORT` | Target port number (required for query mode) |
| `-t IP:PORT`, `--tor IP:PORT` | SOCKS proxy address for anonymized requests (e.g., `127.0.0.1:9050`) |
| `-n`, `--noninteractive` | Run without prompts (skips IP confirmation and warnings) |
| `-v`, `--verbose` | Enable verbose output |

Note: The `-q`, `-s`, `-e`, `-sh`, and `-pt` options are mutually exclusive. You must choose one per execution.

### Workflow

**1. Query Shodan for Targets**

Query Shodan to populate your database with potential targets:

```
python DataReaper.py -q -p 8000
```

This searches Shodan for servers on port 8000 with exposed directory listings and stores the results in the SQLite database.

**2. Scan and Download from Targets**

Scan the discovered targets to enumerate their exposed files and automatically download anything matching the built-in keyword lists:

```
python DataReaper.py -s -p 8000
```

Downloaded files are saved to `downloads/` organized by target IP.

**3. Exploit Discovered SSH Keys**

After downloading files, attempt to authenticate to targets using any discovered SSH keys. DataReaper extracts usernames from public key files and bash history, then tries each key/username combination:

```
python DataReaper.py -e -t 127.0.0.1:9050
```

Without a proxy, you will be warned before connecting directly. Successfully accessed hosts are logged to the database and the SSH walker performs a full directory enumeration, writing results to `survey_results/`.

**4. Process Shadow Files**

Extract password hashes from any downloaded `/etc/shadow` files:

```
python DataReaper.py -sh
```

Hashes are written to `hashes.txt` and stored in the database for offline cracking.

**5. Export Scan Results**

Export scan results from the database to dated log files in `scan_results/`:

```
python DataReaper.py -pt
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

Query Shodan for servers on port 80:
```
python DataReaper.py -q -p 80
```

Scan stored targets through Tor with verbose output:
```
python DataReaper.py -s -p 8000 -t 127.0.0.1:9050 -v
```

Exploit downloaded SSH keys through Tor:
```
python DataReaper.py -e -t 127.0.0.1:9050
```

Export scan results without prompts:
```
python DataReaper.py -pt -n
```

Process shadow files:
```
python DataReaper.py -sh
```

## Output

- **Database**: All target data, scan results, download records, accessed hosts, and extracted hashes are stored in `db/database.db`
- **Downloads**: Files downloaded from targets are saved in `downloads/`, organized by IP address
- **Scan Results**: Exported scan data is saved to `scan_results/` as dated log files (e.g., `targets_output_2026-04-07.log`)
- **Survey Results**: SSH walker directory enumerations are saved to `survey_results/` as per-IP dated log files (e.g., `192.168.1.1_survey_2026-04-07.log`)
- **Hashes**: Extracted shadow file hashes are written to `hashes.txt`
- **Runtime Log**: Each execution is timestamped in `runtime.log`

## Detected File Types

DataReaper includes built-in detection for security-sensitive files and directories, including:

- SSH keys (`id_rsa`, `id_ed25519`, `id_ecdsa`, etc.)
- AWS credentials (`.aws`)
- Git repositories and credentials (`.git`, `.git-credentials`)
- Certificate files (`.pem`, `.pfx`, `.p12`, `.crt`, `.key`)
- Shell history files (`.bash_history`, `.zsh_history`, `.python_history`)
- System directories (`/home`, `/root`)
- Password files (`passwd`, `shadow`)
- Configuration files (`.env`, `config.yaml`, `docker-compose.yml`, Wireguard configs)
- Offensive security tools (Cobalt Strike, Metasploit, Sliver, Havoc, Mythic, etc.)
- Malware artifacts (ransomware, stealers, droppers, crypters)

## SSH Walker

The SSH walker (`executors/ssh_walker.py`) can also be used as a standalone tool for SSH directory enumeration:

```
python executors/ssh_walker.py -i <IP> -p <PORT> -u <USERNAME> (-P <PASSWORD> | -k <KEY>)
```

| Argument | Description |
|----------|-------------|
| `-i`, `--ip_addr` | Target IP address |
| `-p`, `--port` | Remote SSH port (default: 22) |
| `-u`, `--username` | Username for authentication |
| `-P`, `--password` | Password for authentication |
| `-k`, `--key` | Path to private key file |

The walker performs a full SFTP directory enumeration while skipping noisy system directories (`/proc`, `/sys`, `/snap`, `/dev`, `/usr/share`, `/usr/src`, `/usr/snap`). Results are logged to `survey_results/`.

## Database Parser

The database parser (`parsers/db_parser.py`) can also be run standalone to export scan results:

```
python parsers/db_parser.py [-f] [-t]
```

| Argument | Description |
|----------|-------------|
| `-f`, `--filter` | Filter out common junk file types (html, js, jpg, ts, svg) |
| `-t`, `--today` | Only export results from today's scans |

## Disclaimer

DataReaper is intended for authorized security research and educational purposes only. Users are solely responsible for ensuring they have proper authorization before scanning any systems. Unauthorized access to computer systems is illegal. The authors assume no liability for misuse of this tool.

## Resources

- Shodan API Documentation: https://developer.shodan.io/api
- Python Requests Library: https://docs.python-requests.org/
- Tor Project: https://www.torproject.org/

## License

See the LICENSE file for details.

