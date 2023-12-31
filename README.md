# DataReaper (DARE)

<p align="center">
  <img src="https://github.com/ice-wzl/DataReaper/assets/75596877/c537207c-1d48-4766-b7e3-91a1f896ec04"/>
</p>

# DataReaper (DARE): Documentation

DataReaper is a powerful Python tool designed to harvest data from publicly accessible HTTP servers. It combines the capabilities of Shodan search with web scraping techniques to efficiently gather information from targeted websites.

## Key Features:

- Shodan Integration: Queries Shodan based on specific criteria and stores results in a text file.
- Web Scraping: Extracts valuable content and links from target websites.
- Reaping: Optionally gathers subdirectories and files for deeper analysis.
- Tor Support: Anonymize your scans and protect your identity by using Tor.
- History Tracking: Maintains a history file to avoid redundant scans and save time.

## Installation:

- Python 3.6+: Ensure Python 3.6 or later is installed.

- Virtual Environment: Create a virtual environment to manage program dependencies separately from your system packages.
````
python3 -m venv venv
source venv/bin/activate
````
### Dependencies: Install required packages from requirements.txt.
````
pip3 install -r requirements.txt
````
- Non-Free Shodan Membership:
    - A paid Shodan membership is required to access the API and use this program's full functionality.
    - Create a Shodan account and upgrade to a paid plan if needed.
    - Obtain your API key from your account dashboard.
    - Create a file named api.txt in the same directory as the program.
    - Enter your API key as the only line in the file.

## Usage:
- Utilizing Tor for making requests is the default, if you plan on using the default option of Tor, ensure it is started on your system. Install Tor if it is not already present on your system.
````
sudo apt install tor
sudo systemctl start tor
````

- Run the program:
````
python3 DataReaper.py
````
- Options:\
        - `-q`: Perform a Shodan query and update the result.txt file.\
        - `-s`: Scan and enumerate targets listed in the result.txt file.\
        - `-r`: Reap subdirectories and files from harvested targets (requires -s).\
        - `-x`: Execute all actions: Perform a Shodan query, scan targets, and reap data (equivalent to -q -s -r).\
        - `-n`: Disable Tor support: Do not use Tor for anonymized scanning.\
        - `-i`: Ignore history file: Scan all targets again, regardless of past scans.\
        - `-p [port number]`: Port number to do query or scan on. Default 8000.\
        - `-t [target ip]`: Target ip to scan. Assumes scan unless -r specified.

- Output:
    - Shodan query results are stored in the result.txt file.
    - A history of scanned targets is maintained in the history.txt file.
    - Harvested files are saved in directories based on the target IP address.

## Examples:

- Update results and scan targets:
````
python data_reaper.py -q -s
````
- Perform a complete data harvest with Tor:
````
python data_reaper.py -x
````
- Ignore history and scan all targets without Tor:
````
python data_reaper.py -s -i -n
````
## Disclaimer:

- DataReaper is designed for educational and research purposes only. Use it responsibly and ethically, considering any relevant legal and ethical implications of data collection activities.

- Further Information:

- Shodan API Documentation: https://developer.shodan.io/api
- Python Requests Library: https://readthedocs.org/projects/requests/

### Thank you for using DataReaper!
