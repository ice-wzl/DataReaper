from colorama import Fore

full_word_match = [
    ".ash_history",
    ".bash_history",
    ".zsh_history",
    ".csh_history",
    ".ksh_history",
    ".git-credentials",
    ".sqlite_history",
    "archive.zip",
    "backend.yml",
    "bruteforce",
    "BACKUP-SYSTEM.md",
    "backup.log",
    "backup.zip",
    "backup.conf",
    "backup.rar",
    "backup.tar",
    "backup.tar.gz",
    "cookies.json",
    "cookies1.json",
    ".dbshell",
    "edges_log.txt",
    "evil.dtd",
    "listener.log",
    "test.dtd",
    "proxies.txt",
    "Proxies1.txt",
    "Proxies22.txt",
    "proxies_de.txt",
    "proxies_fr.txt",
    "proxies_mix.txt",
    "proxies_nl.txt",
    "proxies_uk.txt",
    "proxies_us.txt",
    "config",
    "cobalt",
    "collect",
    "client.zip",
    "client.conf",
    "client1.conf",
    "client2.conf",
    "client3.conf",
    "client4.conf",
    "client5.conf",
    "deploy.yml",
    "dataset.yaml",
    "docker-compose.yml",
    "Dockerfile",
    ".env",
    ".env.backup",
    ".env.production",
    ".env_docker",
    "home",
    "http_server.py",
    "server.py",
    "http_server.sh",
    "server_8888.py",
    "http_server_flask.py",
    "output.log",
    "start.sh",
    "stop.sh",
    "SERVER_SETUP.md",
    "registercluster.sh",
    "root",
    "run.sh",
    "run_headless.sh",
    "shadow",
    "Shadowsocks-4.4.1.0.zip",
    "socat",
    "ssh-tools",
    "scraper.py",
    "scraper_selenium.py",
    "scraper_selenium_chromium.py",
    "tailscale",
    "upload_server.py",
    "tcpdump",
    "ubuntu-jammy-desktop-credential.txt",
    "windows-server-2019-eval.iso",
    "windows_server_2012_r2_standard_eval_kvm_20170321.qcow2",
    "wg",
    "webssh.py",
    "xray"
]
merged_list = [
        ".aws",
        ".msf4",
        ".msf6",
        ".p12",
        ".pem",
        ".pfx",
        ".python_history",
        ".ssh",
        ".viminfo",
        ".wg-easy",
        ".wget-hsts",
        "0day",
        "brute_ratel",
        "bruteforce",
        "cert.crt",
        "cobalt-strike",
        "cobalt_strike",
        "crt.key",
        "crt.pem",
        "crypter",
        "Desktop",
        "Documents",
        "Downloads",
        "dropper_cs.exe",
        "exploit",
        "gorailgun",
        "gost",
        "hack",
        "hacking",
        "havoc",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "id_rsa",
        "key.key",
        "key.pem",
        "lockbit",
        "log4j",
        "malware",
        "metasploit",
        "mrlapis",
        "nessus",
        "ngrok",
        "nmap",
        "notes",
        "nuclei",
        "passwd",
        "proxy_server",
        "password",
        "payload",
        "pp_id_rsa.ppk",
        "priv_key",
        "qakbot",
        "qbot",
        "ransom",
        "ransomware",
        "ratel",
        "redlinestealer",
        "revil",
        "shellcode",
        "sliver",
        "sqlmap",
        "ssh_rsa.pem",
        "tencentcloud_files",
        "victim",
        "wireguard",
        "wormhole",
        "wpscan"
    ]

def banner():
    print(
        Fore.RED +
        r"""
               ...                            
             ;::::;                           
           ;::::; :;                          
         ;:::::'   :;                         
        ;:::::;     ;.                        
       ,:::::'       ;           OOO\      
       ::::::;       ;          OOOOO\        
       ;:::::;       ;         OOOOOOOO       
      ,;::::::;     ;'         / OOOOOOO      
    ;:::::::::`. ,,,;.        /  / DOOOOOO    
  .';:::::::::::::::::;,     /  /     DOOOO   
 ,::::::;::::::;;;;::::;,   /  /        DOOO  
;`::::::`'::::::;;;::::: ,#/  /          DOOO 
:`:::::::`;::::::;;::: ;::#  /            DOOO
::`:::::::`;:::::::: ;::::# /              DOO
`:`:::::::`;:::::: ;::::::#/               DOO
 :::`:::::::`;; ;:::::::::##                OO
 ::::`:::::::`;::::::::;:::#                OO
 `:::::`::::::::::::;'`:;::#                O 
  `:::::`::::::::;' /  / `:#                  
   ::::::`:::::;'  /  /   `#              v.3.0.0
                                  Made by Aznable,
                                          ice-wzl
    """ + Fore.RESET
    )