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
    "backup.log",
    "backup.zip",
    "backup.conf",
    "backup.rar",
    "backup.tar",
    "backup.tar.gz",
    "cookies.json",
    "cookies1.json",
    "edges_log.txt",
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
    ".env",
    ".env.backup",
    ".env.production",
    "home",
    "registercluster.sh",
    "root",
    "shadow",
    "Shadowsocks-4.4.1.0.zip",
    "socat",
    "ssh-tools",
    "tailscale",
    "tcpdump",
    "ubuntu-jammy-desktop-credential.txt",
    "windows-server-2019-eval.iso",
    "windows_server_2012_r2_standard_eval_kvm_20170321.qcow2",
    "wg",
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
        "tools",
        "tencentcloud_files",
        "victim",
        "wireguard",
        "wormhole"
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