from colorama import Fore

full_word_match = [
    ".bash_history",
    ".git",
    ".git-credentials",
    "backend.yml",
    "bruteforce",
    "cobalt",
    "collect",
    "deploy.yml",
    ".env",
    ".env.backup",
    ".env.production",
    "home",
    "root",
    "shadow",
    "ssh-tools",
    "wg",
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
        "backup",
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