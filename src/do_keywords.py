#!/usr/bin/python3
from colorama import Fore


def key_words(content, ip_addr):
    interesting_words = [
        ".aws/",
        ".bash_history",
        ".git/",
        ".python_history",
        ".ssh/",
        ".viminfo",
        ".wg-easy/",
        ".wget-hsts",
        "/etc",
        "/opt",
        "0day",
        "brute",
        "brute_ratel",
        "bruteforce",
        "cobalt",
        "cobalt-strike",
        "cobalt_strike",
        "collect",
        "crypter",
        "dropper_cs.exe",
        "Desktop",
        "Documents",
        "Downloads",
        "exploit",
        "gost",
        "hacking",
        "havoc",
        "home/",
        "id_rsa",
        "id_ecdsa",
        "id_dsa",
        "id_ed25519",
        "lockbit",
        "log4j",
        "malware",
        "metasploit",
        "mrlapis",
        ".msf4",
        ".msf6",
        "nessus",
        "ngrok",
        "nmap",
        "notes/",
        "nuclei",
        "gorailgun",
        "passwd",
        "payload",
        "pt/",
        "pp_id_rsa.ppk",
        "qakbot",
        "qbot",
        "Users"
        "ransom",
        "ransomware",
        "ratel",
        "redlinestealer",
        "revil",
        "root/",
        "shadow",
        "shellcode",
        "sliver",
        "sqlmap",
        "tools/",
        "victim",
        "wg/",
        "wireguard",
        "wormhole",
        "key.pem",
        "crt.pem",
        "key.key",
        "crt.key",
        "cert.crt",
        ".git-credentials",
        "password"
    ]

    word_found = False
    content = content.decode().lower()
    interesting_find = ""
    for i in interesting_words:
        if i in content:
            word_found = True
            print(Fore.GREEN + "\t{} found at {}".format(i, ip_addr.strip()))
            if (interesting_find == ""):
                interesting_find = i
            else:
                interesting_find = interesting_find + "," + i
    return word_found, interesting_find
