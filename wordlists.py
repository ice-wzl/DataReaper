from colorama import Fore, Back, Style


def key_words(content, ip_addr):
    interesting_words = [
        "authorized_keys",
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
        "password"
    ]

    word_found = False
    content = content.decode().lower()
    for i in interesting_words:
        if i in content:
            word_found = True
            print(Fore.GREEN + "\t{} found at {}".format(i, ip_addr.strip()))
    return word_found


def ssh_words(content, ip_addr):
    interesting_words = [
        "authorized_keys",
        "id_rsa.pub",
        "id_rsa",
        "id_ecdsa.pub",
        "id_ecdsa",
        "id_dsa.pub",
        "id_dsa",
        "id_ed25519.pub",
        "id_ed25519",
        "pp_id_rsa.ppk"
    ]

    word_found = False
    content = content.decode().lower()
    for i in interesting_words:
        if i in content:
            word_found = True
            print(Fore.GREEN + "\t{} found at {}".format(i, ip_addr.strip()))
    return word_found
