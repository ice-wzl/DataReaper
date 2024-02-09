#!/usr/bin/python3
import shodan
import sys
from colorama import Fore

def banner():
    print(
        Fore.RED +
        """
               ...                            
             ;::::;                           
           ;::::; :;                          
         ;:::::'   :;                         
        ;:::::;     ;.                        
       ,:::::'       ;           OOO\         
       ::::::;       ;          OOOOO\        
       ;:::::;       ;         OOOOOOOO       
      ,;::::::;     ;'         / OOOOOOO      
    ;:::::::::`. ,,,;.        /  / DOOOOOO    
  .';:::::::::::::::::;,     /  /     DOOOO   
 ,::::::;::::::;;;;::::;,   /  /        DOOO  
;`::::::`'::::::;;;::::: ,#/  /          DOOO 
:`:::::::`;::::::;;::: ;::#  /            DOOO
::`:::::::`;:::::::: ;::::# /              DOO
`:`:::::::`;:::::: ;::::::#/               DOO
 :::`:::::::`;; ;:::::::::##                OO
 ::::`:::::::`;::::::::;:::#                OO
 `:::::`::::::::::::;'`:;::#                O 
  `:::::`::::::::;' /  / `:#                  
   ::::::`:::::;'  /  /   `#              v.2.1.0
                                  Made by Aznable,
                                          ice-wzl
    """ + Fore.RESET
    )


def setup_api():
    with open("api.txt", "r") as fp:
        api_key = fp.read().strip()
        print("API key used: {}".format(api_key))
    api = shodan.Shodan(api_key)
    return api


def do_query(api, query):
    try:
        query = "".join(query)
        print("Query {}".format(query))
        result = api.search(query)
        with open("result.txt", "w+") as fp:
            for service in result["matches"]:
                fp.write(service["ip_str"] + "\n")
        fp.close()
    except shodan.exception.APIError as e:
        print("Invalid Shodan API Key...")
        sys.exit(2)
