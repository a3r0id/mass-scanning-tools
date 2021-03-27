from requests import get
from re import search
import ipaddress
import json
import threading
from sys import argv
from random import choice
from time import sleep
from user_agent import generate_navigator

class a:
    ip_stack = 0
    cidr = str()
    ips = []
    hits = 0
    iplen_init = 0
    final_data = []
    false_positives = ["result", "{\"", "404", "error"]
    status_codes_to_ignore = [404, 403, 401, 300, 301, 302, 500, 502]
    final_data = []
    thread_control = []
    s_hash = ""
    filelocked = False
    with open("ports.json", "r") as f:
        port_types = json.load(f)

def make_hash(length):
    thisHash = ""
    for _ in range(length):
        thisHash += choice(["a", "b", "c", "d", "e", "f", "0", "1", "2", "3", "4", "5"])
    return thisHash   

def thread_worker(thread_id, timeout, SPOOF_UA):

    while True:

        try:
            ip = a.ips.pop(0)
        except IndexError:
            print(f"[Thread #{thread_id}] [EOL]")   
            break 

        count = 0
        this_ip_port_data = {"ip": ip, "open_ports": []}

        for port in a.port_types:
            portnum = str(port["port"])
            #print(f"[Thread #{thread_id}] Trying {ip}:{portnum}....")

            try:
                if SPOOF_UA: headers = {"User-Agent": generate_navigator()["user_agent"]}
                else: headers = {"User-Agent": "Mozilla/5.0 (compatible; http-sevice-discovery/1.0; +https://mysite.io)"}    

                r = get(f"http://{ip}:" + str(port["port"]), timeout=timeout, headers=headers)
                
                if r.status_code not in a.status_codes_to_ignore and len(r.headers) > 0 and [ele for ele in a.false_positives if(ele in r.text.lower())] == False:
                    this_ip_port_data["open_ports"].append({"port_number": port["port"], "port_info": port, "raw": r.text})
                    a.final_data.append(this_ip_port_data) 
                    a.hits += 1

                    while True:
                        # Threads wait their turn
                        if a.filelocked == False:
                            a.filelocked = True
                            json_object = json.dumps(a.final_data, indent = 4)
                            with open(a.s_hash + ".json", "w+") as t:
                                t.write(json_object)
                            a.filelocked = False    
                            break    

            except:
                pass
            

            if count >= len(a.port_types):
                break

            count += 1

        #if a.ip_stack >= len(a.ips):
        #    print(f"Thread #{thread_id} stopping...\n")
        #    break    

        #a.ip_stack += 1    



def spawn_threads(thread_count, TIMEOUT, SPOOF_UA):

    for x in range(thread_count):
        thread = threading.Thread(
            target=thread_worker,
            args=(
                str(x + 1),
                float(TIMEOUT),
                SPOOF_UA,
                )
            )       

        if x == thread_count / 2:
            sleep(thread_count / (2 * TIMEOUT))

        thread.start()

        if x == thread_count:
            print(f"Spawned {thread_count} threads...\n")

        

def range_scan(CIDR, TIMEOUT, THREAD_COUNT, SPOOF_UA=False):

    validate = search(r'(?:\d{1,3}\.){3}\d{1,3}(?:/\d\d?)?', CIDR)
    if validate == None:
        print("Invalid CIDR")
        exit()

    a.s_hash = make_hash(12) 

    a.cidr = str(CIDR)    

    a.ips = [str(ip) for ip in ipaddress.IPv4Network(a.cidr)]    

    a.iplen_init = len(a.ips)

    print()

    spawn_threads(THREAD_COUNT, TIMEOUT, SPOOF_UA)



SPOOF_UA = False
for arg in argv:
    if "--user":
        SPOOF_UA = True

range_scan(argv[1], float(argv[2]), int(argv[3]), SPOOF_UA=SPOOF_UA)    
