import os
import time
import json
from telnetlib import Telnet
import threading
from datetime import datetime
from random import choice
from colorama import Fore

a = datetime.now()

def span_token(length):
    buf = str()
    lis = [str(i) for i in range(0, 9)] + ["a", "b", "c"]
    for _ in range(length):
        buf += choice(lis)
    return buf	

def get_lst(input_file):
	handle = open(input_file, "r").read().split('\n')
	if ".json" in input_file:
		ips = [p.split("{ \"saddr\": \"")[1].split("\" }")[0] for p in handle if len(p) > 0 and "{" in p]		
	else:
		ips = [p for p in handle]
	return ips	

class glbls:
	with open('config.json') as f:
		data = json.load(f)
	current_session = span_token(8)
	hit_words 		= data['hit_words']	
	port 			= data['port']
	thread_count 	= data['thread_count']
	input_file 		= data['input_file']
	timeout 		= data["timeout"]
	output_file 	= data['output_file'] + "_" + current_session + ".txt"
	ips 			= get_lst(input_file)
	init_ip_len 	= len(ips)
	threads_closed  = 0
	full_std_out 	= data["full_stdout"]
	hits 			= []

def threadWorker(t_id):
	time.sleep(1.50)
	while True:
		if len(glbls.ips) == 0:
			glbls.threads_closed += 1
			if glbls.full_std_out:
				print(Fore.CYAN + f"[{len(glbls.hits)}/{len(glbls.ips)}/{glbls.init_ip_len}] THREAD {t_id} CLOSING..." + Fore.RESET)
			return		
		ip = glbls.ips.pop(0)		
		try:
			with Telnet(ip, glbls.port) as tn:
				tn.interact()
		except Exception as ff:
			print(ff)
		except:
			if glbls.full_std_out:
				print(Fore.RED + f"[{len(glbls.hits)}/{len(glbls.ips)}/{glbls.init_ip_len}] THREAD {t_id} WAS REFUSED @ {ip}:{glbls.port}..." + Fore.RESET)
			continue

		# IF CONNECTED
		brk = False
		if glbls.full_std_out:
			print(Fore.GREEN + f"[{len(glbls.hits)}/{len(glbls.ips)}/{glbls.init_ip_len}] THREAD {t_id} CONNECTED @ {ip}:{glbls.port}..." + Fore.RESET)
		pointer = 0
		while True:
			time.sleep(glbls.timeout)
			try:
				buf = repr(tn.read_all())[2:][:-1].lower()
			except:
				if glbls.full_std_out:
					print(Fore.RED + f"[{len(glbls.hits)}/{len(glbls.ips)}/{glbls.init_ip_len}] THREAD {t_id} TIMED OUT @ {ip}:{glbls.port}..." + Fore.RESET)
				brk = True
				break	
			if len(buf) > 0:
				break
			if pointer == 1:
				break
			pointer += 1
		if brk:
			continue
		for i in glbls.hit_words:
			if i in buf:
				if ip not in glbls.hits:
					glbls.hits.append(ip)
					print(Fore.GREEN + f"[{len(glbls.hits)}/{len(glbls.ips)}/{glbls.init_ip_len}] HIT @ {ip}:{glbls.port}" + Fore.RESET)
					if os.path.exists(glbls.output_file):
						append_write = 'a' # append if already exists
					else:
						append_write = 'w' # make a new file if not
					f = open(glbls.output_file,append_write)
					f.write(ip + '\n')
					f.close()
					break	
if len(glbls.ips) < glbls.thread_count:
	print(Fore.BLUE + f"Thread count too high!\nTry something like 100 threads or lower!" + Fore.RESET)
	exit()
 
for i in range(glbls.thread_count):
	i += 1
	x = threading.Thread(target=threadWorker, args=(i,))
	print(Fore.RED + "[" + Fore.MAGENTA  + f" By A3R0 " + Fore.RED + "]" + Fore.GREEN + f" - Starting THREAD: {i}..." + Fore.RESET)
	x.start()
while True:
	if glbls.threads_closed == glbls.thread_count:
		total_sec = ( datetime.now() - a ).total_seconds()
		print("\n" + Fore.GREEN + f"[COMPLETED SCAN OF {glbls.init_ip_len} IPS IN {total_sec} SECONDS]\n[HITS: {len(glbls.hits)}]" + Fore.RESET)
		exit()



