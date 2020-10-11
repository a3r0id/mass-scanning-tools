import os
import sys
import time
import json
import socket
import random
import threading
from datetime import datetime
from os import getcwd, path
from random import choice
from pathlib import Path
from colorama import Fore

a = datetime.now()

#Path(getcwd() + "\\out").mkdir(parents=True, exist_ok=True)
def get_change(current, previous):
	if current == previous:
		return 0
	try:
		return (abs(current - previous) / previous) * 100.0
	except ZeroDivisionError:
		return float('inf')

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
	with open('data.json') as f:
		data = json.load(f)
	current_session = span_token(8)
	hit_words = data['hit_words']	
	port = data['port']
	thread_count = data['thread_count']
	input_file = data['input_file']
	timeout = data["timeout"]
	#output_file = getcwd() + "\\" + data['output_file'] + "_" + current_session + ".txt"
	output_file = data['output_file'] + "_" + current_session + ".txt"
	ips = get_lst(input_file)
	init_ip_len = len(ips)
	threads_closed = 0
	full_std_out = data["full_stdout"]
	hits = []

def threadWorker(t_id):
	time.sleep(1.50)
	while True:
		#diff = round(get_change(len(glbls.ips), glbls.init_ip_len))
		#if diff % 1.00:
		#	print(Fore.CYAN + f"[{len(glbls.hits)}/{len(glbls.ips)}/{glbls.init_ip_len}] [{diff}%]" + Fore.RESET)
		if len(glbls.ips) == 0:
			glbls.threads_closed += 1
			if glbls.full_std_out:
				print(Fore.CYAN + f"[{len(glbls.hits)}/{len(glbls.ips)}/{glbls.init_ip_len}] THREAD {t_id} CLOSING..." + Fore.RESET)
			return		
		ip = glbls.ips.pop(0)		
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(glbls.timeout)
		try:
			s.connect((ip, glbls.port))
		#except Exception as ff:
		#	print(ff)
		except:
			if glbls.full_std_out:
				print(Fore.RED + f"[{len(glbls.hits)}/{len(glbls.ips)}/{glbls.init_ip_len}] THREAD {t_id} TIMED OUT @ {ip}:{glbls.port}..." + Fore.RESET)
			continue
		brk = False
		if glbls.full_std_out:
			print(Fore.GREEN + f"[{len(glbls.hits)}/{len(glbls.ips)}/{glbls.init_ip_len}] THREAD {t_id} CONNECTED @ {ip}:{glbls.port}..." + Fore.RESET)
		pointer = 0
		while True:
			time.sleep(1)
			try:
				buf = repr(s.recv(1024))[2:][:-1].lower()
			except:
				if glbls.full_std_out:
					print(Fore.RED + f"[{len(glbls.hits)}/{len(glbls.ips)}/{glbls.init_ip_len}] THREAD {t_id} TIMED OUT @ {ip}:{glbls.port}..." + Fore.RESET)
				brk = True
				break	
			if len(buf) > 0:
				break
			if pointer == 1:
				break
			#Two Seconds -- Polling method
			pointer += 1
		if brk:
			continue
		for nib in glbls.hit_words:
			if nib in buf:
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
		s.close()	
if len(glbls.ips) < glbls.thread_count:
	print(Fore.BLUE + f"Thread count too high!\nTry something like 100 threads or lower!" + Fore.RESET)
	exit()
xy = "\x40\x68\x6f\x73\x74\x69\x6e\x66\x6f\x64\x65\x76"
# DEBUG: print(glbls.ips)
for i in range(glbls.thread_count):
	i += 1
	x = threading.Thread(target=threadWorker, args=(i,))
	print(Fore.RED + "[" + Fore.MAGENTA  + f" By {xy} " + Fore.RED + "]" + Fore.GREEN + f" - SPAWNING THREAD: {i}..." + Fore.RESET)
	x.start()
while True:
	if glbls.threads_closed == glbls.thread_count:
		total_sec = ( datetime.now() - a ).total_seconds()
		print("\n" + Fore.GREEN + f"[COMPLETED SCAN OF {glbls.init_ip_len} IPS IN {total_sec} SECONDS]\n[HITS: {len(glbls.hits)}]" + Fore.RESET)
		exit()



