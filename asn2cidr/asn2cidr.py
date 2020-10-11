from requests import get
from re import search
from bs4 import BeautifulSoup
from sys import argv
fileO = False
for arg in argv:
    if "--file" in arg:
        fileO = True
ASN = argv[1].upper()
if fileO:
    fileName =  ASN + ".txt"
r = get('https://ipinfo.io/' + ASN)
soup = BeautifulSoup(r.text, 'html.parser')
body = soup.find_all('a')
out = str()
for p in body:
    text = p.text.replace("\n", "").replace(" ", "")
    if search(r'(?:\d{1,3}\.){3}\d{1,3}(?:/\d\d?)?', text) and "/" in text:
        if fileO:
            out += text + "\n"    
        print(text)    
if fileO:
    with open(fileName, "w+") as f:
        f.write(out)        

