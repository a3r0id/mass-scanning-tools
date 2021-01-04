from subprocess import check_output
from sys import argv
# DUMPS ALL SUBNETS OF AN ASN TO A FILE
asn = argv[1].upper()
command = " ".join(["whois", "-h", "whois.radb.net", "--",  '\'-i origin %s\'' % (asn,), "|", "grep", "-Eo", "\"([0-9.]+){4}/[0-9]+\""])
cidrs = check_output(command, shell=True)
if len(cidrs) and b'not' not in cidrs:
    fname = asn.upper() + ".txt"
    with open(fname, "w+") as f:
        f.write(cidrs.decode('utf-8'))
        print(fname)
        exit(0)
       

print("Invalid CIDR!")
exit(1)
