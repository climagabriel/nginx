import requests
import re
import random
import subprocess


comp = True
uri = 'f2p24b'
boundary_pattern = rb'--[0-9]{20}'
range_start = 'bytes='
max_range = 16777216

ORIGIN='http://pwnrzclb.net/'
#CACHE='http://pwnrz-fe-preprod.gcdn.co/'
CACHE='http://sliced/'

while (comp):

    a , b = sorted(random.sample(range(max_range), 2))
    c , d = sorted(random.sample(range(max_range), 2))

    range_h = f"{range_start}{a}-{b},{c}-{d}"
    rheader = { 'Range' : range_h }

    print(range_h)

    r = requests.get(f"{ORIGIN}{uri}", headers=rheader)
    rh = r.headers
    print(r.status_code, r.elapsed.total_seconds(), len(r.content), rh['Content-length'])

    mrheader = { 'Range' : range_h, 'Host': 'sliced'}
    mr = requests.get(f"{CACHE}{uri}", headers=rheader)
    mrh = mr.headers
    print(mr.status_code, mr.elapsed.total_seconds(), len(mr.content), mrh['Cache'])#, mrh['traceparent'])


    modified_r = re.sub(boundary_pattern, b'--BOUNDARY', r.content)
    modified_mr = re.sub(boundary_pattern, b'--BOUNDARY', mr.content)
    comp =  modified_r == modified_mr
    print(comp)

    if not (comp):
        with open('/tmp/origin.txt', 'wb') as originc:
            originc.write(r.content)
        with open('/tmp/cache.txt', 'wb') as cachec:
            cachec.write(mr.content)

    print()

    subprocess.run('find /mnt/disk1/cache/ -type f -delete', shell=True, check=True)
