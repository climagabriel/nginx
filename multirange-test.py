import requests
import re
import random
import signal
import subprocess
from pathlib import Path

quit_received = False
two_o_sixes = 0
two_o_os = 0

def signal_handler(sig, frame):
    global quit_received
    print("206/200: ", two_o_sixes, two_o_os)
    quit_received = True

signal.signal(signal.SIGINT, signal_handler)

cache_dir = Path('/mnt/disk1/cache/')

ORIGIN='http://127.0.0.1:8080/'
CACHE='http://sliced/'
uri = 'f2p24b'
origin_file_size = 16777216
max_distance = origin_file_size//25

boundary_pattern = rb'--[0-9]{20}'
range_start = 'bytes='


c = 0
comp = True

while (comp and not quit_received):
    range_header = range_start
    rangecount = random.randint(2,6)

    for i in (range(rangecount)):
        a = random.randint(1, origin_file_size - max_distance)
        b = a + random.randint(0, max_distance)

        #open ranges
        # x-      (x ... last)
        # -x (last-x ... last)
        items = ['a', 'b', 'c']
        weights = [0.1, 0.1, 0.8]
        choice = random.choices(items, weights=weights, k=1)[0]
        if choice == 'a':
            a = ""
        elif choice == 'b':
            b = ""
        elif choice == 'c':
            c = ""


        range_header += f'{a}-{b}'
        if ((i+1) < rangecount):
            range_header += ','



    print(range_header)
    rheader = { 'Range' : range_header }

    r = requests.get(f"{ORIGIN}{uri}", headers=rheader)
    rh = r.headers
    print(r.status_code, r.elapsed.total_seconds(), len(r.content), rh['Content-length'])
    if(r.status_code == 206):
        two_o_sixes += 1
    elif (r.status_code == 200):
        two_o_os += 1
    else:
        print(r.status_code, range_header)
        quit()

    mr = requests.get(f"{CACHE}{uri}", headers=rheader)
    mrh = mr.headers
    print(mr.status_code, mr.elapsed.total_seconds(), len(mr.content), mrh['Cache'])#, mrh['traceparent'])


    modified_r = re.sub(boundary_pattern, b'--BOUNDARY', r.content)
    modified_mr = re.sub(boundary_pattern, b'--BOUNDARY', mr.content)
    comp =  modified_r == modified_mr
    print(comp, '\n')

    if not (comp):
        with open('/tmp/origin.txt', 'wb') as originc:
            originc.write(r.content)
        with open('/tmp/cache.txt', 'wb') as cachec:
            cachec.write(mr.content)
        quit()


    if (random.choice([True])):
        subprocess.run('find /mnt/disk1/cache/ -type f -delete', shell=True, check=True) #faster
       # for file_path in cache_dir.rglob('*'):
       #     if file_path.is_file():
       #         file_path.unlink()
