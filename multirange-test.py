import requests
import re
import random
import subprocess


ORIGIN='http://127.0.0.1:8080/'
CACHE='http://sliced/'
uri = 'f2p24b'
origin_file_size = 16777216
max_distance = origin_file_size//10

boundary_pattern = rb'--[0-9]{20}'
range_start = 'bytes='


c = 0
comp = True
while (comp):
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
        quit()

    print()

    if (random.choice([True, False])):
        subprocess.run('find /mnt/disk1/cache/ -type f -delete', shell=True, check=True)
