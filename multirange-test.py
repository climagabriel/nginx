import requests
import re
import random
import subprocess
import logging

#logging.basicConfig(level=logging.DEBUG)

two_o_sixes = 0
two_o_os = 0

#ORIGIN='http://origin:8080/'
ORIGIN='http://local_origin1:3333/'
#CACHE='http://pwnrzclb-fe.gcdn.co/'
CACHE='http://127.0.0.3:8081/'
uri = 'f2p24b'

# Cache virtual hosts, chosen per iteration and sent as the Host header.
# bypass_unsliced and bypass_spill are the only ones where the edge's range
# filter builds the multipart response from a streamed 200: everywhere else
# the origin answers the forwarded Range itself (min_unsliced), each slice is
# a 206 (sliced, minuses), or the response is read back from the cache file
# (unsliced).
CACHE_HOSTS = ['sliced', 'unsliced', 'minuses', 'min_unsliced',
               'bypass_unsliced', 'bypass_spill']

origin_head_response = requests.head(f'{ORIGIN}{uri}')
origin_file_size = int(origin_head_response.headers.get('Content-Length'))
max_distance = origin_file_size//10

range_prefix = 'bytes='


class Mismatch(Exception):
    pass


def boundary_of(content_type):
    m = re.search(r'boundary=(?:"([^"]+)"|([^;\s]+))', content_type or '')
    if m is None:
        raise Mismatch(f'no boundary in Content-Type {content_type!r}')
    return (m.group(1) or m.group(2)).encode()


def parts_of(body, boundary):
    """RFC 2046 multipart body -> [(content_range, payload)].

    Lenient about framing the RFC allows to vary (preamble, epilogue,
    header layout), so an origin that frames differently still compares
    by content.
    """
    delimiter = b'--' + boundary
    pieces = re.split(b'(?:^|\r\n)' + re.escape(delimiter), body)
    parts = []
    for piece in pieces[1:]:
        if piece.startswith(b'--'):
            return parts
        piece = re.sub(b'^[ \t]*\r\n', b'', piece, count=1)
        head, sep, payload = piece.partition(b'\r\n\r\n')
        if not sep:
            raise Mismatch(f'part without header end: {piece[:120]!r}')
        m = re.search(br'(?im)^content-range:\s*bytes\s+(\d+)-(\d+)/(\d+)\s*$',
                      head)
        if m is None:
            raise Mismatch(f'part without Content-Range: {head[:200]!r}')
        parts.append(((int(m.group(1)), int(m.group(2)), int(m.group(3))),
                      payload))
    raise Mismatch('no closing delimiter')


def check_our_framing(response):
    """The edge's multipart body must be exactly what nginx frames:

        CRLF "--" B CRLF header-lines CRLF CRLF payload ...
        CRLF "--" B "--" CRLF

    with the payload as long as its Content-Range says, and a
    Content-Length equal to the body length. Independent of the origin.
    """
    body = response.content
    boundary = boundary_of(response.headers.get('content-type'))
    content_length = response.headers.get('content-length')
    if content_length is None or int(content_length) != len(body):
        raise Mismatch(f'Content-Length {content_length} for a body of {len(body)}')

    delimiter = b'\r\n--' + boundary
    closing = delimiter + b'--\r\n'
    if not body.endswith(closing):
        raise Mismatch(f'body does not end with the closing delimiter: {body[-80:]!r}')
    if not body.startswith(delimiter + b'\r\n'):
        raise Mismatch(f'body does not start with a delimiter line: {body[:80]!r}')

    pos = 0
    while pos < len(body) - len(closing):
        if not body.startswith(delimiter + b'\r\n', pos):
            raise Mismatch(f'no delimiter line at {pos}: {body[pos:pos + 80]!r}')
        pos += len(delimiter) + 2
        end = body.find(b'\r\n\r\n', pos)
        if end < 0:
            raise Mismatch(f'part headers at {pos} are not terminated')
        lines = body[pos:end].split(b'\r\n')
        if not all(re.fullmatch(br'[A-Za-z-]+: [^\r\n]*', l) for l in lines):
            raise Mismatch(f'malformed part header lines: {lines!r}')
        ranges = [l for l in lines if l.lower().startswith(b'content-range: ')]
        m = re.fullmatch(br'Content-Range: bytes (\d+)-(\d+)/(\d+)',
                         ranges[0]) if len(ranges) == 1 else None
        if m is None:
            raise Mismatch(f'part needs exactly one Content-Range: {lines!r}')
        pos = end + 4 + int(m.group(2)) - int(m.group(1)) + 1
        if not body.startswith(delimiter, pos):
            raise Mismatch(f'payload of {m.group(0)!r} not followed by a delimiter')
    if pos != len(body) - len(closing):
        raise Mismatch(f'framing ends at {pos}, closing delimiter at {len(body) - len(closing)}')


c = 0
n = 0
comp = True

while (comp):

    n += 1

    CACHE_HOST=random.choice(CACHE_HOSTS)
    range_header = range_prefix
    rangecount = random.randint(1,7)

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


        if (random.choice([True, False])):
            range_header += f'{a}-{b}'
        else:
            range_header += f'{b}-{a}'

        if ((i+1) < rangecount):
            range_header += ','



    rheader = { 'Range' : range_header }
    print(n, CACHE_HOST, range_header, end='', flush=True)

    origin_response = requests.get(f"{ORIGIN}{uri}", headers=rheader)
    cache_response = requests.get(f"{CACHE}{uri}",
                                  headers={**rheader, 'Host': CACHE_HOST})

    problem = None

    try:
        if (cache_response.status_code == 206 == origin_response.status_code):
            two_o_sixes += 1
            origin_ct = origin_response.headers.get('content-type', '')
            cache_ct = cache_response.headers.get('content-type', '')
            if ('multipart/byteranges' in origin_ct) != ('multipart/byteranges' in cache_ct):
                raise Mismatch(f'Content-Type {origin_ct!r} vs {cache_ct!r}')
            if 'multipart/byteranges' in cache_ct:
                check_our_framing(cache_response)
                origin_parts = parts_of(origin_response.content, boundary_of(origin_ct))
                cache_parts = parts_of(cache_response.content, boundary_of(cache_ct))
                if origin_parts != cache_parts:
                    raise Mismatch('parts differ: origin %s, cache %s' % (
                        [r for r, _ in origin_parts], [r for r, _ in cache_parts]))
            else:
                if (origin_response.headers.get('content-range')
                        != cache_response.headers.get('content-range')):
                    raise Mismatch('Content-Range %r vs %r' % (
                        origin_response.headers.get('content-range'),
                        cache_response.headers.get('content-range')))
                if origin_response.content != cache_response.content:
                    raise Mismatch('single-range bodies differ')
        elif (cache_response.status_code == 200 == origin_response.status_code):
            two_o_os += 1
            if cache_response.content != origin_response.content:
                raise Mismatch('200 bodies differ')
        elif (cache_response.status_code == 416 == origin_response.status_code):
            print('\n',cache_response.status_code, origin_response.status_code, range_header, '\n')
        else:
            print('\n',cache_response.status_code, origin_response.status_code, range_header, '\n')
            quit()
    except Mismatch as e:
        problem = str(e)

    print(' (', origin_response.status_code, rangecount, cache_response.headers.get('cache'), '),', end='\n', flush=True)

    if problem is not None:
        comp = False
        print('\n', cache_response.status_code, origin_response.status_code, range_header, '\n', problem, '\n')
        with open('/tmp/origin.txt', 'wb') as originc:
            originc.write(origin_response.content)
        with open('/tmp/cache.txt', 'wb') as cachec:
            cachec.write(cache_response.content)
        quit()

    if (random.choice([True, False])):
        subprocess.run('find /mnt/disk1/cache/multirange-splitted/ -type f ! -name "*.*"  | shuf -n 8 | xargs --no-run-if-empty rm -f ', shell=True, check=True)
    #subprocess.run('find /mnt/disk1/cache/multirange-splitted/ -type f ! -name "*.*" | xargs --no-run-if-empty rm -f ', shell=True, check=True)
