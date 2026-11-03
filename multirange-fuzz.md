# multirange fuzz harness

Differential fuzzer for `multipart/byteranges` (RFC 9110 §14.6) handling through
the slice and proxy-cache modules of an nginx-gcdn fork. Each iteration sends the
same multi-range request to a cache edge and to a vanilla origin and compares
what they return: the status, and for a multipart response the list of parts
(each Content-Range and its bytes). It also checks the edge's multipart framing on
its own, since the origin may frame its response differently. A mismatch, a
framing error, or a status disagreement stops the run: the edge must return the
origin's status, and any split, including 200/206, is a failure.

| File | Role |
| --- | --- |
| `multirange-test.py` | The fuzzer. Loops until the first mismatch. |
| `multirange_slicing.conf` | Cache edge. Six virtual hosts (nginx `server` blocks) on `127.0.0.3:8081`. Runs under the fork binary. |
| `nginx-origin.conf` | Origin. Vanilla nginx, static files. Listens on `127.0.0.2:3333`, `127.0.0.3:3333`, `127.0.0.4:3333`. |

## Topology

- fuzzer → cache edge, port 8081
- cache edge → origin, upstream `local_origin1` and `local_origin2`, port 3333
- fuzzer → origin directly, `local_origin1:3333`, for the reference body

The six cache virtual hosts differ as:

| Host | Slicing | Other | Who builds the multipart response |
| --- | --- | --- | --- |
| `sliced` | `slice 2m` | `proxy_cache_max_range_offset 1000` | The edge, from one 206 per slice. |
| `minuses` | `slice 3m` | `proxy_cache_min_uses 1024` | The edge, from one 206 per slice. |
| `unsliced` | off | `proxy_cache`, no other cache directive | The edge, from the cache file: on a miss, a clone subrequest reads it once the miss has filled it. |
| `min_unsliced` | off | `proxy_cache_min_uses 1024` | The origin: the edge forwards the client's Range and relays the origin's 206. |
| `bypass_unsliced` | off | `proxy_cache_bypass 1`, `proxy_no_cache 1` | The edge, from the origin's 200 as it streams: a bypass sends the origin no Range. |
| `bypass_spill` | off | as `bypass_unsliced`, with `proxy_buffers 4 8k` and `limit_rate 40m` | The same, with the stream spilled to the proxy temp file. |

## Setup

Vanilla nginx binary at `/usr/local/sbin/nginx-plain`.

Name resolution — `/etc/hosts`:

```
127.0.0.2 local_origin1
127.0.0.4 local_origin2
```

`local_origin1` and `local_origin2` are the only origin names the harness uses;
the origin's `127.0.0.3:3333` listener has no name here and is not reached. The
fuzzer sends every edge request to `127.0.0.3:8081` with the virtual host in the
`Host` header, so the cache host names need no entry.

Origin object, 16777216 bytes (5 + 16777208 + 3), alphanumeric ASCII framed by
`START` and `END`:

```
{ printf START; tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 16777208; printf END; } > /var/www/html/f2p24b
```

Directories the configs expect to exist:

```
mkdir -p /mnt/disk1/cache/multirange-splitted /var/lib/nginx/cores
mkdir -p /var/lib/nginx-origin/{body,proxy,fastcgi,uwsgi,scgi}
```

Dependencies: python3 `requests`; `find`, `shuf`, `xargs`.

## Run

`multirange_slicing.conf` sets `daemon off`, so the cache edge holds its terminal.
Use two.

Terminal 1 — origin first, then cache edge; both stay in the foreground:

```
cd /path/to/harness
/usr/local/sbin/nginx-plain -c "$(pwd)/nginx-origin.conf"
/path/to/fork/objs/nginx -c "$(pwd)/multirange_slicing.conf"
```

Terminal 2 — fuzzer:

```
python3 multirange-test.py
```

## Behaviour

Each iteration picks a cache virtual host, builds a `Range` header of 1–7
subranges (closed; `x-`; `-x`; and descending, `high-low`), requests origin and
edge, and compares:

- 206 multipart on both: each body is split into parts by its own boundary, and
  the two lists of (Content-Range, bytes) must be equal. The origin's preamble,
  epilogue and header layout are not compared.
- The edge's multipart body must also be exactly what nginx frames, CRLF
  `--boundary` CRLF, header lines, CRLF CRLF, the bytes, and CRLF
  `--boundary--` CRLF at the end, with each part's length as its Content-Range
  says and a `Content-Length` equal to the body length.
- 206 single range: the Content-Range headers and the bodies must be equal.
- 200: the bodies must be equal.

- Mismatch or framing error: prints the reason, writes `/tmp/origin.txt` and
  `/tmp/cache.txt`, then exits.
- Status pair not 200/200, 206/206 or 416/416: prints the pair and exits, with no
  artifacts.
- Match: continues; on a coin flip per iteration, deletes 8 randomly chosen cache
  files under `/mnt/disk1/cache/multirange-splitted`.
