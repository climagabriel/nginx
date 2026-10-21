# multirange fuzz harness

Differential fuzzer for `multipart/byteranges` (RFC 9110 §14.6) handling through
the slice and proxy-cache modules of an nginx-gcdn fork. Each iteration sends the
same multi-range request to a cache edge and to a vanilla origin, normalizes both
bodies, and compares them. A body mismatch, or a status disagreement, stops the
run.

| File | Role |
| --- | --- |
| `multirange-test.py` | The fuzzer. Loops until the first mismatch. |
| `multirange_slicing.conf` | Cache edge. Four virtual hosts (nginx `server` blocks) on `127.0.0.3:8081`. Runs under the fork binary. |
| `nginx-origin.conf` | Origin. Vanilla nginx, static files. Listens on `127.0.0.2:3333`, `127.0.0.3:3333`, `127.0.0.4:3333`. |

## Topology

- fuzzer → cache edge, port 8081
- cache edge → origin, upstream `local_origin1` and `local_origin2`, port 3333
- fuzzer → origin directly, `local_origin1:3333`, for the reference body

The four cache virtual hosts differ as:

| Host | Slicing | Other |
| --- | --- | --- |
| `sliced` | `slice 2m` | `proxy_cache_max_range_offset 1000` |
| `minuses` | `slice 3m` | `proxy_cache_min_uses 1024` |
| `unsliced` | off | caching |
| `min_unsliced` | off | `proxy_cache_min_uses 1024` |

## Setup

Vanilla nginx binary at `/usr/local/sbin/nginx-plain`.

Name resolution — `/etc/hosts`:

```
127.0.0.2 local_origin1
127.0.0.4 local_origin2
127.0.0.3 sliced unsliced minuses min_unsliced
```

`local_origin1` and `local_origin2` are the only origin names the harness uses;
the origin's `127.0.0.3:3333` listener has no name here and is not reached.

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
subranges (closed; `x-`; `-x`; and reversed, `end-start` with end greater than
start), requests origin and edge, then normalizes both bodies — every CRLF
removed, and the generated boundary string replaced by the literal `BOUNDARY`
wherever it appears — before comparing.

- Body mismatch: writes `/tmp/origin.txt` and `/tmp/cache.txt`, then exits.
- Status pair not 200/200, 206/206 or 416/416: prints the pair and exits, with no
  artifacts.
- Match: continues; on a coin flip per iteration, deletes 8 randomly chosen cache
  files under `/mnt/disk1/cache/multirange-splitted`.

The edge must return the origin's status. Any split, including 200/206, is a
failure.
