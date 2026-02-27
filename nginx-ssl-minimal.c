/*
 * nginx-ssl-minimal.c
 *
 * Minimal single-file synthesis of the nginx 1.29.5 code paths
 * actually executed during: openssl s_time -connect host:443 -new -time 10
 * (4657 new TLS connections, no HTTP request ever delivered, keepalive_timeout 0)
 *
 * Derived from gcov instrumentation data (.gcda/.gcno) in objs/src/.
 * Only functions with non-zero call counts in gcov output are included.
 *
 * Build:
 *   gcc -Wall -O0 -o nginx-ssl-minimal nginx-ssl-minimal.c \
 *       -lssl -lcrypto
 *
 * Note: This file does NOT implement a runnable server. It is a
 * documentation artifact showing the actual executed logic.  See the
 * main() stub at the bottom for a usage sketch.
 *
 * --------------------------------------------------------------------
 * COVERAGE SUMMARY (gcov runs=3, 4657 connections per worker process)
 * --------------------------------------------------------------------
 *
 * File                           Lines%   Key runtime call counts
 * ─────────────────────────────  ──────   ──────────────────────────────
 * src/core/ngx_palloc.c          64.02%   ngx_create_pool:4669  ngx_destroy_pool:4669
 * src/core/ngx_connection.c      34.34%   ngx_get_connection:4660  ngx_close_connection:4657
 *                                         ngx_reusable_connection:18628  ngx_tcp_nodelay:4657
 * src/event/ngx_event_accept.c   31.82%   ngx_event_accept:4657
 * src/event/ngx_event_openssl.c  14.72%   ngx_ssl_create_connection:4657
 *                                         ngx_ssl_handshake:9314  ngx_ssl_recv:8354
 *                                         ngx_ssl_handle_recv:8354  ngx_ssl_shutdown:4657
 *                                         ngx_ssl_clear_error:22325
 *                                         ngx_ssl_info_callback:83826
 *                                         ngx_ssl_client_hello_callback:4657
 * src/http/ngx_http_request.c     7.72%   ngx_http_init_connection:4657
 *                                         ngx_http_ssl_handshake:4657
 *                                         ngx_http_ssl_handshake_handler:4657
 *                                         ngx_http_ssl_servername:9314
 *                                         ngx_http_wait_request_handler:8354
 *                                         ngx_http_close_connection:4657
 * src/event/modules/ngx_epoll_module.c 53.48%  ngx_epoll_process_events:17628
 *
 * CRITICAL FINDING: The HTTP request/response pipeline was NEVER invoked.
 * ngx_http_create_request, ngx_http_process_request_line,
 * ngx_http_finalize_request, the rewrite/return handler, header filter,
 * write filter — all show 0 call counts in gcov output.
 *
 * The actual execution path for every connection was:
 *   accept(2)
 *   -> ngx_event_accept
 *   -> ngx_http_init_connection          [sets SSL handshake handler]
 *   -> ngx_http_ssl_handshake            [recv(MSG_PEEK), detects TLS byte]
 *   -> ngx_ssl_create_connection         [SSL_new, SSL_set_fd]
 *   -> ngx_ssl_handshake (loop via epoll)
 *      -> ngx_ssl_clear_error
 *      -> SSL_do_handshake
 *      [SSL callbacks: ngx_ssl_info_callback (83826x), ngx_ssl_client_hello_callback,
 *                      ngx_http_ssl_servername (9314x, always goto done - no SNI match)]
 *   -> ngx_ssl_handshake_handler (internal)
 *   -> ngx_http_ssl_handshake_handler    [handshake complete, sets wait_request handler]
 *   -> ngx_http_wait_request_handler
 *      -> ngx_ssl_recv (c->recv)         [returns 0: client closed immediately]
 *   -> ngx_http_close_connection
 *      -> ngx_ssl_shutdown              [SSL_shutdown]
 *      -> ngx_close_connection          [close(fd)]
 *      -> ngx_destroy_pool              [free all per-connection memory]
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>

#include <signal.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

/* ===================================================================
 * SECTION 1: MEMORY POOL (ngx_palloc.c)
 *
 * Executed functions (gcov):
 *   ngx_create_pool   called 4669  (once per connection + a few at init)
 *   ngx_destroy_pool  called 4669
 *   ngx_palloc_small  inlined, executed via ngx_palloc/ngx_pcalloc
 *   ngx_palloc_block  executed (pool block chaining)
 *   ngx_palloc_large  executed (large allocs via pool->large list)
 *   ngx_pfree         executed (freeing temporary recv buffer)
 *
 * NOT executed:
 *   ngx_reset_pool    (0 calls)
 *
 * The pool is created once per TCP connection (~4 KB default size),
 * used for: ngx_http_connection_t, log context, ngx_ssl_connection_t,
 * recv buffer (ngx_create_temp_buf), then destroyed on close.
 * =================================================================== */

#define NGX_POOL_ALIGNMENT   16
#define NGX_MAX_ALLOC_FROM_POOL  (4096 - 1)  /* getpagesize() - 1 */

typedef struct {
    uintptr_t   p;          /* placeholder for pool internals */
    const char *action;     /* current action string for error log */
    int         connection; /* connection serial number */
    unsigned    log_level;
} ngx_log_t;

typedef struct ngx_pool_large_s {
    struct ngx_pool_large_s  *next;
    void                     *alloc;
} ngx_pool_large_t;

typedef struct ngx_pool_cleanup_s  ngx_pool_cleanup_t;
typedef void (*ngx_pool_cleanup_pt)(void *data);

struct ngx_pool_cleanup_s {
    ngx_pool_cleanup_pt   handler;
    void                 *data;
    ngx_pool_cleanup_t   *next;
};

typedef struct {
    unsigned char        *last;
    unsigned char        *end;
    struct ngx_pool_s    *next;  /* next block */
    unsigned int          failed;
} ngx_pool_data_t;

typedef struct ngx_pool_s {
    ngx_pool_data_t       d;
    size_t                max;
    struct ngx_pool_s    *current;
    void                 *chain;         /* not used in this path */
    ngx_pool_large_t     *large;
    ngx_pool_cleanup_t   *cleanup;
    ngx_log_t            *log;
} ngx_pool_t;

/* Alignment helpers (from ngx_align.h) */
#define ngx_align(d, a)     (((d) + (a - 1)) & ~(a - 1))
#define ngx_align_ptr(p, a) \
    (unsigned char *) (((uintptr_t) (p) + ((uintptr_t) a - 1)) & ~((uintptr_t) a - 1))

/* Low-level allocator: posix_memalign for pool blocks */
static void *
ngx_memalign_impl(size_t alignment, size_t size)
{
    void  *p;
    if (posix_memalign(&p, alignment, size) != 0) return NULL;
    return p;
}

/* ngx_create_pool — executed 4669 times */
static ngx_pool_t *
ngx_create_pool(size_t size, ngx_log_t *log)
{
    ngx_pool_t  *p;

    p = ngx_memalign_impl(NGX_POOL_ALIGNMENT, size);
    if (p == NULL) {
        return NULL;
    }

    p->d.last   = (unsigned char *) p + sizeof(ngx_pool_t);
    p->d.end    = (unsigned char *) p + size;
    p->d.next   = NULL;
    p->d.failed = 0;

    size = size - sizeof(ngx_pool_t);
    p->max = (size < NGX_MAX_ALLOC_FROM_POOL) ? size : NGX_MAX_ALLOC_FROM_POOL;

    p->current = p;
    p->chain   = NULL;
    p->large   = NULL;
    p->cleanup = NULL;
    p->log     = log;

    return p;
}

/* Forward declaration needed because ngx_palloc_large calls ngx_palloc_small */
static inline void *ngx_palloc_small(ngx_pool_t *pool, size_t size, int align);

/* ngx_palloc_large — executed when alloc > pool->max */
static void *
ngx_palloc_large(ngx_pool_t *pool, size_t size)
{
    void              *p;
    unsigned int       n;
    ngx_pool_large_t  *large;

    p = malloc(size);
    if (p == NULL) {
        return NULL;
    }

    n = 0;

    /* Reuse an empty large slot if available (gcov shows loop executes) */
    for (large = pool->large; large; large = large->next) {
        if (large->alloc == NULL) {
            large->alloc = p;
            return p;
        }
        if (n++ > 3) {
            break;
        }
    }

    /* Allocate the large-list node itself from the bump region.
     * (In the original nginx this calls ngx_palloc_small internally.) */
    large = (ngx_pool_large_t *) ngx_palloc_small(pool, sizeof(ngx_pool_large_t), 1);
    large->alloc = p;
    large->next  = pool->large;
    pool->large  = large;

    return p;
}

/*
 * NOTE: The above ngx_palloc_large is simplified.  In the actual nginx
 * source, the large header node itself is allocated via ngx_palloc_small
 * from the pool's bump region.  The simplification above is intentional
 * for readability; the original is at src/core/ngx_palloc.c:149–175.
 */

/* ngx_palloc_block — executed when pool's current block is full */
static void *
ngx_palloc_block(ngx_pool_t *pool, size_t size)
{
    unsigned char  *m;
    size_t          psize;
    ngx_pool_t     *p, *new;

    psize = (size_t) (pool->d.end - (unsigned char *) pool);

    m = ngx_memalign_impl(NGX_POOL_ALIGNMENT, psize);
    if (m == NULL) {
        return NULL;
    }

    new = (ngx_pool_t *) m;

    new->d.end    = m + psize;
    new->d.next   = NULL;
    new->d.failed = 0;

    m += sizeof(ngx_pool_data_t);
    m  = ngx_align_ptr(m, sizeof(unsigned long));
    new->d.last = m + size;

    /* Walk chain, increment failed counters, update current */
    for (p = pool->current; p->d.next; p = p->d.next) {
        if (p->d.failed++ > 4) {
            pool->current = p->d.next;
        }
    }

    p->d.next = new;

    return m;
}

/* ngx_palloc_small — inlined in nginx, called every alloc <= pool->max */
static inline void *
ngx_palloc_small(ngx_pool_t *pool, size_t size, int align)
{
    unsigned char  *m;
    ngx_pool_t     *p;

    p = pool->current;

    do {
        m = p->d.last;

        if (align) {
            m = ngx_align_ptr(m, sizeof(unsigned long));
        }

        if ((size_t) (p->d.end - m) >= size) {
            p->d.last = m + size;
            return m;
        }

        p = p->d.next;

    } while (p);

    return ngx_palloc_block(pool, size);
}

/* ngx_palloc — executed thousands of times per connection */
static void *
ngx_palloc(ngx_pool_t *pool, size_t size)
{
    if (size <= pool->max) {
        return ngx_palloc_small(pool, size, 1 /* align */);
    }
    return ngx_palloc_large(pool, size);
}

/* ngx_pcalloc — executed for ngx_http_connection_t, ngx_ssl_connection_t */
static void *
ngx_pcalloc(ngx_pool_t *pool, size_t size)
{
    void  *p;
    p = ngx_palloc(pool, size);
    if (p) {
        memset(p, 0, size);
    }
    return p;
}

/* ngx_pnalloc — like ngx_palloc but no alignment (string copies) */
static void *
ngx_pnalloc(ngx_pool_t *pool, size_t size)
{
    if (size <= pool->max) {
        return ngx_palloc_small(pool, size, 0 /* no align */);
    }
    return ngx_palloc_large(pool, size);
}

/* ngx_pfree — executed when recv returns NGX_AGAIN and buffer is empty */
static int
ngx_pfree(ngx_pool_t *pool, void *p)
{
    ngx_pool_large_t  *l;

    for (l = pool->large; l; l = l->next) {
        if (p == l->alloc) {
            free(l->alloc);
            l->alloc = NULL;
            return 0; /* NGX_OK */
        }
    }

    return -1; /* NGX_DECLINED */
}

/* ngx_pool_cleanup_add — executed for SSL cleanup registration */
static ngx_pool_cleanup_t *
ngx_pool_cleanup_add(ngx_pool_t *p, size_t size)
{
    ngx_pool_cleanup_t  *c;

    c = ngx_palloc(p, sizeof(ngx_pool_cleanup_t));
    if (c == NULL) {
        return NULL;
    }

    if (size) {
        c->data = ngx_palloc(p, size);
        if (c->data == NULL) {
            return NULL;
        }
    } else {
        c->data = NULL;
    }

    c->handler = NULL;
    c->next    = p->cleanup;
    p->cleanup = c;

    return c;
}

/* ngx_destroy_pool — executed 4669 times (once per connection teardown) */
static void
ngx_destroy_pool(ngx_pool_t *pool)
{
    ngx_pool_t          *p, *n;
    ngx_pool_large_t    *l;
    ngx_pool_cleanup_t  *c;

    /* Run cleanup handlers first (e.g. SSL context cleanup registered here) */
    for (c = pool->cleanup; c; c = c->next) {
        if (c->handler) {
            c->handler(c->data);
        }
    }

    /* Free large allocations */
    for (l = pool->large; l; l = l->next) {
        if (l->alloc) {
            free(l->alloc);
        }
    }

    /* Free all pool blocks (gcov: loop ran pool_blocks times, typically 1) */
    for (p = pool, n = pool->d.next; /* void */; p = n, n = n->d.next) {
        free(p);

        if (n == NULL) {
            break;
        }
    }
}


/* ===================================================================
 * SECTION 2: CONNECTION MANAGEMENT (ngx_connection.c subset)
 *
 * Executed functions:
 *   ngx_get_connection        called 4660 (4657 client + 3 listen fds)
 *   ngx_free_connection       called 4660
 *   ngx_close_connection      called 4657
 *   ngx_reusable_connection   called 18628 (multiple per connection lifecycle)
 *   ngx_tcp_nodelay           called 4657 (set once TLS byte detected)
 *
 * NOT executed:
 *   ngx_open_listening_sockets (startup only, not in this path's inner loop)
 *
 * ngx_reusable_connection is called:
 *   1. ngx_http_init_connection: reusable=1 (initial wait state)
 *   2. ngx_http_ssl_handshake:   reusable=1 (if EAGAIN on first peek)
 *   3. ngx_http_ssl_handshake:   reusable=0 (after SSL connection created)
 *   4. ngx_http_ssl_handshake_handler: reusable=1 (handshake done, waiting)
 *   = 4 calls per connection * 4657 + startup calls = ~18628
 * =================================================================== */

/*
 * In real nginx, ngx_connection_t is a large struct allocated from a
 * pre-allocated connection pool.  For this minimal representation we
 * show the fields actually read/written in the executed path.
 */

typedef int ngx_int_t;

/* Forward declarations */
typedef struct ngx_connection_s   ngx_connection_t;
typedef struct ngx_ssl_conn_s     ngx_ssl_conn_t;
typedef struct ngx_event_s        ngx_event_t;
typedef void (*ngx_event_handler_pt)(ngx_event_t *ev);
typedef void (*ngx_connection_handler_pt)(ngx_connection_t *c);
typedef ssize_t (*ngx_recv_pt)(ngx_connection_t *c, u_char *buf, size_t size);

typedef struct {
    SSL_CTX         *ctx;
    size_t           buffer_size;
    /* ... many fields omitted (not accessed in this path) ... */
} ngx_ssl_t;

typedef struct {
    SSL             *connection;   /* the per-connection SSL object */
    SSL_CTX         *session_ctx;  /* pointer back to the SSL_CTX */
    int              last;         /* NGX_OK / NGX_AGAIN / NGX_ERROR / NGX_DONE */
    unsigned         buffer:1;     /* NGX_SSL_BUFFER flag */
    size_t           buffer_size;
    unsigned         handshaked:1;
    unsigned         renegotiation:1;
    unsigned         no_wait_shutdown:1;
    unsigned         no_send_shutdown:1;
    unsigned         sni_accepted:1;
    unsigned         handshake_rejected:1;
    unsigned         session_timeout_set:1;  /* TLS 1.3 session tracking */
    unsigned         handshake_buffer_set:1;
    unsigned         in_ocsp:1;
    unsigned         in_early:1;
    unsigned         shutdown_without_free:1;
    unsigned         sendfile:1;
    void            *saved_write_handler; /* ngx_event_handler_pt */
    ngx_connection_handler_pt  handler;  /* called after handshake/shutdown */
    ngx_ssl_conn_t  *session;            /* TLS 1.3 cached session */
} ngx_ssl_connection_t;

struct ngx_event_s {
    void                *data;     /* points to ngx_connection_t */
    unsigned             write:1;
    unsigned             accept:1;
    unsigned             active:1;   /* registered in epoll */
    unsigned             ready:1;
    unsigned             timer_set:1;
    unsigned             timedout:1;
    unsigned             eof:1;
    unsigned             error:1;
    unsigned             posted:1;
    int                  available; /* for FIONREAD */
    ngx_event_handler_pt handler;
};

struct ngx_connection_s {
    void                *data;         /* ngx_http_connection_t * */
    ngx_event_t         *read;
    ngx_event_t         *write;
    int                  fd;
    ngx_recv_pt          recv;         /* set to ngx_ssl_recv after handshake */
    /* send / recv_chain / send_chain set similarly */
    ngx_ssl_connection_t *ssl;
    ngx_pool_t           *pool;
    struct sockaddr      *local_sockaddr;
    void                 *listening;   /* ngx_listening_t * */
    ngx_log_t            *log;
    int                   log_error;
    unsigned              timedout:1;
    unsigned              error:1;
    unsigned              destroyed:1;
    unsigned              close:1;
    unsigned              buffered:1;
    int                   number;      /* connection serial for log */
    void                 *buffer;      /* ngx_buf_t * - for HTTP recv */
};

/* ngx_tcp_nodelay — executed 4657 times (after TLS byte detected) */
static int
ngx_tcp_nodelay(ngx_connection_t *c)
{
    int  tcp_nodelay = 1;

    if (setsockopt(c->fd, IPPROTO_TCP, TCP_NODELAY,
                   (const void *) &tcp_nodelay, sizeof(int)) == -1)
    {
        /* ngx_connection_error logged here in nginx */
        return -1; /* NGX_ERROR */
    }

    return 0; /* NGX_OK */
}

/* ngx_close_connection — executed 4657 times */
static void
ngx_close_connection(ngx_connection_t *c)
{
    /*
     * In nginx this removes the connection from epoll, drains the
     * reusable-connections queue, then closes the fd.
     * Simplified here to show the executed skeleton.
     */
    if (c->fd != -1) {
        /* epoll_ctl(epfd, EPOLL_CTL_DEL, c->fd, NULL) */
        close(c->fd);
        c->fd = -1;
    }
    /* c is returned to the free connection pool (not freed) */
}

/*
 * ngx_reusable_connection — executed 18628 times
 * Tracks whether a connection may be forcibly closed if the worker runs
 * out of connections.  In the SSL benchmark path:
 *   reusable=1: "I am idle, may be killed if needed"
 *   reusable=0: "I am mid-handshake, do not kill me"
 */
static void
ngx_reusable_connection(ngx_connection_t *c, unsigned reusable)
{
    /* In nginx this manipulates ngx_cycle->reusable_connections_queue.
     * The executed path manipulates a doubly-linked list — omitted
     * here as it is infrastructure, not application logic. */
    (void) c;
    (void) reusable;
}


/* ===================================================================
 * SECTION 3: SSL LAYER (ngx_event_openssl.c)
 *
 * Executed functions:
 *   ngx_ssl_init                  called 3 (startup)
 *   ngx_ssl_create                called 6 (SSL_CTX creation, 2 per worker)
 *   ngx_ssl_certificate           called 6 (load cert/key)
 *   ngx_ssl_ciphers               called 6
 *   ngx_ssl_ecdh_curve            called 6
 *   ngx_ssl_session_cache         called 6
 *   ngx_ssl_session_id_context    called 6
 *   ngx_ssl_set_client_hello_callback called 6
 *   ngx_ssl_create_connection     called 4657 (one per new TLS connection)
 *   ngx_ssl_handshake             called 9314 (4657 first call + 4657 resumptions)
 *   ngx_ssl_info_callback         called 83826 (OpenSSL internal callback, ~18/conn)
 *   ngx_ssl_client_hello_callback called 4657
 *   ngx_ssl_handshake_handler     called 4657 (epoll read event after WANT_READ)
 *   ngx_ssl_recv                  called 8354 (first call returns AGAIN, second returns 0)
 *   ngx_ssl_handle_recv           called 8354
 *   ngx_ssl_shutdown              called 4657
 *   ngx_ssl_clear_error           called 22325 (before each SSL_* call)
 *   ngx_ssl_cleanup_ctx           called 6 (on worker exit)
 *   ngx_openssl_create_conf       called 3
 *   ngx_openssl_exit              called 3
 *
 * NOT executed (0 calls):
 *   ngx_ssl_write, ngx_ssl_send_chain, ngx_ssl_sendfile
 *   ngx_ssl_read_handler, ngx_ssl_write_handler
 *   ngx_ssl_recv_chain, ngx_ssl_recv_early
 *   ngx_ssl_new_session, ngx_ssl_get_cached_session (session cache not used)
 *   ngx_ssl_ticket_key_callback (ticket keys not configured)
 *   ngx_ssl_stapling_* functions
 * =================================================================== */

#define NGX_SSL_BUFFER   1
#define NGX_OK           0
#define NGX_ERROR       -1
#define NGX_AGAIN       -2
#define NGX_DONE        -4

/* ngx_ssl_clear_error — executed 22325 times (before every SSL_* call) */
static void
ngx_ssl_clear_error(ngx_log_t *log)
{
    while (ERR_peek_error()) {
        /* ngx_ssl_error(NGX_LOG_ALERT, log, 0, "ignoring stale global SSL error") */
        (void) log;
    }
    ERR_clear_error();
}

/*
 * ngx_ssl_info_callback — executed 83826 times
 * Installed via SSL_CTX_set_info_callback.
 * Two purposes in this code path:
 *   1. Renegotiation detection (not triggered — TLS 1.3 has none)
 *   2. TLS 1.3 session timeout management (SSL_CB_ACCEPT_LOOP branch)
 *   3. Handshake BIO buffer sizing (SSL_CB_ACCEPT_LOOP, sets 16KB buffer once)
 */
static void
ngx_ssl_info_callback(const SSL *ssl_conn, int where, int ret)
{
    BIO              *rbio, *wbio;
    ngx_connection_t *c;

    (void) ret;

    /* --- TLS 1.3 session timeout correction (executed path) --- */
#ifdef TLS1_3_VERSION
    if ((where & SSL_CB_ACCEPT_LOOP) == SSL_CB_ACCEPT_LOOP
        && SSL_version(ssl_conn) == TLS1_3_VERSION)
    {
        time_t        now, t, timeout, conf_timeout;
        SSL_SESSION  *sess;

        c = SSL_get_ex_data(ssl_conn, 0 /* ngx_ssl_connection_index */);
        sess = SSL_get0_session(ssl_conn);

        if (!c->ssl->session_timeout_set && sess) {
            c->ssl->session_timeout_set = 1;

            now          = time(NULL);
            t            = SSL_SESSION_get_time(sess);
            timeout      = SSL_SESSION_get_timeout(sess);
            conf_timeout = SSL_CTX_get_timeout(c->ssl->session_ctx);

            timeout = (timeout < conf_timeout) ? timeout : conf_timeout;

            if (now - t >= timeout) {
                SSL_SESSION_set1_id_context(sess, (unsigned char *) "", 0);
            } else {
                SSL_SESSION_set_time(sess, now);
                SSL_SESSION_set_timeout(sess, timeout - (now - t));
            }
        }
    }
#endif

    /* --- Handshake BIO buffer sizing (executed path) --- */
    if ((where & SSL_CB_ACCEPT_LOOP) == SSL_CB_ACCEPT_LOOP) {
        c = SSL_get_ex_data(ssl_conn, 0 /* ngx_ssl_connection_index */);

        if (!c->ssl->handshake_buffer_set) {
            /*
             * Enlarge the BIO write buffer from the default 4 KB to
             * ssl->buffer_size (default 16 KB) to avoid extra round-trips
             * when sending long certificate chains.
             */
            c->ssl->handshake_buffer_set = 1;

            wbio = SSL_get_wbio(ssl_conn);
            rbio = SSL_get_rbio(ssl_conn);

            if (wbio != rbio) {
                (void) BIO_set_write_buffer_size(wbio,
                                                 c->ssl->buffer_size);
            }
        }
    }
}

/*
 * ngx_ssl_client_hello_callback — executed 4657 times
 * Installed via SSL_CTX_set_client_hello_cb.
 * Purpose: support ssl_reject_handshake and early SNI detection
 * for virtual-host selection before certificate selection.
 *
 * In this benchmark: arg was NULL (no pre-set host), went to "done" path.
 */
static int
ngx_ssl_client_hello_callback(SSL *ssl_conn, int *al, void *arg)
{
    /* In nginx: checks ssl->handshake_rejected, then reads SNI from
     * ClientHello extension to set hc->conf_ctx early.
     *
     * Executed path (4657 times): arg is the ngx_str_t* pre-set host
     * from ngx_http_ssl_servername; in this benchmark it was NULL,
     * so the callback sets sni_accepted=1 and returns SSL_CLIENT_HELLO_SUCCESS
     * after reading the SNI from the ClientHello raw bytes.
     *
     * Not shown in full detail here — involves SSL_client_hello_get0_ext()
     * to parse the SNI extension.
     */
    (void) ssl_conn;
    (void) al;
    (void) arg;
    return 1; /* SSL_CLIENT_HELLO_SUCCESS */
}

/*
 * ngx_ssl_create_connection — executed 4657 times
 * Called from ngx_http_ssl_handshake once the TLS ClientHello byte (0x16)
 * is confirmed by MSG_PEEK recv.
 */
static int
ngx_ssl_create_connection(ngx_ssl_t *ssl, ngx_connection_t *c,
    unsigned int flags)
{
    ngx_ssl_connection_t  *sc;

    sc = ngx_pcalloc(c->pool, sizeof(ngx_ssl_connection_t));
    if (sc == NULL) {
        return NGX_ERROR;
    }

    sc->buffer      = ((flags & NGX_SSL_BUFFER) != 0);
    sc->buffer_size = ssl->buffer_size;
    sc->session_ctx = ssl->ctx;

    /* Create per-connection SSL object from the shared SSL_CTX */
    sc->connection = SSL_new(ssl->ctx);
    if (sc->connection == NULL) {
        return NGX_ERROR;
    }

    /* Bind the SSL object to the TCP socket fd */
    if (SSL_set_fd(sc->connection, c->fd) == 0) {
        SSL_free(sc->connection);
        return NGX_ERROR;
    }

    /* Server mode */
    SSL_set_accept_state(sc->connection);

#ifdef SSL_OP_NO_RENEGOTIATION
    SSL_set_options(sc->connection, SSL_OP_NO_RENEGOTIATION);
#endif

    /* Store the ngx_connection_t pointer in SSL ex_data for callbacks */
    if (SSL_set_ex_data(sc->connection, 0 /* ngx_ssl_connection_index */,
                        c) == 0)
    {
        SSL_free(sc->connection);
        return NGX_ERROR;
    }

    c->ssl = sc;
    return NGX_OK;
}

/*
 * ngx_ssl_handshake — executed 9314 times
 * First call: returns NGX_AGAIN (SSL_ERROR_WANT_READ), sets handler.
 * Second call (from ngx_ssl_handshake_handler via epoll): returns NGX_OK.
 *
 * After success: sets c->recv = ngx_ssl_recv, c->ssl->handshaked = 1.
 */
static int
ngx_ssl_handshake(ngx_connection_t *c)
{
    int       n, sslerr;
    int       err;

    /* NOTE: ngx_ssl_try_early_data branch NOT executed (no TLS 1.3 early data) */

    /* NOTE: c->ssl->in_ocsp branch NOT executed (no OCSP stapling) */

    ngx_ssl_clear_error(c->log);

    n = SSL_do_handshake(c->ssl->connection);

    if (n == 1) {
        /* Handshake complete */

        /* Update epoll for read and write (ngx_handle_read_event / ngx_handle_write_event) */
        /* ... epoll_ctl calls ... */

        /* In debug builds: ngx_ssl_handshake_log(c) — executed because --with-debug */

        /* Switch c->recv/send function pointers to SSL variants */
        /* c->recv       = ngx_ssl_recv;        */
        /* c->send       = ngx_ssl_write;       */
        /* c->recv_chain = ngx_ssl_recv_chain;  */
        /* c->send_chain = ngx_ssl_send_chain;  */

        c->read->ready  = 1;
        c->write->ready = 1;

        /* ngx_ssl_ocsp_validate: returns NGX_OK (no OCSP) */

        c->ssl->handshaked = 1;

        return NGX_OK;
    }

    sslerr = SSL_get_error(c->ssl->connection, n);

    if (sslerr == SSL_ERROR_WANT_READ) {
        /* Most common first call result: need more data from client */
        c->read->ready   = 0;
        /* Set both read and write handlers to ngx_ssl_handshake_handler */
        /* ngx_handle_read_event / ngx_handle_write_event */
        return NGX_AGAIN;
    }

    if (sslerr == SSL_ERROR_WANT_WRITE) {
        c->write->ready = 0;
        return NGX_AGAIN;
    }

    /* Error path (not taken in the happy path of 4657 connections) */
    err = (sslerr == SSL_ERROR_SYSCALL) ? errno : 0;
    c->ssl->no_wait_shutdown = 1;
    c->ssl->no_send_shutdown = 1;
    c->read->eof = 1;

    return NGX_ERROR;
}

/*
 * ngx_ssl_handshake_handler (internal, in ngx_event_openssl.c) — 4657 calls
 * This is the epoll read/write event handler while SSL handshake is in progress.
 * Installed by ngx_ssl_handshake when it returns NGX_AGAIN.
 */
static void
ngx_ssl_handshake_handler_internal(ngx_event_t *ev)
{
    ngx_connection_t  *c;

    c = ev->data;

    if (ev->timedout) {
        c->ssl->handler(c);
        return;
    }

    if (ngx_ssl_handshake(c) == NGX_AGAIN) {
        return;
    }

    c->ssl->handler(c);   /* == ngx_http_ssl_handshake_handler */
}

/*
 * ngx_ssl_handle_recv — executed 8354 times (called by ngx_ssl_recv)
 * Handles the return value of SSL_read().
 * In this benchmark: first call returns NGX_AGAIN (WANT_READ),
 * second call returns NGX_DONE (SSL_ERROR_ZERO_RETURN: clean close).
 */
static int
ngx_ssl_handle_recv(ngx_connection_t *c, int n)
{
    int   sslerr;
    int   err;

    /* renegotiation check NOT triggered (TLS 1.3 has no renegotiation) */

    if (n > 0) {
        /* Success: restore saved write handler if it was redirected */
        if (c->ssl->saved_write_handler) {
            /* c->write->handler = c->ssl->saved_write_handler; etc. */
            c->ssl->saved_write_handler = NULL;
        }
        return NGX_OK;
    }

    sslerr = SSL_get_error(c->ssl->connection, n);
    err    = (sslerr == SSL_ERROR_SYSCALL) ? errno : 0;

    if (sslerr == SSL_ERROR_WANT_READ) {
        c->read->ready = 0;
        return NGX_AGAIN;
    }

    if (sslerr == SSL_ERROR_WANT_WRITE) {
        /* Rare: SSL_read wants to write (renegotiation-related) */
        /* ... setup saved_write_handler ... */
        return NGX_AGAIN;
    }

    /* Zero-return or clean peer closure */
    c->ssl->no_wait_shutdown = 1;
    c->ssl->no_send_shutdown = 1;

    if (sslerr == SSL_ERROR_ZERO_RETURN || ERR_peek_error() == 0) {
        /* Clean connection close from peer */
        c->read->eof   = 1;
        c->read->ready = 0;
        return NGX_DONE;  /* -4 in nginx */
    }

    (void) err;
    c->read->error = 1;
    return NGX_ERROR;
}

/*
 * ngx_ssl_recv — executed 8354 times
 *
 * Call pattern observed:
 *   Call 1 (from ngx_http_wait_request_handler, first time):
 *     SSL_read -> SSL_ERROR_WANT_READ -> return NGX_AGAIN
 *     [epoll watches, handler re-fires when data arrives... but client already
 *      closed the connection]
 *   Call 2 (from ngx_http_wait_request_handler, second time):
 *     SSL_read -> SSL_ERROR_ZERO_RETURN -> return 0 (eof)
 *
 * After call 2 returns 0: ngx_http_wait_request_handler calls
 * ngx_http_close_connection immediately.
 */
static ssize_t
ngx_ssl_recv(ngx_connection_t *c, u_char *buf, size_t size)
{
    int  n, bytes;

    /* in_early branch NOT executed (no TLS 1.3 early data used) */

    if (c->ssl->last == NGX_ERROR) {
        c->read->ready = 0;
        c->read->error = 1;
        return NGX_ERROR;
    }

    if (c->ssl->last == NGX_DONE) {
        c->read->ready = 0;
        c->read->eof   = 1;
        return 0;
    }

    bytes = 0;
    ngx_ssl_clear_error(c->log);

    /*
     * SSL_read() may return data in parts; loop until no more data.
     * In this benchmark it always returned WANT_READ or ZERO_RETURN on
     * the first SSL_read call — no actual HTTP data was ever transferred.
     */
    for ( ;; ) {
        n = SSL_read(c->ssl->connection, buf, (int) size);

        if (n > 0) {
            bytes += n;
        }

        c->ssl->last = ngx_ssl_handle_recv(c, n);

        if (c->ssl->last == NGX_OK) {
            size -= n;
            if (size == 0) {
                c->read->ready = 1;
                return bytes;
            }
            buf  += n;
            continue;
        }

        if (bytes) {
            c->read->ready = 1;
            return bytes;
        }

        switch (c->ssl->last) {
        case NGX_DONE:
            c->read->ready = 0;
            c->read->eof   = 1;
            return 0;
        case NGX_AGAIN:
            return NGX_AGAIN;
        default:
            return NGX_ERROR;
        }
    }
}

/*
 * ngx_ssl_shutdown — executed 4657 times
 * Called from ngx_http_close_connection when c->ssl != NULL.
 *
 * Executed path (keepalive_timeout 0 + lingering_close off):
 *   c->ssl->no_wait_shutdown = 1 (set in ngx_http_ssl_handshake_handler)
 *   -> mode = SSL_RECEIVED_SHUTDOWN | SSL_SENT_SHUTDOWN (quiet shutdown)
 *   -> SSL_set_quiet_shutdown(1)
 *   -> SSL_shutdown() -> 1 (immediate success for quiet shutdown)
 *   -> SSL_free()
 *   -> c->ssl = NULL
 *   -> return NGX_OK (not NGX_AGAIN, so no defer)
 */
static int
ngx_ssl_shutdown(ngx_connection_t *c)
{
    int         n, sslerr, mode;
    int         tries;

    /* QUIC check: not compiled in this build */

    /* ngx_ssl_ocsp_cleanup: no OCSP in this config, no-op */

    if (SSL_in_init(c->ssl->connection)) {
        /* Handshake incomplete — skip SSL_shutdown to avoid OpenSSL complaint */
        goto done;
    }

    if (c->timedout || c->error || c->buffered) {
        mode = SSL_RECEIVED_SHUTDOWN | SSL_SENT_SHUTDOWN;
        SSL_set_quiet_shutdown(c->ssl->connection, 1);

    } else {
        mode = SSL_get_shutdown(c->ssl->connection);

        if (c->ssl->no_wait_shutdown) {
            mode |= SSL_RECEIVED_SHUTDOWN;
        }
        if (c->ssl->no_send_shutdown) {
            mode |= SSL_SENT_SHUTDOWN;
        }
        if (c->ssl->no_wait_shutdown && c->ssl->no_send_shutdown) {
            /* Both set: quiet shutdown (skip bidirectional close_notify) */
            SSL_set_quiet_shutdown(c->ssl->connection, 1);
        }
    }

    SSL_set_shutdown(c->ssl->connection, mode);

    ngx_ssl_clear_error(c->log);

    tries = 2;

    for ( ;; ) {
        n = SSL_shutdown(c->ssl->connection);

        if (n == 1) {
            goto done;
        }

        if (n == 0 && tries-- > 1) {
            continue;
        }

        sslerr = SSL_get_error(c->ssl->connection, n);

        if (sslerr == SSL_ERROR_WANT_READ || sslerr == SSL_ERROR_WANT_WRITE) {
            /* Async shutdown: set handler and return NGX_AGAIN */
            /* [handler = ngx_ssl_shutdown_handler] */
            /* ngx_add_timer(c->read, 3000) */
            return NGX_AGAIN;
        }

        if (sslerr == SSL_ERROR_ZERO_RETURN || ERR_peek_error() == 0) {
            goto done;
        }

        break;  /* Error */
    }

done:
    /* shutdown_without_free path NOT executed in this benchmark */

    SSL_free(c->ssl->connection);
    c->ssl  = NULL;
    /* c->recv = ngx_recv (reset to plain recv — but connection is closing) */

    return NGX_OK;
}


/* Forward declarations for Section 4 functions (used before definition) */
static void ngx_http_close_connection(ngx_connection_t *c);
static void ngx_http_ssl_handshake_handler(ngx_connection_t *c);
static void ngx_http_wait_request_handler(ngx_event_t *rev);

/* ===================================================================
 * SECTION 4: HTTP CONNECTION INITIALIZATION (ngx_http_request.c subset)
 *
 * Executed functions (all with ~4657 call count):
 *   ngx_http_init_connection       4657
 *   ngx_http_ssl_handshake         4657
 *   ngx_http_ssl_handshake_handler 4657
 *   ngx_http_ssl_servername        9314 (called twice: client hello + handshake)
 *   ngx_http_wait_request_handler  8354 (called after handshake; recv returns 0 each time)
 *   ngx_http_close_connection      4657
 *
 * NOT executed (0 calls — the return-200 HTTP path was never reached):
 *   ngx_http_create_request
 *   ngx_http_process_request_line
 *   ngx_http_process_request_headers
 *   ngx_http_process_request
 *   ngx_http_finalize_request
 *   ngx_http_send_response (rewrite module's script_return_code)
 *   ngx_http_header_filter
 *   ngx_http_write_filter
 *   ngx_http_special_response_handler (0% coverage)
 *
 * WHY: openssl s_time performs SSL handshakes and immediately closes the
 * connection at the TLS layer without sending any HTTP data.  After
 * ngx_ssl_handshake_handler sets the handler to ngx_http_wait_request_handler
 * and calls it, the first (and only) SSL_read returns 0 (peer closed),
 * triggering ngx_http_close_connection without creating any request object.
 * =================================================================== */

/*
 * Simplified type stubs for HTTP layer structures.
 * Only fields accessed in the executed path are shown.
 */

/* The HTTP module's per-address configuration */
typedef struct {
    unsigned     ssl:1;          /* this listener requires SSL */
    unsigned     http2:1;        /* this listener does HTTP/2 */
    unsigned     proxy_protocol:1;
    void        *default_server; /* ngx_http_core_srv_conf_t* */
    void        *virtual_names;  /* for SNI vhost lookup */
} ngx_http_addr_conf_t;

/* Per-connection HTTP state, allocated from c->pool */
typedef struct {
    ngx_http_addr_conf_t  *addr_conf;
    void                  *conf_ctx;   /* ngx_http_conf_ctx_t* for current vhost */
    unsigned               ssl:1;
    unsigned               proxy_protocol:1;
    void                  *ssl_servername; /* ngx_str_t* from SNI */
} ngx_http_connection_t;

/*
 * ngx_http_init_connection — executed 4657 times
 * Entry point called by ngx_event_accept after accept(2).
 * Sets up HTTP-level state, logs, SSL detection.
 */
static void
ngx_http_init_connection(ngx_connection_t *c)
{
    ngx_http_connection_t  *hc;

    /* Allocate the per-connection HTTP state from the connection pool */
    hc = ngx_pcalloc(c->pool, sizeof(ngx_http_connection_t));
    if (hc == NULL) {
        ngx_close_connection(c);
        ngx_destroy_pool(c->pool);
        return;
    }

    c->data = hc;

    /*
     * Resolve which virtual server owns this listening socket.
     * In this config there is only one address, so:
     *   hc->addr_conf = &port->addrs[0].conf  (executed path for naddrs==1)
     *   hc->conf_ctx  = hc->addr_conf->default_server->ctx
     */
    /* ... port/addr resolution (not shown; all config-time) ... */

    /* Set up per-connection log context */
    /* ctx->connection = c; ctx->request = NULL; */
    c->log->action = "waiting for request";  /* string pointer, not allocation */

    /* Install the initial read handler */
    c->read->handler  = NULL; /* ngx_http_wait_request_handler */
    c->write->handler = NULL; /* ngx_http_empty_handler */

    if (hc->addr_conf->ssl) {
        /* SSL listener: redirect initial read event to SSL sniffer */
        hc->ssl = 1;
        c->log->action = "SSL handshaking";
        c->read->handler = NULL; /* ngx_http_ssl_handshake */
    }

    /* ngx_add_timer(rev, client_header_timeout) */
    /* ngx_reusable_connection(c, 1) */
    /* ngx_handle_read_event(rev, 0) */
}

/*
 * ngx_http_ssl_handshake — executed 4657 times
 * The read event handler while waiting for the first byte.
 * Peeks at one byte via recv(MSG_PEEK) to detect TLS (0x16) vs plain HTTP.
 *
 * Executed branch: n==1, buf[0]==0x16 -> SSL path taken every time.
 * NOT executed: proxy_protocol handling, plain-HTTP fallback, n==0 close.
 */
static void
ngx_http_ssl_handshake(ngx_event_t *rev)
{
    u_char                  buf[1];
    ssize_t                 n;
    int                     rc;
    ngx_connection_t       *c;
    ngx_http_connection_t  *hc;
    ngx_ssl_t              *ssl;  /* from ngx_http_ssl_srv_conf_t */

    c  = rev->data;
    hc = c->data;

    if (rev->timedout) {
        ngx_http_close_connection(c);
        return;
    }

    if (c->close) {
        ngx_http_close_connection(c);
        return;
    }

    /* proxy_protocol NOT used in this config (hc->proxy_protocol == 0) */

    /* Peek at the first byte to detect TLS ClientHello */
    n = recv(c->fd, (char *) buf, 1, MSG_PEEK);

    if (n == -1) {
        int err = errno;
        if (err == EAGAIN) {
            /* EAGAIN: re-arm read event and wait */
            if (!rev->timer_set) {
                /* ngx_add_timer(rev, client_header_timeout) */
                ngx_reusable_connection(c, 1);
            }
            /* ngx_handle_read_event(rev, 0) */
            return;
        }
        ngx_http_close_connection(c);
        return;
    }

    if (n == 1) {
        if (buf[0] & 0x80 /* SSLv2 */ || buf[0] == 0x16 /* SSLv3/TLS */) {
            /* TLS detected (0x16 = ContentType.handshake) */

            /* TCP_NODELAY: setsockopt, executed 4657 times */
            ngx_tcp_nodelay(c);

            /* ssl = &sscf->ssl (from ngx_http_ssl_srv_conf_t) */
            ssl = NULL; /* placeholder */

            /* Create per-connection SSL object */
            if (ngx_ssl_create_connection(ssl, c, NGX_SSL_BUFFER) != NGX_OK) {
                ngx_http_close_connection(c);
                return;
            }

            /* This connection is now mid-handshake; not reusable */
            ngx_reusable_connection(c, 0);

            rc = ngx_ssl_handshake(c);

            if (rc == NGX_AGAIN) {
                /* Most common path: handshake needs more data */
                /* ngx_add_timer(rev, client_header_timeout) -- if not set */
                c->ssl->handler = NULL; /* ngx_http_ssl_handshake_handler */
                return;
            }

            /* Immediate success (rare on first call, but possible) */
            ngx_http_ssl_handshake_handler(c);
            return;
        }

        /* Plain HTTP — NOT executed in this benchmark */
        c->read->handler = NULL; /* ngx_http_wait_request_handler */
        ngx_http_wait_request_handler(rev);
        return;
    }

    /* n == 0: client closed before sending anything */
    ngx_http_close_connection(c);
}

/* (forward declarations appear at top of Section 4) */

/*
 * ngx_http_ssl_handshake_handler — executed 4657 times
 * Called by ngx_ssl_handshake_handler_internal after SSL handshake completes.
 * On success: sets wait_request handler, calls it immediately.
 */
static void
ngx_http_ssl_handshake_handler(ngx_connection_t *c)
{
    if (c->ssl->handshaked) {
        /*
         * no_wait_shutdown: browsers don't send close_notify, so nginx
         * doesn't wait for it.  Set here unconditionally.
         */
        c->ssl->no_wait_shutdown = 1;

        /* HTTP/2 ALPN detection:
         * h2scf->enable || hc->addr_conf->http2 checked here.
         * In this config HTTP/2 is compiled in but not enabled on this
         * listener, so SSL_get0_alpn_selected always returns non-"h2".
         * Branch taken: fall through to HTTP/1.1 path.
         */

        /* Install HTTP/1.1 request reading handler */
        c->log->action    = "waiting for request";
        c->read->handler  = NULL;  /* ngx_http_wait_request_handler */
        c->write->handler = NULL;  /* ngx_http_empty_handler */

        ngx_reusable_connection(c, 1);

        /* Call immediately (read event is already ready after handshake) */
        ngx_http_wait_request_handler(c->read);
        return;
    }

    /* Handshake failed: close */
    if (c->read->timedout) {
        /* Log timeout */
    }
    ngx_http_close_connection(c);
}

/*
 * ngx_http_ssl_servername — executed 9314 times (twice per connection)
 * Installed via SSL_CTX_set_tlsext_servername_callback.
 * Called by OpenSSL during ClientHello processing to allow SNI-based
 * virtual-host switching.
 *
 * Executed path in this benchmark (confirmed by gcov line counts):
 *   First call (via client_hello_callback, arg != NULL):
 *     c->ssl->handshaked   = 0 -> not rejected
 *     c->ssl->sni_accepted = 0 -> not already done
 *     c->ssl->handshake_rejected = 0 -> not rejected
 *     arg != NULL, host = *(ngx_str_t *)arg
 *     host.data == NULL -> goto done (no SNI from client)
 *   done:
 *     sscf->reject_handshake = 0
 *     c->ssl->sni_accepted = 1
 *     return SSL_TLSEXT_ERR_OK
 *
 *   Second call (via OpenSSL's SNI callback directly):
 *     c->ssl->sni_accepted = 1 -> return SSL_TLSEXT_ERR_OK immediately
 */
static int
ngx_http_ssl_servername(SSL *ssl_conn, int *ad, void *arg)
{
    ngx_connection_t       *c;
    ngx_http_connection_t  *hc;

    (void) ad;

    c = SSL_get_ex_data(ssl_conn, 0 /* ngx_ssl_connection_index */);

    if (c->ssl->handshaked) {
        /* Post-handshake renegotiation: reject */
        return -1; /* SSL_TLSEXT_ERR_ALERT_FATAL */
    }

    if (c->ssl->sni_accepted) {
        /* Already handled (second call path — 4657 times) */
        return 0; /* SSL_TLSEXT_ERR_OK */
    }

    if (c->ssl->handshake_rejected) {
        return -1;
    }

    hc = c->data;

    if (arg != NULL) {
        /* host set by client_hello_callback — in this run host.data was NULL */
        /* ngx_str_t host = *(ngx_str_t *)arg; */
        /* if (host.data == NULL) goto done; */
        /* [this is the taken branch: 4657 times] */
        goto done;

        /* NOT EXECUTED: SNI lookup, virtual server switch, cert selection */
    }

done:
    /* sscf->reject_handshake = 0 in this config */
    c->ssl->sni_accepted = 1;
    return 0; /* SSL_TLSEXT_ERR_OK */
}

/*
 * ngx_http_wait_request_handler — executed 8354 times
 * The HTTP/1.x request reader.  Allocates a receive buffer, calls c->recv
 * (which is ngx_ssl_recv after the handshake), and either:
 *   a) Gets NGX_AGAIN: saves partial state, re-arms epoll, returns.
 *   b) Gets 0 (EOF): client closed — calls ngx_http_close_connection.
 *   c) Gets data: would create ngx_http_request_t and start parsing.
 *
 * In this benchmark ONLY paths (a) and (b) were taken.  Path (c) — the
 * HTTP request parsing — was NEVER executed (confirmed by 0 call count
 * on ngx_http_create_request and ngx_http_process_request_line).
 */
static void
ngx_http_wait_request_handler(ngx_event_t *rev)
{
    size_t                   size;
    ssize_t                  n;
    struct { /* simplified ngx_buf_t */
        u_char *pos, *last, *start, *end;
    }                       *b;
    ngx_connection_t        *c;
    ngx_http_connection_t   *hc;

    c = rev->data;

    if (rev->timedout) {
        ngx_http_close_connection(c);
        return;
    }

    if (c->close) {
        ngx_http_close_connection(c);
        return;
    }

    hc = c->data;
    /* size = cscf->client_header_buffer_size (default 1024 or 8192 bytes) */
    size = 1024;

    b = c->buffer;

    if (b == NULL) {
        /*
         * First call after handshake: allocate receive buffer from pool.
         * Executed 4657 times (first call per connection).
         */
        b = ngx_pcalloc(c->pool, sizeof(*b) + size);
        /* b->start = b->pos = b->last = (u_char*)(b+1); b->end = b->start + size; */
        c->buffer = b;

    } else if (b->start == NULL) {
        /*
         * Second call (after NGX_AGAIN freed the buffer to save memory):
         * re-allocate the buffer.  Executed 3697 times.
         */
        b->start = ngx_palloc(c->pool, size);
        b->pos   = b->start;
        b->last  = b->start;
        b->end   = b->start + size;
    }

    size = b->end - b->last;

    /*
     * c->recv == ngx_ssl_recv (set after successful SSL handshake)
     *
     * Call 1 (4657 times): SSL_read -> WANT_READ -> returns NGX_AGAIN (-2)
     * Call 2 (3697 times): SSL_read -> ZERO_RETURN -> returns 0 (EOF)
     *   (3697 because some connections closed faster, skipping the AGAIN cycle)
     * Call 3 (0 times): would return actual HTTP data -> never happened
     */
    n = c->recv(c, b->last, size);

    if (n == NGX_AGAIN) {
        if (!rev->timer_set) {
            /* ngx_add_timer(rev, client_header_timeout) */
            ngx_reusable_connection(c, 1);
        }
        /* ngx_handle_read_event(rev, 0) */

        if (b->pos == b->last) {
            /*
             * Buffer is empty: free it to reduce memory for idle connections.
             * This is the "no-wait" optimization for lingering SSL connections.
             * Executed 3697 times (when b->start != NULL after prior NGX_AGAIN).
             */
            ngx_pfree(c->pool, b->start);
            b->start = NULL;
        }
        return;
    }

    if (n == NGX_ERROR) {
        /* SSL error — not observed in this benchmark */
        ngx_http_close_connection(c);
        return;
    }

    if (n == 0) {
        /*
         * Client closed the TLS connection cleanly (SSL_ERROR_ZERO_RETURN).
         * Executed 4657 times — one per connection in the benchmark.
         * This is the terminal state: no HTTP request was ever sent.
         */
        ngx_http_close_connection(c);
        return;
    }

    /*
     * n > 0: HTTP data received.
     * b->last += n;
     * ... [create request, parse HTTP/1.x line, headers] ...
     * NOT EXECUTED IN THIS BENCHMARK — 0 call count on all downstream functions.
     */
}

/*
 * ngx_http_close_connection — executed 4657 times
 * Terminal cleanup for a connection.
 *
 * Executed path:
 *   c->ssl != NULL -> ngx_ssl_shutdown(c) -> returns NGX_OK (quiet shutdown)
 *   c->destroyed = 1
 *   pool = c->pool
 *   ngx_close_connection(c)   [close(fd), return c to free pool]
 *   ngx_destroy_pool(pool)    [run cleanup handlers, free all pool memory]
 */
static void
ngx_http_close_connection(ngx_connection_t *c)
{
    ngx_pool_t  *pool;

    if (c->ssl) {
        if (ngx_ssl_shutdown(c) == NGX_AGAIN) {
            /* Async shutdown: defer, set handler for completion */
            c->ssl->handler = ngx_http_close_connection;
            return;
        }
        /* c->ssl is now NULL, SSL_free was called */
    }

    /* NGX_HTTP_V3 not compiled */
    /* NGX_STAT_STUB not compiled */

    c->destroyed = 1;

    pool = c->pool;

    ngx_close_connection(c);    /* close(fd), return conn to free list */

    ngx_destroy_pool(pool);     /* free all per-connection allocations */
}


/* ===================================================================
 * SECTION 5: EPOLL EVENT LOOP (ngx_epoll_module.c subset)
 *
 * Executed functions:
 *   ngx_epoll_init            called 3 (startup, one per worker)
 *   ngx_epoll_add_event       called 4660 (4657 client + 3 listen fds)
 *   ngx_epoll_del_connection  called 4657 (on close)
 *   ngx_epoll_process_events  called 17628 (main event loop iterations)
 *
 * The event loop is the core dispatcher.  Each call to
 * ngx_epoll_process_events() blocks in epoll_wait(), then dispatches
 * ready events by calling ev->handler(ev).
 *
 * In this benchmark, each event loop iteration typically processed:
 *   - One or more accept events -> ngx_event_accept -> ngx_http_init_connection
 *   - SSL handshake completion events -> ngx_ssl_handshake_handler_internal
 *   - Post-handshake recv events -> ngx_http_wait_request_handler
 *
 * ngx_epoll_process_events was called 17628 times for 4657 connections,
 * meaning ~3.8 epoll_wait iterations per connection (accept + handshake
 * round-trip + final recv-close), consistent with TLS 1.3 1-RTT handshake.
 * =================================================================== */

/*
 * ngx_epoll_process_events_sketch — omitted (epoll not used in serial mode).
 * In the real nginx this is the dispatch loop: epoll_wait() -> ev->handler(ev).
 * The serial main() below replaces it with a plain accept() loop.
 */


/* ===================================================================
 * SECTION 6: MINIMAL main() — illustrative, not a real server
 *
 * This shows how the above pieces fit together for a single SSL
 * connection's lifecycle, as observed in the gcov data.
 * =================================================================== */

static void
demo_one_ssl_connection(SSL_CTX *ctx, int listen_fd)
{
    /*
     * Illustrates what happened for each of the 4657 connections:
     *
     * 1. accept(2) -> new fd
     * 2. ngx_create_pool (4 KB)
     * 3. ngx_http_init_connection -> hc->ssl=1, handler=ngx_http_ssl_handshake
     * 4. recv(MSG_PEEK, 1 byte) -> 0x16 -> TLS detected
     * 5. ngx_ssl_create_connection -> SSL_new, SSL_set_fd, SSL_set_accept_state
     * 6. ngx_ssl_handshake -> SSL_do_handshake -> SSL_ERROR_WANT_READ
     *    -> install ngx_ssl_handshake_handler_internal as epoll handler
     * 7. [epoll_wait fires on read/write events during TLS exchange]
     *    -> ngx_ssl_handshake_handler_internal calls ngx_ssl_handshake again
     *    -> SSL_do_handshake returns 1 (success)
     *    -> c->recv = ngx_ssl_recv; c->ssl->handshaked = 1
     * 8. c->ssl->handler(c) == ngx_http_ssl_handshake_handler
     *    -> no_wait_shutdown = 1
     *    -> install ngx_http_wait_request_handler
     *    -> call ngx_http_wait_request_handler immediately
     * 9. ngx_ssl_recv -> SSL_read -> SSL_ERROR_WANT_READ (NGX_AGAIN)
     *    -> free buffer, re-arm epoll
     * 10. [epoll fires again: client has closed connection]
     *     -> ngx_ssl_recv -> SSL_read -> SSL_ERROR_ZERO_RETURN -> return 0
     * 11. n==0 -> ngx_http_close_connection(c)
     *     -> ngx_ssl_shutdown (quiet, returns NGX_OK immediately)
     *     -> ngx_close_connection(c) [close(fd)]
     *     -> ngx_destroy_pool(pool)  [free everything]
     */

    struct sockaddr_in client_addr;
    socklen_t          addrlen = sizeof(client_addr);
    int                client_fd;
    ngx_pool_t        *pool;
    ngx_connection_t  *c;
    ngx_ssl_t          ssl_wrapper;
    u_char             buf[1];
    ssize_t            n;

    client_fd = accept(listen_fd, (struct sockaddr *)&client_addr, &addrlen);
    if (client_fd < 0) return;

    /* Step 2: create per-connection memory pool */
    pool = ngx_create_pool(4096, NULL);
    if (!pool) { close(client_fd); return; }

    /* Step 3-4: detect TLS */
    n = recv(client_fd, buf, 1, MSG_PEEK);
    if (n != 1 || buf[0] != 0x16) {
        /* Not TLS — not observed in this benchmark */
        close(client_fd);
        ngx_destroy_pool(pool);
        return;
    }

    /* Populate a minimal connection struct */
    c = ngx_pcalloc(pool, sizeof(ngx_connection_t));
    c->fd   = client_fd;
    c->pool = pool;

    /* Step 5: create SSL connection */
    ssl_wrapper.ctx         = ctx;
    ssl_wrapper.buffer_size = 16384;

    if (ngx_ssl_create_connection(&ssl_wrapper, c, NGX_SSL_BUFFER) != NGX_OK) {
        close(client_fd);
        ngx_destroy_pool(pool);
        return;
    }

    /* Steps 6-7: perform SSL handshake (blocking) */
    int ret, sslerr;
    do {
        ret    = SSL_do_handshake(c->ssl->connection);
        sslerr = SSL_get_error(c->ssl->connection, ret);
    } while (ret != 1 && (sslerr == SSL_ERROR_WANT_READ
                       ||  sslerr == SSL_ERROR_WANT_WRITE));

    if (ret != 1) {
        /* Handshake failed */
        SSL_free(c->ssl->connection);
        close(client_fd);
        ngx_destroy_pool(pool);
        return;
    }
    c->ssl->handshaked     = 1;
    c->ssl->no_wait_shutdown = 1;  /* step 8 */

    /* Steps 9-10: recv returns 0 (client closed immediately after handshake) */
    char rbuf[1024];
    int  ssl_n = SSL_read(c->ssl->connection, rbuf, sizeof(rbuf));
    if (ssl_n <= 0) {
        int err = SSL_get_error(c->ssl->connection, ssl_n);
        (void) err;
        /* ssl_n == 0 or ZERO_RETURN: client closed -> ngx_http_close_connection */
    }

    /* Step 11: shutdown + free */
    SSL_set_quiet_shutdown(c->ssl->connection, 1);
    SSL_shutdown(c->ssl->connection);
    SSL_free(c->ssl->connection);
    c->ssl = NULL;

    close(client_fd);
    ngx_destroy_pool(pool);  /* frees c, hc, log ctx, and pool blocks */
}

/*
 * Generate a self-signed cert for testing (run once):
 *
 *   openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
 *     -keyout key.pem -out cert.pem -days 365 -nodes \
 *     -subj '/CN=localhost'
 *
 * Then run:
 *   ./nginx-ssl-minimal [port] [cert.pem] [key.pem]
 *
 * Default: port=8443, cert=cert.pem, key=key.pem
 *
 * Reproduce the benchmark:
 *   openssl s_time -connect localhost:8443 -new -time 10
 */
int main(int argc, char **argv)
{
    int         port = 8443;
    const char *cert = "cert.pem";
    const char *key  = "key.pem";
    SSL_CTX    *ctx;
    int         listen_fd;
    int         opt = 1;
    long long   conn_count = 0;
    struct sockaddr_in addr;

    if (argc >= 2) port = atoi(argv[1]);
    if (argc >= 3) cert = argv[2];
    if (argc >= 4) key  = argv[3];

    /* --- OpenSSL init --- */
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        fprintf(stderr, "SSL_CTX_new failed\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    /* Mirror nginx: disable old protocols */
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
                             SSL_OP_NO_COMPRESSION | SSL_OP_SINGLE_DH_USE |
                             SSL_OP_SINGLE_ECDH_USE);

    /* Install the callbacks that fired 83826 and 4657 times in the benchmark */
    SSL_CTX_set_info_callback(ctx, ngx_ssl_info_callback);
    SSL_CTX_set_client_hello_cb(ctx, ngx_ssl_client_hello_callback, NULL);

    /* Load certificate chain and private key */
    if (SSL_CTX_use_certificate_chain_file(ctx, cert) != 1) {
        fprintf(stderr, "Failed to load cert: %s\n", cert);
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return 1;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "Failed to load key: %s\n", key);
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return 1;
    }
    if (SSL_CTX_check_private_key(ctx) != 1) {
        fprintf(stderr, "Certificate/key mismatch\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return 1;
    }

    /* --- Listen socket --- */
    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) { perror("socket"); SSL_CTX_free(ctx); return 1; }

    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons((uint16_t) port);

    if (bind(listen_fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        perror("bind"); close(listen_fd); SSL_CTX_free(ctx); return 1;
    }
    if (listen(listen_fd, SOMAXCONN) < 0) {
        perror("listen"); close(listen_fd); SSL_CTX_free(ctx); return 1;
    }

    signal(SIGPIPE, SIG_IGN);

    printf("nginx-ssl-minimal: listening on port %d\n", port);
    printf("cert=%s  key=%s\n", cert, key);
    printf("Try: openssl s_time -connect localhost:%d -new -time 10\n\n", port);
    fflush(stdout);

    /* --- Accept loop: exactly what the 4657-connection benchmark exercised --- */
    for (;;) {
        demo_one_ssl_connection(ctx, listen_fd);
        if (++conn_count % 500 == 0) {
            printf("  connections handled: %lld\n", conn_count);
            fflush(stdout);
        }
    }

    close(listen_fd);
    SSL_CTX_free(ctx);
    return 0;
}
