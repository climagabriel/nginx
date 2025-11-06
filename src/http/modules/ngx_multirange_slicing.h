typedef struct {
    off_t        start;
    off_t        end;
    ngx_str_t    content_range;
    off_t        fulfilled;
    unsigned     boundary_prepended:1;
    unsigned     boundary_appended:1;
} ngx_http_range_t;

