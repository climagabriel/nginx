typedef struct {
    off_t        start;
    off_t        end;
    ngx_str_t    content_range;
    off_t        range_offset;
} ngx_http_range_t;

