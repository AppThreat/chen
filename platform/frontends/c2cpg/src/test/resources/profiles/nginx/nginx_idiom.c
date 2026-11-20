/* Raw allocation through the library's malloc wrapper, and allocation from a pool whose
 * destroy releases everything it handed out. */
#include <ngx_core.h>
#include <ngx_palloc.h>

struct line {
    unsigned char text[16];
};

unsigned char *raw_block(ngx_log_t *log, unsigned long n) {
    return (unsigned char *) ngx_alloc(n, log);
}

void raw_drop(void *p) {
    ngx_free(p);
}

ngx_pool_t *pool_make(ngx_log_t *log) {
    return ngx_create_pool(1024, log);
}

void pool_drop(ngx_pool_t *pool) {
    ngx_destroy_pool(pool);
}

unsigned char *line_copy(ngx_pool_t *pool, struct line *l) {
    unsigned char *copy = (unsigned char *) ngx_palloc(pool, 16);
    for (int i = 0; i < 16; i++) {
        copy[i] = l->text[i];
    }
    return copy;
}
