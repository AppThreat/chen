/* Declaration-only stand-in for the pool allocator header. The real free is a macro over
 * the libc free; here it stays a declared name so the library's own release governs it. */
#include <ngx_core.h>

typedef struct ngx_pool_s ngx_pool_t;

void *ngx_alloc(unsigned long size, ngx_log_t *log);
void ngx_free(void *p);
ngx_pool_t *ngx_create_pool(unsigned long size, ngx_log_t *log);
void ngx_destroy_pool(ngx_pool_t *pool);
void *ngx_palloc(ngx_pool_t *pool, unsigned long size);
