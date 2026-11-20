/* Declaration-only stand-in for the pool allocator header. */
typedef struct apr_pool_t apr_pool_t;
typedef int apr_status_t;

apr_status_t apr_pool_create(apr_pool_t **newpool, apr_pool_t *parent);
void *apr_palloc(apr_pool_t *p, unsigned long size);
void apr_pool_clear(apr_pool_t *p);
void apr_pool_destroy(apr_pool_t *p);
