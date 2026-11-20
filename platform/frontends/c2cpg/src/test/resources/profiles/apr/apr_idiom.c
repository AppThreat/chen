/* Allocation from a pool that outlives the function, and the pool's create, clear and
 * destroy lifecycle. */
#include <apr_pools.h>

struct note {
    unsigned char text[16];
};

unsigned char *note_copy(apr_pool_t *pool, struct note *n) {
    unsigned char *copy = (unsigned char *) apr_palloc(pool, 16);
    for (int i = 0; i < 16; i++) {
        copy[i] = n->text[i];
    }
    return copy;
}

apr_status_t pool_make(apr_pool_t **out, apr_pool_t *parent) {
    return apr_pool_create(out, parent);
}

void pool_recycle(apr_pool_t *pool) {
    apr_pool_clear(pool);
}

void pool_drop(apr_pool_t *pool) {
    apr_pool_destroy(pool);
}
