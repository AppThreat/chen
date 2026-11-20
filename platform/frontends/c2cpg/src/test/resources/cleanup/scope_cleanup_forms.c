/* The GCC cleanup attribute on automatic variables, in the spellings projects use:
 * the attribute written out, Linux's DEFINE_FREE()/__free() pair, glib's g_autofree
 * and g_autoptr(), and systemd's _cleanup_free_. A cleanup function runs once per
 * exit of the variable's scope: where the block ends, before every return, and on
 * every goto, break or continue that leaves the scope.
 */
#include <stdlib.h>
#include <string.h>

typedef unsigned int gfp_t;
#define GFP_KERNEL 0xcc0

void *kmalloc(size_t size, gfp_t flags);
void kfree(const void *objp);

/* Linux: include/linux/cleanup.h and include/linux/slab.h, reduced to what is used here. */
#define __always_inline inline __attribute__((__always_inline__))
#define DEFINE_FREE(_name, _type, _free) \
    static __always_inline void __free_##_name(void *p) { _type _T = *(_type *)p; _free; }
#define __free(_name) __attribute__((__cleanup__(__free_##_name)))

DEFINE_FREE(kfree, void *, if (_T) kfree(_T))

/* glib: glib/gmacros.h and glib/glib-autocleanups.h, reduced the same way. */
typedef void *gpointer;
typedef struct _GHashTable GHashTable;

void g_free(void *mem);
char *g_strdup(const char *str);

#define _GLIB_CLEANUP(func) __attribute__((cleanup(func)))

static __attribute__((unused)) inline void
g_autoptr_cleanup_generic_gfree(void *p)
{
    void **pp = (void **)p;
    g_free(*pp);
    *pp = NULL;
}

#define g_autofree _GLIB_CLEANUP(g_autoptr_cleanup_generic_gfree)

#define _GLIB_AUTOPTR_FUNC_NAME(TypeName) glib_autoptr_cleanup_##TypeName
#define _GLIB_AUTOPTR_TYPENAME(TypeName) TypeName##_autoptr
#define _GLIB_DEFINE_AUTOPTR_CLEANUP_FUNCS(TypeName, cleanup) \
    typedef TypeName *_GLIB_AUTOPTR_TYPENAME(TypeName);        \
    static __attribute__((unused)) inline void                 \
    _GLIB_AUTOPTR_FUNC_NAME(TypeName)(TypeName **_ptr)         \
    { if (*_ptr) (cleanup)((TypeName *)*_ptr); }
#define G_DEFINE_AUTOPTR_CLEANUP_FUNC(TypeName, func) \
    _GLIB_DEFINE_AUTOPTR_CLEANUP_FUNCS(TypeName, func)
#define g_autoptr(TypeName) \
    _GLIB_CLEANUP(_GLIB_AUTOPTR_FUNC_NAME(TypeName)) _GLIB_AUTOPTR_TYPENAME(TypeName)

GHashTable *g_hash_table_new(int (*hash)(const void *), int (*equal)(const void *));
void g_hash_table_insert(GHashTable *table, gpointer key, gpointer value);
unsigned int g_hash_table_size(GHashTable *table);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(GHashTable, free)

/* systemd: src/basic/alloc-util.h, reduced. */
#define _cleanup_(x) __attribute__((__cleanup__(x)))

static inline void freep(void *p)
{
    free(*(void **)p);
    *(void **)p = NULL;
}

#define _cleanup_free_ _cleanup_(freep)

/* The plain GNU spelling, trailing the declarator: one cleanup call per exit. */
static int plain_attribute_exits(size_t len)
{
    char *buf __attribute__((cleanup(freep))) = malloc(len);
    if (buf == NULL)
        return -1;
    memset(buf, 0, len);
    if (len == 0)
        return -2;
    return 0;
}

/* The leading g_autofree spelling, at an early return and where the block ends. */
static void autofree_block_end(const char *input)
{
    g_autofree char *text = g_strdup(input);
    if (text == NULL)
        return;
    text[0] = 'x';
}

/* The g_autoptr() spelling with its generated cleanup function. */
static unsigned int autoptr_table(int (*hash)(const void *))
{
    g_autoptr(GHashTable) table = g_hash_table_new(hash, NULL);
    if (table == NULL)
        return 0;
    g_hash_table_insert(table, NULL, NULL);
    return g_hash_table_size(table);
}

/* The returned value names the cleaned-up variable, so it is read before the call. */
static char *return_of_cleaned_variable(size_t len)
{
    char *buf __free(kfree) = malloc(len);
    if (buf == NULL)
        return NULL;
    memset(buf, 0, len);
    return buf;
}

/* A return that reads through the cleaned-up pointer also stores its value first. */
static int return_reads_through(size_t len)
{
    char *buf __free(kfree) = malloc(len);
    if (buf == NULL)
        return -1;
    buf[0] = 7;
    return buf[0];
}

/* Nested scopes clean up inner first, and one scope's two variables in reverse
 * declaration order. */
static int inner_first_and_reverse_order(size_t n, const char *src)
{
    char *first __free(kfree) = malloc(n);
    _cleanup_free_ char *second = malloc(n);
    if (first == NULL || second == NULL)
        return -1;
    if (n > 8) {
        g_autofree char *inner = g_strdup(src);
        if (inner == NULL)
            return -2;
        memcpy(first, src, n);
        memcpy(second, src, n);
    }
    return (int)n;
}

/* A goto to a label outside the variable's block cleans up at the jump, and the
 * block's own end cleans up where control falls out of it. */
static int goto_leaving_nested(size_t n, const char *src)
{
    int rc = -1;
    if (n > 0) {
        char *buf __free(kfree) = malloc(n);
        if (buf == NULL)
            goto out;
        memcpy(buf, src, n);
        rc = 0;
    }
    return rc;
out:
    return -1;
}

/* A goto whose label stays inside the variable's scope does not clean up at the jump. */
static int goto_within_scope(size_t n)
{
    char *buf __free(kfree) = malloc(n);
    int rc = -1;
    if (buf == NULL)
        goto out;
    buf[0] = 1;
    rc = buf[0];
    goto done;
out:
    rc = -2;
done:
    if (rc < 0)
        return rc;
    return buf[0];
}

/* A break and a continue leave the loop body's block, and the body's end cleans up
 * where an iteration completes. */
static size_t loop_break_continue(const char **lines, size_t count)
{
    size_t kept = 0;
    for (size_t i = 0; i < count; i++) {
        g_autofree char *line = g_strdup(lines[i]);
        if (line == NULL)
            continue;
        if (line[0] == '#')
            break;
        kept += 1;
    }
    return kept;
}
