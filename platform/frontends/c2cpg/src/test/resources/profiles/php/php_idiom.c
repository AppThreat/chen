/* Blocks from the request heap, and a string released through its refcount. */
#include <zend_alloc.h>
#include <zend_string.h>

void *scratch(unsigned long n) {
    return emalloc(n);
}

void scratch_drop(void *p) {
    efree(p);
}

void string_drop(zend_string *s) {
    zend_string_release(s);
}
