/* Reference counts kept and released by hand, and a block from the interpreter's own
 * allocator domain. */
#include <object.h>
#include <pymem.h>

PyObject *keep(PyObject *src) {
    Py_INCREF(src);
    return src;
}

void release(PyObject *owned) {
    Py_DECREF(owned);
}

void *fresh_block(void) {
    return PyMem_Malloc(64);
}

void drop_block(void *p) {
    PyMem_Free(p);
}
