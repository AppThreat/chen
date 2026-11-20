/* Declaration-only stand-in for the object header. The reference count operations are
 * macros in the real header; they stay declared names here so the library's declared
 * release and acquire govern them. */
typedef struct _object PyObject;

void Py_INCREF(PyObject *o);
void Py_DECREF(PyObject *o);
