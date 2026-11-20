/* Declaration-only stand-in for glib's allocator header. The type-and-count allocation is
 * spelled with the element size here so the calls stay valid C; no body is ever in an
 * analysed tree, so the library's own behaviour governs these names. */
void *g_new0(unsigned long type_size, unsigned long n_structs);
void g_free(void *mem);
void *g_steal_pointer(void **pp);
void g_autoptr_cleanup_generic_gfree(void *pp);
