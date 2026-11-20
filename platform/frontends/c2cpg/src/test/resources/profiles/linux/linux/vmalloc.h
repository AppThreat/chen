/* Declaration-only stand-in for the kernel's virtually contiguous allocator header. */
void *vmalloc(unsigned long size);
void vfree(const void *addr);
