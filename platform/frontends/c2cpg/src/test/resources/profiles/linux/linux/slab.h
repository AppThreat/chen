/* Declaration-only stand-in for the kernel's slab allocator header. */
struct device;

void *kmalloc(unsigned long size, unsigned int flags);
void *kzalloc(unsigned long size, unsigned int flags);
void *kcalloc(unsigned long n, unsigned long size, unsigned int flags);
void *kmalloc_array(unsigned long n, unsigned long size, unsigned int flags);
void *kvmalloc(unsigned long size, unsigned int flags);
void *kvzalloc(unsigned long size, unsigned int flags);
void kfree(const void *obj);
void kvfree(const void *addr);
void *devm_kzalloc(struct device *dev, unsigned long size, unsigned int flags);
