/* Declaration-only stand-in for the kernel's device-managed allocator header. */
struct device;

void *devm_kzalloc(struct device *dev, unsigned long size, unsigned int flags);
void *devm_kcalloc(struct device *dev, unsigned long n, unsigned long size, unsigned int flags);
