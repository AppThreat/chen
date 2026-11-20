/* Declaration-only stand-in for the kernel's reference counter header. */
struct kref {
    unsigned int refcount;
};

int kref_put(struct kref *kref, void (*release)(struct kref *kref));
