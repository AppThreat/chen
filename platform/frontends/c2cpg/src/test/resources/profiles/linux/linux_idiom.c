/* Slab and vmalloc allocation with their releases, device-managed allocation owned by the
 * device, and a reference count handed to a release callback. */
#include <linux/slab.h>
#include <linux/kref.h>
#include <linux/gfp.h>
#include <linux/vmalloc.h>
#include <linux/device.h>

struct device {
    void *driver_data;
};

struct record {
    struct kref refs;
    unsigned char *payload;
};

static void record_release(struct kref *refs) {
    (void) refs;
}

void *page_scratch(unsigned long n) {
    return kmalloc(n, GFP_KERNEL);
}

struct record *record_new(unsigned long payload_size) {
    struct record *r = kzalloc(sizeof(struct record) + payload_size, GFP_KERNEL);
    return r;
}

void *sparse_block(unsigned long n) {
    return vmalloc(n);
}

void record_drop(struct record *r) {
    kfree(r);
}

void scratch_drop(void *p) {
    kvfree(p);
}

struct record *record_for_device(struct device *dev) {
    return devm_kzalloc(dev, sizeof(struct record), GFP_KERNEL);
}

struct record *records_for_device(struct device *dev, unsigned long n) {
    return devm_kcalloc(dev, n, sizeof(struct record), GFP_KERNEL);
}

int record_put(struct record *r) {
    return kref_put(&r->refs, record_release);
}
