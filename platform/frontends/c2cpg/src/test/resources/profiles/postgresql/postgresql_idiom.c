/* Allocation from the current memory context, release through the context's own free, and
 * the create, reset and destroy lifecycle of a context. */
#include <postgres.h>
#include <utils/palloc.h>
#include <utils/memutils.h>

struct setting {
    unsigned char name[16];
};

unsigned char *copy_name(struct setting *s) {
    unsigned char *copy = (unsigned char *) palloc(16);
    for (int i = 0; i < 16; i++) {
        copy[i] = s->name[i];
    }
    return copy;
}

unsigned char *copy_name_zeroed(struct setting *s) {
    unsigned char *copy = (unsigned char *) palloc0(16);
    for (int i = 0; i < 16; i++) {
        copy[i] = s->name[i];
    }
    return copy;
}

void drop_copy(unsigned char *p) {
    pfree(p);
}

MemoryContext make_scratch(MemoryContext parent) {
    return AllocSetContextCreate(parent, "scratch", 0, 1024, 8192);
}

void reset_scratch(MemoryContext scratch) {
    MemoryContextReset(scratch);
}

void drop_scratch(MemoryContext scratch) {
    MemoryContextDelete(scratch);
}
