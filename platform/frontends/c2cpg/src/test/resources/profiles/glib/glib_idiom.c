/* Zeroed allocation handed to a caller, released by the library's own free, and ownership
 * moved out of a variable through the steal idiom. */
#include <glib.h>
#include <gmem.h>

struct blob {
    unsigned char bytes[16];
};

struct blob *blob_copy(struct blob *src) {
    struct blob *copy = (struct blob *) g_new0(sizeof(struct blob), 1);
    for (int i = 0; i < 16; i++) {
        copy->bytes[i] = src->bytes[i];
    }
    return copy;
}

void blob_drop(struct blob *b) {
    g_free(b);
}

struct blob *blob_hand_over(struct blob **owner) {
    return (struct blob *) g_steal_pointer((void **) owner);
}

void scoped_scratch(void) {
    char *scratch __attribute__((cleanup(g_autoptr_cleanup_generic_gfree))) = g_new0(1, 16);
    if (scratch == NULL) return;
    scratch[0] = 1;
}
