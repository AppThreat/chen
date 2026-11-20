/* Declaration-only stand-in for the context allocator header, including the global that
 * plain palloc allocates from. */
#include <postgres.h>

typedef struct MemoryContextData *MemoryContext;

extern MemoryContext CurrentMemoryContext;

extern void *palloc(Size size);
extern void *palloc0(Size size);
extern void pfree(void *pointer);
