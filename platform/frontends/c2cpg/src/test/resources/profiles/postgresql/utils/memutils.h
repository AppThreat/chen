/* Declaration-only stand-in for the memory context management header. */
#include <utils/palloc.h>

extern MemoryContext AllocSetContextCreate(MemoryContext parent, const char *name,
                                           Size minContextSize, Size initBlockSize,
                                           Size maxBlockSize);
extern void MemoryContextReset(MemoryContext context);
extern void MemoryContextDelete(MemoryContext context);
