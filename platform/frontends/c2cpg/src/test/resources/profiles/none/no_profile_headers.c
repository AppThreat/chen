/* Plain C with no library memory management header included: no profile applies. */
#include <stdio.h>

int greet(char *out, unsigned long n) {
    return snprintf(out, n, "hello");
}
