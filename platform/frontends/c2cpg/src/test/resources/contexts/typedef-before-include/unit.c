typedef struct { int n; char *buf; } ctx_t;
#include "impl.h"

int main(void)
{
    ctx_t c = {0};
    return get_n(&c);
}
