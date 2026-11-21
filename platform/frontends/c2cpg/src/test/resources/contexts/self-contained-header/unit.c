#include "lib.h"
#include "plain.h"

int run(void)
{
    sample_t s = {0};
    struct plain p = {0};
    return sample_len(&s) + plain_tag(&p);
}
