#include "pair.h"

void swap_ints(int *a, int *b)
{
    int held = *a;
    *a = *b;
    *b = held;
}

pair_t ordered_pair(int a, int b)
{
    if (a > b) swap_ints(&a, &b);
    pair_t p = {a, b};
    return p;
}
