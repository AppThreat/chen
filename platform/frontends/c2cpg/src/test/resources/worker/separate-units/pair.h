#ifndef PAIR_H
#define PAIR_H

typedef struct
{
    int first;
    int second;
} pair_t;

static inline int pair_first(pair_t p) { return p.first; }
static inline int pair_second(pair_t p) { return p.second; }

#endif
