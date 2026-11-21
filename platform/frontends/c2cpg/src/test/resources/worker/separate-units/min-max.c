#include "pair.h"

int smaller(int a, int b) { return a < b ? a : b; }

int larger(int a, int b) { return a < b ? b : a; }

int first_of(pair_t p) { return pair_first(p); }
