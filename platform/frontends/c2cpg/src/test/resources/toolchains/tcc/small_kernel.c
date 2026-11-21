// A source tuned for TinyCC's C99 subset, compiled by the tcc driver.
#if !defined(__TINYC__)
#error "this unit is compiled by tcc, __TINYC__ is not defined"
#endif

int step(int state) { return (state * 1103515245 + 12345) & 0x7fffffff; }
