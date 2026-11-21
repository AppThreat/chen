// A bare-metal GCC cross build: the target macros of the arm-none-eabi triple gate the
// busy-wait this delay uses.
#if !defined(__GNUC__) || !defined(__arm__)
#error "this unit is compiled by arm-none-eabi-gcc, its target macros are not defined"
#endif

volatile int ticks;

void delay(int n) {
    for (int i = 0; i < n; i++) ticks++;
}
