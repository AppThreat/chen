// The IAR compiler for Arm announces itself with __ICCARM__.
#if !defined(__ICCARM__)
#error "this unit is compiled by iccarm, __ICCARM__ is not defined"
#endif

extern void enable_irq(int n);
extern void disable_irq(int n);

int guarded_step(int n) {
    disable_irq(n);
    enable_irq(n);
    return n;
}
