// Arm Compiler for Embedded (armclang) for a Cortex-M4: its version macros gate the
// intrinsics this handler uses.
#if !defined(__ARMCC_VERSION) || __ARMCC_VERSION < 6000000
#error "this unit is compiled by armclang 6, __ARMCC_VERSION is not defined or too old"
#endif

extern void enable_irq(int n);
extern void disable_irq(int n);

int guarded_step(int n) {
    disable_irq(n);
    enable_irq(n);
    return n;
}
