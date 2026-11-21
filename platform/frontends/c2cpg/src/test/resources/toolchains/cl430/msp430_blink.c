// TI's MSP430 compiler defines __MSP430__ with its version macro.
#if !defined(__MSP430__) || !defined(__TI_COMPILER_VERSION__)
#error "this unit is compiled by cl430, its identifying macros are not defined"
#endif

int toggle(int state) { return state ^ 1; }
