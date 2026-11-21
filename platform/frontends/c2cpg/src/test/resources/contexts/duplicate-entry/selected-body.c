/* The definition a build hands this file selects the bodies of both functions: the helper's
   return value and the total the caller adds to it. Listed twice in the compilation database
   with different definitions, each function has one body per context. */
static int amount(void)
{
#ifdef FAST_PATH
    return 2;
#else
    return 5;
#endif
}

int total(void)
{
#ifdef FAST_PATH
    return amount() + 1;
#else
    return amount() + 100;
#endif
}
