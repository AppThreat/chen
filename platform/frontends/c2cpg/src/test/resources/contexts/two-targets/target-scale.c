/* One file built for two targets: the scale factor is the target's, so the two build
   contexts compile different bodies of scale, while limit is the same in every build. */
int scale(int value)
{
#ifdef TARGET_WIDE
    return value * 2;
#else
    return value * 4;
#endif
}

int limit(int value)
{
    return value - 1;
}
