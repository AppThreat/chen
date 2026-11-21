unsigned mask_for(unsigned bits) { return bits >= 32 ? 0xffffffffu : ((1u << bits) - 1u); }

int flag_set(unsigned flags, unsigned bit)
{
    return (flags & (1u << bit)) != 0;
}

unsigned keep_low(unsigned value, unsigned bits) { return value & mask_for(bits); }
