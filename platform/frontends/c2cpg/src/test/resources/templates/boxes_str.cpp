/* The second unit of the template project: the same header's templates used
 * with the unit's own types, the unsigned instantiation of the function
 * template, and the instantiation of the seeded bugs that carries them. */
#include "tmplbox.hpp"

/* A plain type of this unit: the class template is used with it here and with
 * int in the other unit. */
struct Str
{
    unsigned len;
};

/* Larger than the scratch buffer: sizeof(Record) is 16, sizeof(Str) is 4. */
struct Record
{
    char tag[12];
    unsigned len;
};

unsigned use_str_boxes()
{
    TBox<Str> wbox;
    Str text{ 3 };
    wbox.put(text);
    Str read = wbox.get();

    /* The function template's unsigned instantiation: the other type. */
    unsigned biggest = tmax(3u, 4u);

    /* The look-alike: the pointer is valid, so the write is safe. */
    fill_checked(&wbox);

    /* The record instantiation of the scratch bug writes past the bound:
     * sizeof(Record) is 16 and the array holds 8 bytes. */
    Scratch<Record> scratch;
    scratch.stamp();

    /* The str instantiation stays inside the bound. */
    Scratch<Str> small;
    small.stamp();

    /* The guarded look-alike skips the write for Record entirely. */
    ScratchGuarded<Record> guarded;
    guarded.stamp();

    return read.len + biggest;
}

/* The seeded bug in this unit: this pointer is null too, so the Str
 * instantiation of fill dereferences null on the same header line. */
int broken_str_boxes()
{
    TBox<Str> *none = nullptr;
    fill(none);
    return 0;
}
