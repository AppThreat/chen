/* The first unit of the template project: the int instantiations, the dependent
 * calls probe and refill are instantiated with, the variadic call, the lambda
 * with an auto parameter, and the int instantiation of the seeded bugs. */
#include "tmplbox.hpp"

#include <algorithm>

/* A plain class the dependent call probe is instantiated with: its get() is a
 * different METHOD from the box's. */
struct Account
{
    int balance;

    int get() const { return balance; }
};

/* A dependent call: x.get() names a member of the template parameter itself,
 * so every instance of probe calls a different METHOD. */
template<typename T>
int probe(const T &x)
{
    return x.get();
}

/* A dependent call on a member of a class template instance: box.put and
 * box.get name members of TBox<T>, which only the unit's instances realise. */
template<typename T>
void refill(TBox<T> &box, const T &fresh)
{
    box.put(box.get());
    box.put(fresh);
}

unsigned use_boxes()
{
    TBox<int> box;
    box.put(3);
    int read = box.get();

    /* The partial specialisation: a box that holds a pointer. */
    TBox<int *> pbox;
    pbox.put(&read);
    int *taken = pbox.get();

    /* The function template used with two types: this unit instantiates it for
     * int, the other unit for unsigned. */
    int biggest = tmax(read, 2);

    /* The explicit specialisation: the double call links to its own METHOD. */
    double wide = tmax(1.5, 2.5);

    /* The variadic template, called with two arguments. */
    unsigned args = count_args(1, 2);

    /* A lambda with an auto parameter, run by a standard algorithm. */
    int nums[4]  = { 1, 2, 3, 4 };
    int nums_sum = 0;
    std::for_each(nums, nums + 4, [&nums_sum](const auto &n) { nums_sum += n; });

    /* The dependent call probe, instantiated once per argument type: the call
     * inside it reaches the box's get() here and the account's get() below. */
    Account acct{ 9 };
    int from_box = probe(box);
    int from_acct = probe(acct);

    /* The dependent call refill with a known argument type. */
    refill(box, 7);

    /* The look-alike: the pointer is valid, so the write is safe. */
    fill_checked(&box);

    /* The int instantiation of the scratch bug writes inside the bound. */
    Scratch<int> scratch;
    scratch.stamp();

    /* The guarded look-alike writes inside the bound too. */
    ScratchGuarded<int> guarded;
    guarded.stamp();

    return (unsigned)read + (unsigned)(taken - &read) + (unsigned)biggest +
           (unsigned)wide + args + (unsigned)nums_sum + (unsigned)from_box +
           (unsigned)from_acct;
}

/* The seeded bug in this unit: the box pointer is null, so the int
 * instantiation of fill dereferences null. */
int broken_boxes()
{
    TBox<int> *none = nullptr;
    fill(none);
    return 0;
}
