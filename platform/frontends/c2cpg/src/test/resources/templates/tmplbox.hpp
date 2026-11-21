/* The template constructs the analysis sees in a C++ project: a class template
 * whose members both units use with their own argument type, a function template
 * used with two types, an explicit and a partial specialisation, a variadic
 * template, templates nothing instantiates, and two seeded memory-safety bugs
 * with their correct look-alikes. Both units of the project include this header.
 */
#ifndef TMPLBOX_HPP
#define TMPLBOX_HPP

/* A class template whose members each unit uses with its own argument type. */
template<typename T>
struct TBox
{
    T value;

    T get() const { return value; }

    void put(const T &v) { value = v; }

    /* A member nothing instantiates: no unit calls audit, whatever T is. */
    T audit() const { return value; }
};

/* A partial specialisation: a box that holds a pointer instead of a value. */
template<typename T>
struct TBox<T *>
{
    T *ptr;

    T *get() const { return ptr; }

    void put(T *p) { ptr = p; }
};

/* A function template nothing instantiates: no unit calls tally. */
template<typename T>
T tally(const T *items, unsigned count)
{
    return count == 0 ? T() : items[0];
}

/* A function template used with two argument types, and an explicit
 * specialisation for double whose call links to its own METHOD. */
template<typename T>
T tmax(T a, T b)
{
    return a > b ? a : b;
}

template<>
double tmax<double>(double a, double b)
{
    return a > b ? a : b;
}

/* A variadic template: the unit calls it with two arguments. */
template<typename... Rest>
unsigned count_args(const Rest &...)
{
    return sizeof...(Rest);
}

/* The seeded bug every instantiation has: both units call fill with a null
 * box, so every instantiation dereferences null on the same line. */
template<typename T>
void fill(TBox<T> *box)
{
    box->put(T()); /* @expect cwe=476 kind=null-deref */
}

/* The correct look-alike: the check first, the same call afterwards. */
template<typename T>
void fill_checked(TBox<T> *box)
{
    if (box != nullptr)
        box->put(T()); /* @nofinding */
}

/* The seeded bug only one instantiation has: the index is sizeof(T), which is
 * 16 for Record and 4 for int, and the array holds 8 bytes. */
template<typename T>
struct Scratch
{
    char bytes[8];

    void stamp() { bytes[sizeof(T)] = 'x'; /* @expect cwe=787 kind=oob-write index=sizeof */ }
};

/* The correct look-alike: the same write, guarded by the bound. */
template<typename T>
struct ScratchGuarded
{
    char bytes[8];

    void stamp()
    {
        if (sizeof(T) < 8)
            bytes[sizeof(T)] = 'x'; /* @nofinding */
    }
};

#endif
