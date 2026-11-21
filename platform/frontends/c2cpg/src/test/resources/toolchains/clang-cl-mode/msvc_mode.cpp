// clang in MSVC driver mode predefines the MSVC macros and its own identity.
#if !defined(_MSC_VER) || !defined(__clang__)
#error "this unit is compiled by clang --driver-mode=cl, its macros are not both defined"
#endif

struct Point {
    int x;
    int y;
};

int manhattan(const Point &p) { return p.x < 0 ? -p.x : p.x; }
