// Function and class templates used with two types, and a lambda that captures.
template <class T> T max_of(T a, T b) { return a < b ? b : a; }

template <class T> struct Box {
  T v;
  T get() const { return v; }
};

int use(int a, long b) {
  Box<int> box{a};
  auto twice = [&](int x) { return x * 2 + a; };
  return max_of(a, box.get()) + static_cast<int>(max_of(b, 3L)) + twice(a);
}
