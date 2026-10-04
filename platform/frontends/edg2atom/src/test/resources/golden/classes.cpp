// A class hierarchy with a virtual call, a constructor, an operator and aggregate initialisation.
namespace geo {
struct Point {
  int x, y;
  Point operator+(const Point &o) const { return {x + o.x, y + o.y}; }
};

class Shape {
 public:
  virtual ~Shape() {}
  virtual int area() const = 0;
};

class Rect : public Shape {
 public:
  Rect(int w, int h) : w_(w), h_(h) {}
  int area() const override { return w_ * h_; }

 private:
  int w_, h_;
};

int total(const Shape &a, const Shape &b) { return a.area() + b.area(); }

int use() {
  Rect r(2, 3);
  Point p{1, 2};
  Point q = p + p;
  return total(r, r) + q.x;
}
}  // namespace geo
