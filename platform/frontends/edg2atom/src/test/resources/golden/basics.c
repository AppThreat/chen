/* Structs, typedefs, enums, arrays, loops, switches and pointer walks. */
struct point {
  int x;
  int y;
};
typedef unsigned long size_type;
enum color { RED, GREEN = 4, BLUE };
static int table[8];

int sum(const struct point *p, int n) {
  int total = 0;
  for (int i = 0; i < n; i++) total += p[i].x + p[i].y;
  return total;
}

size_type count_red(const enum color *c, size_type n) {
  size_type k = 0;
  while (n-- > 0)
    if (*c++ == RED) k++;
  return k;
}

void fill(int v) {
  for (int i = 0; i < 8; i++) table[i] = v;
}

char *copy_into(char *dst, const char *src, size_type n) {
  size_type i;
  for (i = 0; i < n && src[i]; i++) dst[i] = src[i];
  dst[i] = '\0';
  return dst;
}

int classify(int v) {
  switch (v) {
    case 0:
      return RED;
    case 1:
      return GREEN;
    default:
      break;
  }
  return v > 0 ? BLUE : -1;
}
