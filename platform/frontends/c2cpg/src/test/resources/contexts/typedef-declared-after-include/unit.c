#include "widget.h"

typedef struct { int len; } widget_t;

int main(void)
{
    widget_t w = {0};
    return widget_len(&w);
}
