#ifndef SAMPLE_LIB_H
#define SAMPLE_LIB_H

typedef struct sample { int len; char *data; } sample_t;

static int sample_len(sample_t *s) { return s->len; }

#endif
