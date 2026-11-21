#pragma once

/* The edge a window spans, selected by the definition the build hands the unit. */
#ifdef WINDOW_WIDE
#define WINDOW_EDGE 4096
#else
#define WINDOW_EDGE 64
#endif
