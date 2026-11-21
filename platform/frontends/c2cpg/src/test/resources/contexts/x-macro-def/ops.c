#define X(name) OP_##name,
enum op_code {
#include "ops.def"
    OP_COUNT
};

int op_dispatch(int op)
{
    switch (op) {
#undef X
#define X(name) case OP_##name: return op;
#include "ops.def"
    default:
        return -1;
    }
}
