enum op_code {
    OP_ADD,
    OP_SUB,
    OP_COUNT
};

int op_dispatch(int op)
{
    switch (op) {
    case OP_ADD:
        return op;
    case OP_SUB:
        return -op;
    default:
        return -1;
    }
}
