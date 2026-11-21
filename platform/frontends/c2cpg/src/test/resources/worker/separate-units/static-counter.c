int next_ticket(void)
{
    static int counter;
    return ++counter;
}

int tickets_issued(void) { return next_ticket() + next_ticket(); }
