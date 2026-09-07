# CHEN-EXPECT: no-parse-errors
# CHEN-EXPECT: node-absent UNKNOWN  # nonlocal lowers to <operator>.nonlocal now

lazy = lambda: 1
def deep():
    x = 1
    def inner():
        nonlocal x
        x += 1
    return inner
async def am():
    async with open("f") as f, open("g") as g:
        pass
    async for i in arange():
        pass
    return [x async for x in arange()]

# Python 3.15 contextual lazy import (task 10: the flag defers loading; AST is an Import)
lazy import json
lazy from os import path as p
assert lazy is not None
