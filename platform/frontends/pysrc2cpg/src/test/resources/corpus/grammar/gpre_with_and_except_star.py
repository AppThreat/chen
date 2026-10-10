# CHEN-EXPECT: no-parse-errors
# CHEN-EXPECT: node-absent UNKNOWN
# `with (expr)... as name:` where the parentheses belong to the context EXPRESSION, not to a
# parenthesised item list (3.9+ grammar: the '(' with_item, ... ')' alternative fails and the
# plain form is tried). chen committed to the item-list reading after two tokens of lookahead,
# so the common pathlib idiom below failed in CPython's Lib (compileall.py, test_pathlib.py),
# aiohttp, pydantic, mcp-python-sdk and vulpy.
# Oracle: CPython 3.15.0
import contextlib
import pathlib

p = pathlib.Path(".")
cond = True

with (p / "setup.cfg").open() as f:
    pass
with (p / "a").open("r") as f, (p / "b").open("rb") as g:
    pass
with (open("a") if cond else contextlib.nullcontext()) as f:
    pass
with (open("a")) as f:
    pass
with (open("a")) as f, open("b") as g:
    pass
with (contextlib.nullcontext(), contextlib.nullcontext()) as pair:
    pass
with (contextlib.nullcontext()).__enter__() as entered:
    pass
# Parenthesised item lists (3.10) keep working.
with (open("a") as f, open("b") as g,):
    pass
with (open("a"), open("b")):
    pass
with (open("a") as f):
    pass
with (open("a")):
    pass
with open("a") as f, open("b"):
    pass


async def async_forms(session):
    async with (session.get("u")).cm() as resp:
        pass
    async with (session.get("a") as r1, session.get("b") as r2):
        pass


# except* - CPython tokenises `except` and `*` separately, so whitespace is legal.
try:
    pass
except *ValueError:
    pass
except * TypeError as e:
    pass
except*(KeyError, IndexError):
    pass
except*OSError as err:
    pass
