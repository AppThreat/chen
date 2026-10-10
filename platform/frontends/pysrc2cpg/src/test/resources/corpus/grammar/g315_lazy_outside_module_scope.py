# CHEN-EXPECT: no-parse-errors
# CHEN-EXPECT: tag lazy-import count=6
# Accepted by CPython 3.15's PARSER (ast.parse sets is_lazy=1) but rejected by its compiler
# (symtable): lazy imports outside module scope and lazy star imports. A static analyser sees
# the AST, so chen parses these like ast.parse does and keeps the lazy flag.
#   compile(): "lazy import not allowed inside functions" / "... inside classes" /
#              "... inside try/except blocks" / "lazy from ... import * is not allowed"


def in_function():
    lazy import json
    return json


class InClass:
    lazy from os import path


try:
    lazy import csv
except ImportError:
    pass
finally:
    lazy import heapq

lazy from os import *
lazy from . import *
