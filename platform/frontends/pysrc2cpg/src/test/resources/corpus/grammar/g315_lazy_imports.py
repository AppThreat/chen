# CHEN-EXPECT: no-parse-errors
# CHEN-EXPECT: node-absent UNKNOWN
# CHEN-EXPECT: tag lazy-import count=15  # one import call per bound name: 13 keyword + 2 via __lazy_modules__
# Python 3.15, PEP 810: explicit lazy imports. `lazy` is a soft keyword: special only
# immediately before `import` / `from`; an identifier everywhere else.
# Oracle: CPython 3.15.0 - ast.parse sets Import/ImportFrom.is_lazy=1 for every lazy form below.

lazy import json
lazy import os.path
lazy import xml.etree.ElementTree as ET, csv
lazy from pathlib import Path
lazy from collections import (OrderedDict, defaultdict,)
lazy from . import sibling
lazy from .. import parent_mod as pm
lazy from .pkg.sub import thing
lazy import a; lazy from b import c

if __debug__:
    lazy import typing  # module scope inside `if` is allowed (only def/class/try are not)

# __lazy_modules__ (PEP 810 compatibility form): regular module-level imports of the listed
# modules, after the assignment, are lazy too - exactly as if `lazy` had been written.
import colorsys                       # before the assignment: eager
__lazy_modules__ = ["fractions", "decimal", "statistics"]
import fractions                      # lazy
from decimal import Decimal           # lazy (the module after `from` is what is looked up)
import heapq                          # eager (not listed)


def eager_inside_function():
    import statistics                 # functions are always eager
    return statistics


try:
    import statistics                 # try blocks are always eager
except ImportError:
    statistics = None

# `lazy` everywhere else is an ordinary name.
lazy = 1
lazy += 1
lazy_value = lazy * 2


class Lazy:
    lazy = "attr"

    def lazy_method(self, lazy=None):
        return self.lazy, lazy


obj = Lazy()
print(obj.lazy, Lazy.lazy, [lazy for lazy in range(3)])
for lazy in (1, 2):
    pass
with open(__file__) as lazy:
    pass
try:
    pass
except Exception as lazy:
    pass
lazy: int = 3


def lazy(lazy):
    return lazy


print(lazy(lazy=1), lazy(1))
match lazy:
    case lazy:
        pass
