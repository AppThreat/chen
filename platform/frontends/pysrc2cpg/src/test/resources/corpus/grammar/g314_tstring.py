# CHEN-EXPECT: no-parse-errors  # t-strings (PEP 750) + PEP 758 unparenthesised except parse since task 10

from string.templatelib import Template
name = "world"
t = t"hello {name}"
t2 = t"{name!r:>{10}}"
try:
    pass
except ValueError, TypeError:
    pass
