# CHEN-EXPECT: no-parse-errors
# CHEN-EXPECT: node-absent UNKNOWN
# CHEN-EXPECT: call <operator>.formattedValue count=37  # every replacement field, nested ones included
# CHEN-EXPECT: call <operator>.formatString count=34  # 19 f-strings + the 15 specs that hold a nested field
# Format specs are JoinedStrs (PEP 701): nested replacement fields are expressions CPython evaluates.
# Oracle: CPython 3.15.0
#   f'{x:>{w}.{p}f}' -> FormattedValue(x, format_spec=JoinedStr([Constant('>'), FormattedValue(w),
#                                                             Constant('.'), FormattedValue(p),
#                                                             Constant('f')]))
#   f'{x:{"{"}>10}'  -> format_spec=JoinedStr([FormattedValue(Constant('{')), Constant('>10')])
x, w, p, y, z, d = 3.14159, 10, 2, "y", 4, {"k": 5}
a = f'{x:{w}}'
b = f'{x:>{w}.{p}f}'
c = f'{x:{w}{p}}'
e = f'{x:{w}:{p}}'
g = f'{y:{z}}'
h = f'{x:{y:>3}}'
i = f'{x:{"{"}>10}'
j = f'{x!r:^{w}}'
k = f'{x=:{w}}'
m = f'{x:{w!r}}'
n = f'{x:{w + p}}'
o = f'''{x:{
    w}}'''
q = f'{x:{f"{y}"}}'
r = f"{d['k']:{w}}"
s = f'{x:{d["k"]}}'
t = f'{x:%H:%M}'
u = f'{x:}'
v = f'{x:=10}'
