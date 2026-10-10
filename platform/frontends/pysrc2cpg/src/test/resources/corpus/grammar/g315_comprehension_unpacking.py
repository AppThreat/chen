# CHEN-EXPECT: no-parse-errors
# CHEN-EXPECT: node-absent UNKNOWN
# CHEN-EXPECT: call extend count=11  # starred list-comprehension / generator elements (9 sync + 2 async)
# CHEN-EXPECT: call update count=10  # 8 starred set / ** dict comprehensions + 2 from the {**a, **b} display
# Python 3.15, PEP 798: `*` and `**` unpacking in comprehensions and generator expressions.
# Oracle: CPython 3.15.0
#   [*L for L in ls]   -> ListComp(elt=Starred(L))     == [x for L in ls for x in L]
#   {*s for s in ss}   -> SetComp(elt=Starred(s))
#   {**d for d in ds}  -> DictComp(key=d, value=None)  == {k: v for d in ds for k, v in d.items()}
#   (*L for L in ls)   -> GeneratorExp(elt=Starred(L)) == (x for L in ls for x in L)
#   f(*L for L in ls)  -> Call(f, [GeneratorExp(elt=Starred(L))])

lists = [[1, 2], [3, 4], [5]]
sets = [{1, 2}, {2, 3}, {3, 4}]
dicts = [{"a": 1}, {"b": 2}, {"a": 3}]
pairs = [(1, 2), (3, 4)]

flat = [*L for L in lists]
flat_if = [*L for L in lists if len(L) > 1]
flat_nested = [*row for grid in [lists] for row in grid]
flat_tuple = [*(a, b) for a, b in pairs]
flat_call = [*range(n) for n in (1, 2, 3)]
union = {*s for s in sets}
union_if = {*s for s in sets if 2 in s}
merged = {**d for d in dicts}
merged_if = {**d for d in dicts if "a" in d}
merged_built = {**{k: v} for k, v in [("x", 1), ("y", 2)]}
merged_call = {**dict(d) for d in dicts}
gen = (*L for L in lists)
total = sum(*L for L in lists)
listed = list(*L for L in lists)
chained = sorted((*L for L in lists), reverse=True)

# Pre-3.15 forms that must keep their meaning next to the new ones.
display = [*lists[0], *lists[1]]
set_display = {*sets[0], *sets[1]}
dict_display = {**dicts[0], **dicts[1]}
plain = [x for L in lists for x in L]
plain_dict = {k: v for d in dicts for k, v in d.items()}


async def agen():
    yield [1]
    yield [2, 3]


async def unpack_async():
    xs = [*a async for a in agen()]
    ys = {*a async for a in agen()}
    zs = {**{"k": a} async for a in agen()}
    g = (*a async for a in agen())
    return xs, ys, zs, g
