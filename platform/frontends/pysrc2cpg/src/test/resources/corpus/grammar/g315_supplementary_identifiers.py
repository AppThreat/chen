# CHEN-EXPECT: no-parse-errors
# CHEN-EXPECT: node-absent UNKNOWN
# CHEN-EXPECT: tag unicode-confusable count=15  # every use of a name spelled with NFKC-folded characters
# Identifiers outside the Basic Multilingual Plane (PEP 3131, Unicode 17 XID_Start/XID_Continue).
# Oracle: CPython 3.15.0 - every assignment below is valid, and the NFKC-normalised names are
#   U+1D465 MATHEMATICAL ITALIC SMALL X       -> x
#   U+1D7D9 MATHEMATICAL DOUBLE-STRUCK DIGIT ONE (continue only) -> 1
#   U+13000 EGYPTIAN HIEROGLYPH A001, U+20000 CJK EXTENSION B -> unchanged (no decomposition)
#   U+E0100 VARIATION SELECTOR-17 (continue only) -> unchanged
𝑥 = 1
print(x + 𝑥)
𓀀_glyph = 1
x󠄀 = 1
𠀀_cjk_ext_b = 1
v𝟙 = 𝑥 * 2
def 𝑓(𝑎, *, 𝑏=2):
    return 𝑎 + 𝑏
class 𝐶:
    𝑚 = 𝑓(1)
print(𝐶.𝑚, "😀 stays in strings")
