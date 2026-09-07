# CHEN-EXPECT: no-parse-errors
# CHEN-EXPECT: control-structure SWITCH count=1

def handle(cmd, point):
    match cmd.split():
        case ["go", ("north"|"south") as dir]: return dir
        case ["drop", *objs]: return objs
        case {"key": v, **rest}: return v, rest
        case Point(x=0, y=0): return "origin"
        case [Point(x=x1), Point(x=x2)] if x1 == x2: return "vert"
        case _: return None
class Point:
    __match_args__ = ("x","y")
    def __init__(self, x, y): self.x, self.y = x, y
def g(x: int | None) -> str | bytes: ...
