from parser_rust import get, Context
from pathlib import Path
import pprint

p = Path("./text.txt")
t = p.read_text()


c = Context(["swp1", "swp2"], [])
r = get(t, c)

pprint.pprint(r)
