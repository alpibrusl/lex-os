"""Render two captured command outputs as aligned columns.

printf pads by bytes, and this demo's output is full of em-dashes and
box-drawing characters, so the columns drift. This pads by display
width and wraps instead of truncating — a comparison that cuts off the
verdict is worse than no comparison.
"""
import sys, unicodedata

W = 66


def width(s):
    return sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in s)


def wrap(line, w):
    if not line.strip():
        return [""]
    if width(line) <= w:
        return [line]          # fits — keep it byte-for-byte, indent included
    out, cur = [], ""
    for word in line.split(" "):
        cand = word if not cur else cur + " " + word
        if width(cand) <= w:
            cur = cand
        else:
            if cur:
                out.append(cur)
            while width(word) > w:
                out.append(word[:w])
                word = word[w:]
            cur = word
    if cur:
        out.append(cur)
    # preserve leading indentation on continuation lines
    indent = len(line) - len(line.lstrip())
    return [out[0]] + [" " * min(indent + 2, 8) + x for x in out[1:]]


def col(path):
    rows = []
    for line in open(path).read().rstrip("\n").split("\n"):
        rows.extend(wrap(line, W))
    return rows


def pad(s):
    return s + " " * max(0, W - width(s))


left, right = col(sys.argv[1]), col(sys.argv[2])
for i in range(max(len(left), len(right))):
    l = left[i] if i < len(left) else ""
    r = right[i] if i < len(right) else ""
    print("  " + pad(l) + "    " + r.rstrip())
