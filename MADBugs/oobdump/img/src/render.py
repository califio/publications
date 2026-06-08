#!/usr/bin/env python3
"""Render the bug/exploit SVGs to raster assets via Chromium (full glyph + SMIL support).

  static  SVG -> PNG  (single screenshot, 2x)
  animated SVG -> GIF  (frame capture -> ffmpeg palette gif)
"""
import asyncio, re, subprocess, tempfile, pathlib, shutil
from playwright.async_api import async_playwright

SRC = pathlib.Path(__file__).parent
OUT = SRC.parent
SCALE = 2
GIF_W = 880

STATIC = ["heap-map",
          "house-of-apple", "wide-overlap"]
ANIM = [{"name": "wrapping-write", "dur": 6, "w": 480},
        {"name": "xvec-switch", "dur": 5, "w": 760}]
FPS = 15


def vb(svg_text):
    m = re.search(r'viewBox="([\d.\s]+)"', svg_text)
    _, _, w, h = [float(x) for x in m.group(1).split()]
    return w, h


def page_html(svg, w):
    return (f'<!DOCTYPE html><meta charset="utf-8">'
            f'<style>html,body{{margin:0;background:#fff}}.wrap{{width:{w}px}}'
            f'svg{{display:block;width:100%;height:auto}}</style>'
            f'<div class="wrap">{svg}</div>')


async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch(channel="chrome")
        # ---- static ----
        for n in STATIC:
            # Prefer a draw.io export ({n}.drawio.svg) over a hand-authored {n}.svg.
            src = SRC / f"{n}.drawio.svg"
            if not src.exists():
                src = SRC / f"{n}.svg"
            svg = src.read_text()
            w, h = vb(svg)
            W = int(w * SCALE)
            page = await browser.new_page(viewport={"width": W, "height": int(h * SCALE)},
                                          device_scale_factor=1, color_scheme="light")
            await page.set_content(page_html(svg, W))
            await page.wait_for_timeout(200)
            el = await page.query_selector(".wrap")
            await el.screenshot(path=str(OUT / f"{n}.png"))
            await page.close()
            print(f"PNG  {n}.png  {(OUT/f'{n}.png').stat().st_size//1024} KB")

        # ---- animated ----
        for a in ANIM:
            n, dur = a["name"], a["dur"]
            svg = (SRC / f"{n}.svg").read_text()
            w, h = vb(svg)
            W = a.get("w", GIF_W)
            H = int(h * (W / w))
            tmp = pathlib.Path(tempfile.mkdtemp(prefix=f"r_{n}_"))
            page = await browser.new_page(viewport={"width": W, "height": H},
                                          device_scale_factor=1, color_scheme="light")
            await page.set_content(page_html(svg, W))
            await page.wait_for_timeout(200)
            await page.evaluate("() => { const s=document.querySelector('svg'); s.pauseAnimations(); s.setCurrentTime(0);} ")
            frames = int(dur * FPS)
            for i in range(frames):
                t = i * (dur / frames)
                await page.evaluate(f"() => document.querySelector('svg').setCurrentTime({t})")
                await page.wait_for_timeout(20)
                await page.screenshot(path=str(tmp / f"f{i:04d}.png"))
            await page.close()
            gif = OUT / f"{n}.gif"
            subprocess.run(["ffmpeg", "-y", "-framerate", str(FPS), "-i", str(tmp / "f%04d.png"),
                            "-vf", f"fps={FPS},scale={W}:-1:flags=lanczos,split[s0][s1];[s0]palettegen[p];[s1][p]paletteuse",
                            str(gif)], check=True, capture_output=True)
            shutil.rmtree(tmp)
            print(f"GIF  {n}.gif  {gif.stat().st_size//1024} KB  ({frames} frames)")
        await browser.close()

asyncio.run(main())
