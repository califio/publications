#!/usr/bin/env python3
"""Capture frames from animated SVGs using Playwright, then assemble with ffmpeg."""
import subprocess, pathlib, shutil, tempfile

OUT_DIR = pathlib.Path(__file__).parent.parent
SRC_DIR = pathlib.Path(__file__).parent
FPS = 30

ANIMATIONS = [
    {"svg": "splice-normal.svg", "prefix": "splice-normal", "dur": 12.0, "width": 580, "height": 170},
    {"svg": "splice-attack.svg", "prefix": "splice-attack", "dur": 12.0, "width": 420, "height": 170},
    {"svg": "backend-wire.svg", "prefix": "backend-wire", "dur": 1.0, "width": 650, "height": 228},
    {"svg": "victim-swallow.svg", "prefix": "victim-swallow", "dur": 1.0, "width": 680, "height": 180},
]

for anim in ANIMATIONS:
    svg = SRC_DIR / anim["svg"]
    dur = anim["dur"]
    prefix = anim["prefix"]
    w = anim["width"]
    h = anim["height"]
    total_frames = int(dur * FPS)

    tmpdir = pathlib.Path(tempfile.mkdtemp(prefix=f"svg_{prefix}_"))
    print(f"\n=== {prefix}: {total_frames} frames at {FPS}fps ===")

    svg_content = svg.read_text()
    html = f"""<!DOCTYPE html>
<html><head><style>
  body {{ margin: 0; background: transparent; display: flex; align-items: center; justify-content: center; height: 100vh; }}
  .wrap {{ width: {w}px; }}
</style></head>
<body><div class="wrap">{svg_content}</div></body></html>
"""
    html_path = tmpdir / "page.html"
    html_path.write_text(html)

    script = f"""
import asyncio, pathlib
from playwright.async_api import async_playwright

async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page(viewport={{"width": {w}, "height": {h}}})
        await page.goto("file://{html_path.resolve()}")
        await page.wait_for_timeout(300)
        await page.evaluate('''() => {{
            const svg = document.querySelector("svg");
            svg.pauseAnimations();
            svg.setCurrentTime(0);
        }}''')
        await page.wait_for_timeout(100)

        frame_dt = {dur} / {total_frames}
        for i in range({total_frames}):
            t = i * frame_dt
            await page.evaluate(f'() => document.querySelector("svg").setCurrentTime({{t}})')
            await page.wait_for_timeout(30)
            await page.screenshot(path=str(pathlib.Path("{tmpdir}") / f"frame_{{i:04d}}.png"))
            if i % 30 == 0:
                print(f"  frame {{i}}/{total_frames} t={{t:.2f}}s")
        await browser.close()

asyncio.run(main())
"""
    script_path = tmpdir / "capture.py"
    script_path.write_text(script)

    print("Capturing...")
    subprocess.run(["python3", str(script_path)], check=True)

    for fmt, cmd in [
        ("gif", ["ffmpeg", "-y", "-framerate", str(FPS), "-i", str(tmpdir / "frame_%04d.png"),
                  "-vf", f"fps=15,scale={w}:-1:flags=lanczos,split[s0][s1];[s0]palettegen=reserve_transparent=1[p];[s1][p]paletteuse=alpha_threshold=128",
                  str(OUT_DIR / f"{prefix}.gif")]),
    ]:
        print(f"  Encoding {fmt}...")
        subprocess.run(cmd, check=True, capture_output=True)

    shutil.rmtree(tmpdir)
    f = OUT_DIR / f"{prefix}.gif"
    print(f"  {f.name}: {f.stat().st_size / 1024:.0f} KB")

print("\nDone.")
