#!/usr/bin/env python3
"""Capture frames from animated SVGs using Playwright, then assemble with ffmpeg."""
import subprocess, pathlib, shutil, tempfile

OUT_DIR = pathlib.Path(__file__).parent
FPS = 30
WIDTH = 1160

ANIMATIONS = [
    {"svg": "ftp-normal.svg", "prefix": "ftp-normal", "dur": 5.0, "height": 192},
    {"svg": "ftp-attack.svg", "prefix": "ftp-attack", "dur": 7.0, "height": 192},
]

for anim in ANIMATIONS:
    svg = OUT_DIR / anim["svg"]
    dur = anim["dur"]
    prefix = anim["prefix"]
    h = anim["height"]
    total_frames = int(dur * FPS)

    tmpdir = pathlib.Path(tempfile.mkdtemp(prefix=f"svg_{prefix}_"))
    print(f"\n=== {prefix}: {total_frames} frames at {FPS}fps ===")

    svg_content = svg.read_text()
    html = f"""<!DOCTYPE html>
<html><head><style>
  body {{ margin: 0; background: white; display: flex; align-items: center; justify-content: center; height: 100vh; }}
  .wrap {{ width: {WIDTH}px; }}
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
        page = await browser.new_page(viewport={{"width": {WIDTH}, "height": {h}}})
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
        ("mp4", ["ffmpeg", "-y", "-framerate", str(FPS), "-i", str(tmpdir / "frame_%04d.png"),
                  "-c:v", "libx264", "-pix_fmt", "yuv420p", "-vf", f"scale={WIDTH}:-2",
                  "-movflags", "+faststart", str(OUT_DIR / f"{prefix}.mp4")]),
        ("webm", ["ffmpeg", "-y", "-framerate", str(FPS), "-i", str(tmpdir / "frame_%04d.png"),
                   "-c:v", "libvpx-vp9", "-b:v", "0", "-crf", "30", "-vf", f"scale={WIDTH}:-2",
                   str(OUT_DIR / f"{prefix}.webm")]),
        ("gif", ["ffmpeg", "-y", "-framerate", str(FPS), "-i", str(tmpdir / "frame_%04d.png"),
                  "-vf", f"fps=15,scale=580:-1:flags=lanczos,split[s0][s1];[s0]palettegen[p];[s1][p]paletteuse",
                  str(OUT_DIR / f"{prefix}.gif")]),
    ]:
        print(f"  Encoding {fmt}...")
        subprocess.run(cmd, check=True, capture_output=True)

    shutil.rmtree(tmpdir)
    for ext in ["mp4", "webm", "gif"]:
        f = OUT_DIR / f"{prefix}.{ext}"
        print(f"  {f.name}: {f.stat().st_size / 1024:.0f} KB")

print("\nDone.")
