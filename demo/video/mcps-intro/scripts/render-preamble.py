#!/usr/bin/env python3
"""
Standalone renderer for the intro preamble -> dist/preamble.mp4 (video only).

This reproduces src/scenes/preamble.tsx frame-for-frame (same dark background,
timing, and motion: materialize -> deadpan -> confident reveal -> subtitle
fade-up) WITHOUT needing the Motion Canvas browser editor, so the full video
can be assembled headlessly. The braam SFX is added later by build-intro-final.

Run with the Pillow venv:
    /tmp/preamble-venv/bin/python scripts/render-preamble.py
Time events mirror src/scenes/preamble.meta.
"""
import subprocess
from PIL import Image, ImageDraw, ImageFont, ImageFilter

W, H, FPS, DUR = 1920, 1080, 60, 8.0
CX = W / 2
BG = (11, 18, 32, 255)          # theme.bg #0b1220
INK = (248, 250, 252, 255)      # #f8fafc
GRAY = (160, 160, 160, 255)     # #A0A0A0
MUTED = (148, 163, 184, 255)    # #94a3b8

AR = '/System/Library/Fonts/Supplemental/Arial.ttf'
AI = '/System/Library/Fonts/Supplemental/Arial Italic.ttf'
AB = '/System/Library/Fonts/Supplemental/Arial Bold.ttf'

f_l1 = ImageFont.truetype(AR, 66)
f_l2 = ImageFont.truetype(AI, 38)
f_mc = ImageFont.truetype(AB, 156)
f_sub = ImageFont.truetype(AR, 42)


def render_text(text, font, fill, spacing=0, pad=70):
    if spacing == 0:
        b = font.getbbox(text)
        img = Image.new('RGBA', (b[2] - b[0] + 2 * pad, b[3] - b[1] + 2 * pad), (0, 0, 0, 0))
        ImageDraw.Draw(img).text((pad - b[0], pad - b[1]), text, font=font, fill=fill)
        return img
    widths = [font.getlength(c) for c in text]
    asc, desc = font.getmetrics()
    total = sum(widths) + spacing * (len(text) - 1)
    img = Image.new('RGBA', (int(total) + 2 * pad, asc + desc + 2 * pad), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    x = pad
    for c, wd in zip(text, widths):
        d.text((x, pad), c, font=font, fill=fill)
        x += wd + spacing
    return img


img_l1 = render_text("There's a new kid on the protocol block.", f_l1, INK)
img_l2 = render_text('No, not the 90s boy band.', f_l2, GRAY)
img_mc = render_text('MCP-S', f_mc, INK, spacing=6)
img_sub = render_text('Verifiable runtime evidence for MCP calls.', f_sub, MUTED)


def ease(t):  # easeInOutCubic (Motion Canvas default)
    return 4 * t ** 3 if t < 0.5 else 1 - ((-2 * t + 2) ** 3) / 2


def seg(t, a, b):
    if t <= a:
        return 0.0
    if t >= b:
        return 1.0
    return ease((t - a) / (b - a))


def stamp(canvas, base, cx, cy, opacity, scale=1.0, blur=0.0):
    if opacity <= 0.003:
        return
    im = base
    if abs(scale - 1.0) > 1e-3:
        w, h = base.size
        im = base.resize((max(1, round(w * scale)), max(1, round(h * scale))), Image.LANCZOS)
    if blur > 0.05:
        im = im.filter(ImageFilter.GaussianBlur(blur))
    if opacity < 0.999:
        im = im.copy()
        im.putalpha(im.getchannel('A').point(lambda v: int(v * opacity)))
    w, h = im.size
    canvas.alpha_composite(im, (round(cx - w / 2), round(cy - h / 2)))


ff = subprocess.Popen(
    ['ffmpeg', '-y', '-loglevel', 'error',
     '-f', 'rawvideo', '-pix_fmt', 'rgb24', '-s', f'{W}x{H}', '-r', str(FPS), '-i', '-',
     '-c:v', 'libx264', '-crf', '18', '-preset', 'medium', '-pix_fmt', 'yuv420p',
     '-movflags', '+faststart', 'dist/preamble.mp4'],
    stdin=subprocess.PIPE,
)

for f in range(int(DUR * FPS)):
    t = f / FPS
    cv = Image.new('RGBA', (W, H), BG)

    # Lines 1 & 2 (cleared at 4.0-4.3 before the reveal)
    clear = seg(t, 4.0, 4.3)
    p1 = seg(t, 0.3, 1.1)
    stamp(cv, img_l1, CX, 540 - 36, p1 * (1 - clear), scale=0.92 + 0.08 * p1, blur=6 * (1 - p1))
    p2 = seg(t, 1.8, 2.1)
    stamp(cv, img_l2, CX, 540 + 48, p2 * (1 - clear))

    # Reveal: MCP-S on the braam, subtitle fades up under it; both fade out 7.5-7.9
    out = seg(t, 7.5, 7.9)
    pm = seg(t, 4.3, 4.8)
    stamp(cv, img_mc, CX, 540 - 44, pm * (1 - out), scale=1.04 - 0.04 * pm)
    ps = seg(t, 5.0, 5.5)
    stamp(cv, img_sub, CX, 540 + 92 + 12 * (1 - ps), ps * (1 - out))

    ff.stdin.write(cv.convert('RGB').tobytes())

ff.stdin.close()
ff.wait()
print('wrote dist/preamble.mp4')
