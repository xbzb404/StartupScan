# -*- coding: utf-8 -*-
"""生成应用图标（多尺寸 .ico，Win11 风格：强调色圆角方块 + 图标字形）。"""

import os
from PIL import Image, ImageDraw, ImageFont

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "assets", "icon.ico")
PNG_OUT = os.path.join(HERE, "assets", "icon.png")

ACCENT = "#0067C0"
ACCENT_DARK = "#004578"
ICON_FONT = r"C:\Windows\Fonts\SegoeIcons.ttf"
# Segoe Fluent Icons: 电源/启动 相关字形
GLYPH = "\uE7E8"          # Power


def rounded(size, radius_ratio=0.22):
    ss = 8
    s = size * ss
    im = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(im)
    r = int(s * radius_ratio)
    d.rounded_rectangle([0, 0, s - 1, s - 1], radius=r, fill=ACCENT)
    grad = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    gd = ImageDraw.Draw(grad)
    gd.rounded_rectangle([0, 0, s - 1, s - 1], radius=r, fill=ACCENT_DARK)
    grad.putalpha(90)
    im = Image.alpha_composite(im, grad)
    return im.resize((size, size), Image.LANCZOS)


def render(size):
    base = rounded(size)
    d = ImageDraw.Draw(base)
    try:
        f = ImageFont.truetype(ICON_FONT, int(size * 0.60))
        d.text((size / 2, size * 0.50), GLYPH, font=f, fill=(255, 255, 255, 255),
               anchor="mm")
    except Exception:
        # 退化：画一个电源符号
        cx, cy = size / 2, size * 0.48
        r = size * 0.26
        d.arc([cx - r, cy - r * 0.6, cx + r, cy + r * 0.9],
              start=135, end=405, fill="#FFFFFF", width=max(1, size // 20))
        d.line([cx, cy - r * 0.9, cx, cy + r * 0.1], fill="#FFFFFF",
               width=max(1, size // 20))
    return base


def main():
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    sizes = [256, 128, 96, 64, 48, 32, 24, 16]
    imgs = [render(s) for s in sizes]
    imgs[0].save(PNG_OUT)
    imgs[0].save(OUT, format="ICO",
                 sizes=[(s, s) for s in sizes], append_images=imgs[1:])
    print("icon:", OUT, os.path.getsize(OUT), "bytes")
    print("png :", PNG_OUT)


if __name__ == "__main__":
    main()
