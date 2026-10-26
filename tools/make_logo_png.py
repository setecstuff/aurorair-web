"""Render app/static/logo.png (512x512) from the same geometry as app/static/favicon.svg (32x32 viewBox)."""
from pathlib import Path

from PIL import Image, ImageDraw

OUT = Path(__file__).resolve().parent.parent / "app" / "static" / "logo.png"
SIZE, SS = 512, 4                      # supersampling for smooth edges
k = SIZE * SS / 32


def main():
    img = Image.new("RGBA", (SIZE * SS, SIZE * SS), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle([0, 0, 32 * k - 1, 32 * k - 1], radius=7 * k, fill="#14304f")
    d.line([(19.8 * k, 19.8 * k), (25.6 * k, 25.6 * k)], fill="#e8b04a", width=int(4.4 * k))
    for cx, cy in ((19.8, 19.8), (25.6, 25.6)):                      # round caps
        r = 2.2 * k
        d.ellipse([cx * k - r, cy * k - r, cx * k + r, cy * k + r], fill="#e8b04a")
    d.line([(19.2 * k, 19.2 * k), (20.6 * k, 20.6 * k)], fill="#b9852c", width=int(4.4 * k))
    r_out, r_in = (7.3 + 1.3) * k, (7.3 - 1.3) * k
    c = 13.5 * k
    d.ellipse([c - r_out, c - r_out, c + r_out, c + r_out], fill="#eaf2fb")
    d.ellipse([c - r_in, c - r_in, c + r_in, c + r_in], fill="#1f4f80")
    d.arc([c - 4.6 * k, c - 4.6 * k, c + 4.6 * k, c + 4.6 * k], start=190, end=255, fill="#ffffff", width=int(1.7 * k))
    img.resize((SIZE, SIZE), Image.LANCZOS).save(OUT, optimize=True)
    print("wrote", OUT)


if __name__ == "__main__":
    main()
