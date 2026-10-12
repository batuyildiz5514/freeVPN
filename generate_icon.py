"""Generates a high-quality .ico icon file for PyVPN Windows application."""

from PIL import Image, ImageDraw

def create_shield_icon():
    sizes = [(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (16, 16)]
    images = []

    for size in sizes:
        w, h = size
        img = Image.new("RGBA", size, (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)

        # Scale coordinates
        scale = w / 256.0

        # Draw rounded shield background (Dark navy / royal blue gradient)
        pad = int(16 * scale)
        # Shield polygon
        points = [
            (w // 2, pad),                       # Top center
            (w - pad, int(50 * scale)),          # Top right
            (w - pad, int(150 * scale)),         # Mid right
            (w // 2, h - pad),                   # Bottom point
            (pad, int(150 * scale)),             # Mid left
            (pad, int(50 * scale)),              # Top left
        ]

        # Draw outer glowing border
        draw.polygon(points, fill=(37, 99, 235))   # Royal blue

        # Inner shield
        inner_pad = int(28 * scale)
        inner_points = [
            (w // 2, inner_pad),
            (w - inner_pad, int(58 * scale)),
            (w - inner_pad, int(145 * scale)),
            (w // 2, h - inner_pad),
            (inner_pad, int(145 * scale)),
            (inner_pad, int(58 * scale)),
        ]
        draw.polygon(inner_points, fill=(24, 26, 32))  # Dark sleek charcoal

        # Center lock / keyhole accent
        cx, cy = w // 2, int(115 * scale)
        radius = int(24 * scale)
        if radius >= 2:
            draw.ellipse([cx - radius, cy - radius, cx + radius, cy + radius], fill=(59, 130, 246))
            bar_w = max(2, int(14 * scale))
            bar_h = max(4, int(30 * scale))
            draw.rectangle([cx - bar_w // 2, cy, cx + bar_w // 2, cy + bar_h], fill=(59, 130, 246))

        images.append(img)

    images[0].save("pyvpn.ico", format="ICO", sizes=[(s[0], s[1]) for s in sizes])
    print("[OK] pyvpn.ico generated successfully.")

if __name__ == "__main__":
    create_shield_icon()
