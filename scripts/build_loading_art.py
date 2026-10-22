"""Build the shared dark loading canvas with centered game art, without text."""
import argparse
import math
import re
import zlib
from pathlib import Path
from PIL import Image

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('logo', type=Path)
p.add_argument('output', type=Path)
p.add_argument('preview', type=Path)
p.add_argument('--animation-preview', type=Path)
a = p.parse_args()
layout_path = Path(__file__).resolve().parent.parent / 'include/loading_style.h'
layout = {key: int(value) for key, value in
          re.findall(r'^#define (LOADING_[A-Z_]+) (\d+)$', layout_path.read_text(), re.M)}
w, h, size = (layout[k] for k in ['LOADING_WIDTH', 'LOADING_HEIGHT', 'LOADING_LOGO_SIZE'])
x, y = (layout[k] for k in ['LOADING_LOGO_X', 'LOADING_LOGO_Y'])
assert (x + size // 2, y + size // 2) == (layout['LOADING_CENTER_X'], layout['LOADING_CENTER_Y'])
background = (10, 10, 15, 255)  # Same clear color as gtasa_nx's launcher.
im = Image.new('RGBA', (w, h), background)
logo = Image.open(a.logo).convert('RGBA')
# The supplied artwork is square; keep it unchanged and centered in its layer.
logo.thumbnail((size, size), Image.Resampling.LANCZOS)
assert logo.width == logo.height, 'Expected the original square game artwork'
logo = logo.resize((size, size), Image.Resampling.LANCZOS)
im.alpha_composite(logo, (x, y))
a.output.parent.mkdir(parents=True, exist_ok=True)
a.output.write_bytes(zlib.compress(im.tobytes(), 9))
a.preview.parent.mkdir(parents=True, exist_ok=True)
im.save(a.preview)
if a.animation_preview:
    frames = []
    count = layout['LOADING_PERIOD_MS'] // layout['LOADING_FRAME_MS']
    for phase in range(count):
        pulse = 1 + 0.04 * (1 - math.cos(phase * 2 * math.pi / count))
        side = round(size * pulse)
        frame = Image.new('RGBA', (w, h), background)
        frame.alpha_composite(logo.resize((side, side), Image.Resampling.LANCZOS),
                              ((w - side) // 2, (h - side) // 2))
        frames.append(frame.convert('RGB'))
    a.animation_preview.parent.mkdir(parents=True, exist_ok=True)
    frames[0].save(a.animation_preview, save_all=True, append_images=frames[1:],
                   duration=layout['LOADING_FRAME_MS'], loop=0, disposal=2)
print(f'{a.output}: {a.output.stat().st_size} bytes; {w}x{h} RGBA; centered game art, no text')
