"""Generate the reproducible KASA application icon assets."""

from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter


OUTPUT_DIRECTORY = Path(__file__).resolve().parent
CANVAS_SIZE = 1024


def interpolate(start: tuple[int, int, int], end: tuple[int, int, int], amount: float):
    return tuple(round(a + (b - a) * amount) for a, b in zip(start, end))


def create_icon() -> Image.Image:
    image = Image.new("RGBA", (CANVAS_SIZE, CANVAS_SIZE), (0, 0, 0, 0))

    tile_mask = Image.new("L", image.size, 0)
    ImageDraw.Draw(tile_mask).rounded_rectangle((64, 64, 960, 960), radius=224, fill=255)

    gradient = Image.new("RGBA", image.size)
    pixels = gradient.load()
    for y in range(CANVAS_SIZE):
        for x in range(CANVAS_SIZE):
            amount = (x + y) / (2 * (CANVAS_SIZE - 1))
            red, green, blue = interpolate((7, 13, 31), (24, 34, 70), amount)
            pixels[x, y] = (red, green, blue, 255)
    image.alpha_composite(Image.composite(gradient, Image.new("RGBA", image.size), tile_mask))

    glow = Image.new("RGBA", image.size, (0, 0, 0, 0))
    glow_draw = ImageDraw.Draw(glow)
    glow_draw.ellipse((180, 180, 844, 844), fill=(42, 209, 224, 105))
    glow = glow.filter(ImageFilter.GaussianBlur(80))
    glow.putalpha(Image.composite(glow.getchannel("A"), Image.new("L", image.size), tile_mask))
    image.alpha_composite(glow)

    draw = ImageDraw.Draw(image)
    draw.rounded_rectangle((65, 65, 959, 959), radius=223, outline=(94, 111, 175, 150), width=14)

    # Concentric vault mark matching the cyan and violet identity used in the UI.
    draw.ellipse((208, 208, 816, 816), fill=(44, 202, 218, 255))
    draw.ellipse((292, 292, 732, 732), fill=(10, 18, 42, 255))
    draw.ellipse((356, 356, 668, 668), fill=(121, 78, 226, 255))

    # A compact keyhole keeps the mark readable at 16 px without relying on text.
    draw.ellipse((458, 430, 566, 538), fill=(205, 250, 252, 255))
    draw.rounded_rectangle((482, 500, 542, 622), radius=28, fill=(205, 250, 252, 255))
    return image


def main() -> None:
    icon = create_icon()
    icon.save(OUTPUT_DIRECTORY / "KASA-icon.png", optimize=True)
    icon.resize((256, 256), Image.Resampling.LANCZOS).save(
        OUTPUT_DIRECTORY / "KASA.ico",
        format="ICO",
        sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)],
    )


if __name__ == "__main__":
    main()
