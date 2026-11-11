"""Untrusted image handling: validate by magic bytes, decode with limits, re-encode to strip metadata and
neutralise polyglot files. The original bytes are never stored or passed on."""

from __future__ import annotations

import io

from PIL import Image, UnidentifiedImageError

ALLOWED_FORMATS = {"PNG", "JPEG", "WEBP"}
_MAGIC = (b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"RIFF")


class UploadRejected(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def sanitize_image(data: bytes, *, max_bytes: int, max_pixels: int) -> tuple[bytes, int, int]:
    if len(data) == 0:
        raise UploadRejected("empty_file")
    if len(data) > max_bytes:
        raise UploadRejected("file_too_large")
    if not data.startswith(_MAGIC) or (data.startswith(b"RIFF") and data[8:12] != b"WEBP"):
        raise UploadRejected("unsupported_type")
    try:
        with Image.open(io.BytesIO(data)) as img:
            if img.format not in ALLOWED_FORMATS:
                raise UploadRejected("unsupported_type")
            if img.width * img.height > max_pixels:
                raise UploadRejected("image_too_large")
            img.load()
            rgb = img.convert("RGB")
    except UploadRejected:
        raise
    except (UnidentifiedImageError, OSError, ValueError, Image.DecompressionBombError) as exc:
        raise UploadRejected("invalid_image") from exc
    # Downscale very large screenshots: enough for OCR and QR decoding, smaller to store and send to AI.
    rgb.thumbnail((2400, 2400))
    out = io.BytesIO()
    rgb.save(out, format="PNG", optimize=True)  # fresh file: no EXIF/GPS, no trailing payloads
    return out.getvalue(), rgb.width, rgb.height
