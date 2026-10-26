"""
Image Steganography Module for Shellcrypt

Embeds arbitrary binary data (shellcode) into images using LSB
(Least Significant Bit) steganography. The output remains a valid
image file with an intact signature — viewers display it normally.

Supported carrier formats:
  - PNG  (lossless, ideal for LSB)
  - BMP  (lossless, uncompressed pixel data)
  - ICO  (favicon — embeds into the largest frame)

Wire format (inside the pixel stream):
  [32 bits] payload length in bytes, big-endian
  [N bytes] payload data

Each bit of the wire is stored in the LSB of one colour-channel
sample. With ``bits_per_channel > 1`` more bits are packed per
sample (trading stealth for capacity).
"""

from __future__ import annotations

import io
import struct
from pathlib import Path

try:
    from PIL import Image
except ImportError:
    raise ImportError(
        "Pillow is required for steganography support. "
        "Install it with: pip install Pillow"
    )

from utils.logging import Log

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SUPPORTED_FORMATS = ("png", "bmp", "ico")

# Bits-per-channel mask: for n LSBs, mask = (1 << n) - 1
# e.g. 1 bit  → mask 0b1,  2 bits → mask 0b11
_BPC_RANGE = range(1, 5)  # 1–4 bits per channel


def _image_capacity(img: Image.Image, bits_per_channel: int = 1) -> int:
    """Return the maximum payload bytes the image can carry."""
    w, h = img.size
    channels = len(img.getbands())
    total_samples = w * h * channels
    total_payload_bits = total_samples * bits_per_channel
    # Subtract 32 bits reserved for the length header
    return max(0, (total_payload_bits - 32) // 8)


def _bytes_to_bits(data: bytes, bits_per_channel: int = 1) -> list[int]:
    """Convert bytes into a list of n-bit chunks (MSB first within each byte).

    When *bits_per_channel* is 1 this returns plain bits.  For 2 it
    returns 2-bit groups, etc.  Each element fits in *bits_per_channel*
    bits.
    """
    chunks: list[int] = []
    bpc = bits_per_channel
    for byte in data:
        # Walk from the MSB side in bpc-sized steps
        for shift in range(8 - bpc, -1, -bpc):
            chunks.append((byte >> shift) & ((1 << bpc) - 1))
    return chunks


def _bits_to_bytes(chunks: list[int], bits_per_channel: int = 1) -> bytearray:
    """Inverse of ``_bytes_to_bits``: reassemble n-bit chunks into bytes."""
    bpc = bits_per_channel
    steps_per_byte = 8 // bpc
    out = bytearray()
    for i in range(0, len(chunks) - steps_per_byte + 1, steps_per_byte):
        byte_val = 0
        for j in range(steps_per_byte):
            byte_val = (byte_val << bpc) | (chunks[i + j] & ((1 << bpc) - 1))
        out.append(byte_val)
    return out


# ---------------------------------------------------------------------------
# Core embed / extract
# ---------------------------------------------------------------------------

def _embed_into_pixels(img: Image.Image, payload: bytes,
                       bits_per_channel: int = 1) -> Image.Image:
    """Return a *copy* of *img* with *payload* hidden in the LSBs."""
    bpc = bits_per_channel
    mask = (1 << bpc) - 1       # e.g. 0b11 for bpc=2
    clear = 0xFF ^ mask          # e.g. 0xFC for bpc=2

    capacity = _image_capacity(img, bpc)
    if len(payload) > capacity:
        raise ValueError(
            f"Payload ({len(payload)} bytes) exceeds image capacity "
            f"({capacity} bytes at {bpc} bit(s)/channel). "
            "Use a larger image or increase --steg-bits."
        )

    # Build wire: 4-byte big-endian length + payload
    wire = struct.pack(">I", len(payload)) + payload
    chunks = _bytes_to_bits(wire, bpc)

    # Flatten pixel data into a mutable list of samples
    pixels = list(img.getdata())
    bands = len(img.getbands())
    flat = []
    for px in pixels:
        if isinstance(px, int):          # grayscale
            flat.append(px)
        else:
            flat.extend(px)

    # Embed
    for idx, chunk in enumerate(chunks):
        flat[idx] = (flat[idx] & clear) | chunk

    # Rebuild image
    out = img.copy()
    if bands == 1:
        out.putdata(flat)
    else:
        # Re-group into tuples
        new_pixels = [tuple(flat[i:i + bands]) for i in range(0, len(flat), bands)]
        out.putdata(new_pixels)

    return out


def _extract_from_pixels(img: Image.Image,
                         bits_per_channel: int = 1) -> bytearray:
    """Read the hidden payload back out of an image's LSBs."""
    bpc = bits_per_channel
    mask = (1 << bpc) - 1

    pixels = list(img.getdata())
    bands = len(img.getbands())
    flat = []
    for px in pixels:
        if isinstance(px, int):
            flat.append(px)
        else:
            flat.extend(px)

    # Read 32-bit length header first
    header_chunks_needed = 32 // bpc
    if len(flat) < header_chunks_needed:
        raise ValueError("Image too small to contain a steganography header.")

    header_chunks = [(flat[i] & mask) for i in range(header_chunks_needed)]
    length_bytes = _bits_to_bytes(header_chunks, bpc)
    payload_len = struct.unpack(">I", bytes(length_bytes[:4]))[0]

    if payload_len == 0:
        return bytearray()

    # Sanity check
    capacity = _image_capacity(img, bpc)
    if payload_len > capacity:
        raise ValueError(
            f"Stored length ({payload_len}) exceeds image capacity ({capacity}). "
            "Wrong image, wrong --steg-bits, or corrupted data."
        )

    # Read payload
    total_chunks = header_chunks_needed + (payload_len * 8 // bpc)
    if total_chunks > len(flat):
        raise ValueError("Image does not contain enough data for the stored length.")

    payload_chunks = [(flat[i] & mask)
                      for i in range(header_chunks_needed, total_chunks)]
    return _bits_to_bytes(payload_chunks, bpc)[:payload_len]


# ---------------------------------------------------------------------------
# ICO handling
# ---------------------------------------------------------------------------

def _load_ico_largest_frame(ico_path: str) -> tuple[Image.Image, int]:
    """Open an ICO and return (largest_frame_as_RGBA, frame_index)."""
    ico = Image.open(ico_path)
    best_idx = 0
    best_area = 0
    for idx in range(getattr(ico, 'n_frames', 1)):
        ico.seek(idx)
        w, h = ico.size
        if w * h > best_area:
            best_area = w * h
            best_idx = idx
    ico.seek(best_idx)
    # ICO frames are typically palette/RGBA — convert to RGBA for uniform handling
    return ico.convert("RGBA"), best_idx


def _save_ico(img: Image.Image, out_path: str) -> None:
    """Save an image as a valid ICO file."""
    # ICO wants specific sizes; keep whatever size we have
    img.save(out_path, format="ICO",
             sizes=[(img.width, img.height)])


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class Steganography:
    """Embed / extract binary payloads in image files."""

    def __init__(self, bits_per_channel: int = 1):
        if bits_per_channel not in _BPC_RANGE:
            raise ValueError(
                f"bits_per_channel must be 1–4, got {bits_per_channel}"
            )
        self.bpc = bits_per_channel

    # -- informational -------------------------------------------------------

    def capacity(self, image_path: str) -> int:
        """Return max payload bytes for the given carrier image."""
        img = Image.open(image_path)
        fmt = self._detect_format(image_path, img)
        if fmt == "ico":
            img, _ = _load_ico_largest_frame(image_path)
        else:
            target_mode = "RGB" if fmt == "bmp" else "RGBA"
            img = img.convert(target_mode)
        return _image_capacity(img, self.bpc)

    # -- embed ---------------------------------------------------------------

    def embed(self, payload: bytes, image_path: str, output_path: str) -> str:
        """Hide *payload* inside *image_path*, write result to *output_path*.

        Returns the output path on success.
        """
        img = Image.open(image_path)
        fmt = self._detect_format(image_path, img)

        Log.logSuccess(f"Carrier image: {image_path} ({img.size[0]}x{img.size[1]}, {fmt.upper()})")

        if fmt == "ico":
            frame, _ = _load_ico_largest_frame(image_path)
            cap = _image_capacity(frame, self.bpc)
            Log.logSuccess(f"ICO largest frame: {frame.size[0]}x{frame.size[1]}, capacity {cap} bytes")
            steg_frame = _embed_into_pixels(frame, payload, self.bpc)
            _save_ico(steg_frame, output_path)
        else:
            # PNG keeps RGBA for max capacity; BMP uses RGB because
            # Pillow's BMP writer drops the alpha to 24bpp anyway —
            # working in RGB keeps embed samples aligned with what
            # ends up on disk so external loaders (e.g. the C loader)
            # read the same channel order.
            target_mode = "RGB" if fmt == "bmp" else "RGBA"
            work = img.convert(target_mode)
            cap = _image_capacity(work, self.bpc)
            Log.logSuccess(f"Image capacity: {cap} bytes at {self.bpc} bit(s)/channel")
            steg = _embed_into_pixels(work, payload, self.bpc)

            save_fmt = "PNG" if fmt == "png" else "BMP"
            steg.save(output_path, format=save_fmt)

        Log.logSuccess(f"Embedded {len(payload)} bytes into {output_path}")
        return output_path

    # -- extract -------------------------------------------------------------

    def extract(self, image_path: str) -> bytearray:
        """Read hidden payload from a steganographic image.

        Returns the raw payload bytes.
        """
        img = Image.open(image_path)
        fmt = self._detect_format(image_path, img)

        if fmt == "ico":
            frame, _ = _load_ico_largest_frame(image_path)
            data = _extract_from_pixels(frame, self.bpc)
        else:
            target_mode = "RGB" if fmt == "bmp" else "RGBA"
            work = img.convert(target_mode)
            data = _extract_from_pixels(work, self.bpc)

        Log.logSuccess(f"Extracted {len(data)} bytes from {image_path}")
        return data

    # -- helpers -------------------------------------------------------------

    @staticmethod
    def _detect_format(path: str, img: Image.Image) -> str:
        """Determine if the image is png, bmp, or ico."""
        pil_fmt = (img.format or "").lower()
        if pil_fmt in SUPPORTED_FORMATS:
            return pil_fmt

        # Fall back to extension
        ext = Path(path).suffix.lower().lstrip(".")
        if ext in SUPPORTED_FORMATS:
            return ext
        if ext == "icon":
            return "ico"

        # Default to PNG (safest lossless format)
        return "png"
