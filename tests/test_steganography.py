"""
Test suite for image steganography module.
Tests embed/extract roundtrips across PNG, BMP, and ICO formats
at multiple bit depths, plus edge cases and CLI integration.
"""
import os
import sys
import struct
import subprocess
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PIL import Image
from utils.steganography import (
    Steganography, _bytes_to_bits, _bits_to_bytes, _image_capacity
)

TEST_SHELLCODE = bytearray(
    b'\x31\xc0\x50\x68\x63\x61\x6c\x63'
    b'\x54\x59\x50\x40\xfe\xff\x00\x01' * 4
)

FORMATS = [
    ("PNG", (100, 100), "png"),
    ("BMP", (100, 100), "bmp"),
    ("ICO", (32, 32), "ico"),
]


class TestResults:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.failures = []

    def add_pass(self, name):
        self.passed += 1
        print(f"  [PASS] {name}")

    def add_fail(self, name, error):
        self.failed += 1
        self.failures.append((name, str(error)))
        print(f"  [FAIL] {name}: {error}")

    def summary(self):
        print(f"\n{'=' * 60}")
        print(f"SUMMARY: {self.passed} passed, {self.failed} failed")
        if self.failures:
            print("\nFailed tests:")
            for name, error in self.failures:
                print(f"  - {name}: {error}")
        print(f"{'=' * 60}")
        return self.failed == 0


def _make_carrier(fmt, size):
    """Create a carrier image with varied pixel data."""
    img = Image.new("RGBA", size, (100, 150, 200, 255))
    for x in range(size[0]):
        for y in range(size[1]):
            img.putpixel(
                (x, y),
                ((x * 7 + y * 3) % 256, (x * 3 + y * 7) % 256,
                 (x * 5 + y * 11) % 256, 255),
            )
    tf = tempfile.NamedTemporaryFile(suffix=f".{fmt.lower()}", delete=False)
    tf.close()
    if fmt == "ICO":
        img.save(tf.name, format="ICO", sizes=[size])
    else:
        img.save(tf.name, format=fmt)
    return tf.name


# ===== Unit tests for bit conversion =====

def test_bit_conversion():
    print("\n[TEST] Bit conversion helpers")
    results = TestResults()

    for bpc in [1, 2, 4]:
        data = bytes(range(256))
        chunks = _bytes_to_bits(data, bpc)
        recovered = _bits_to_bytes(chunks, bpc)
        if recovered == bytearray(data):
            results.add_pass(f"bits roundtrip bpc={bpc}")
        else:
            results.add_fail(f"bits roundtrip bpc={bpc}", "mismatch")

    # Single byte
    for bpc in [1, 2, 4]:
        chunks = _bytes_to_bits(b"\xA5", bpc)
        recovered = _bits_to_bytes(chunks, bpc)
        if recovered == bytearray(b"\xA5"):
            results.add_pass(f"single byte 0xA5 bpc={bpc}")
        else:
            results.add_fail(f"single byte 0xA5 bpc={bpc}", f"got {recovered.hex()}")

    return results


# ===== Capacity tests =====

def test_capacity():
    print("\n[TEST] Image capacity")
    results = TestResults()

    for fmt, size, ext in FORMATS:
        path = _make_carrier(fmt, size)
        try:
            for bpc in [1, 2, 4]:
                steg = Steganography(bits_per_channel=bpc)
                cap = steg.capacity(path)
                if cap > 0:
                    results.add_pass(f"{fmt} bpc={bpc} capacity={cap}")
                else:
                    results.add_fail(f"{fmt} bpc={bpc} capacity", "zero or negative")
        finally:
            os.unlink(path)

    # Capacity scales with bpc
    path = _make_carrier("PNG", (50, 50))
    try:
        c1 = Steganography(1).capacity(path)
        c2 = Steganography(2).capacity(path)
        c4 = Steganography(4).capacity(path)
        if c2 > c1 and c4 > c2:
            results.add_pass("capacity increases with bpc")
        else:
            results.add_fail("capacity scaling", f"c1={c1} c2={c2} c4={c4}")
    finally:
        os.unlink(path)

    return results


# ===== Embed / extract roundtrip =====

def test_roundtrip():
    print("\n[TEST] Embed/extract roundtrip")
    results = TestResults()

    for fmt, size, ext in FORMATS:
        carrier = _make_carrier(fmt, size)
        try:
            for bpc in [1, 2, 4]:
                steg = Steganography(bits_per_channel=bpc)
                cap = steg.capacity(carrier)
                if cap < len(TEST_SHELLCODE):
                    continue

                out = tempfile.NamedTemporaryFile(suffix=f".{ext}", delete=False)
                out.close()
                try:
                    steg.embed(TEST_SHELLCODE, carrier, out.name)
                    extracted = steg.extract(out.name)
                    if extracted == TEST_SHELLCODE:
                        results.add_pass(f"{fmt} bpc={bpc} roundtrip")
                    else:
                        results.add_fail(
                            f"{fmt} bpc={bpc} roundtrip",
                            f"got {len(extracted)}B, expected {len(TEST_SHELLCODE)}B"
                        )
                finally:
                    os.unlink(out.name)
        finally:
            os.unlink(carrier)

    return results


# ===== File signature preservation =====

def test_signature_preservation():
    print("\n[TEST] File signature preservation")
    results = TestResults()

    signatures = {
        "PNG": b"\x89PNG",
        "BMP": b"BM",
        "ICO": b"\x00\x00\x01\x00",
    }

    for fmt, size, ext in FORMATS:
        carrier = _make_carrier(fmt, size)
        out = tempfile.NamedTemporaryFile(suffix=f".{ext}", delete=False)
        out.close()
        try:
            steg = Steganography(bits_per_channel=1)
            steg.embed(TEST_SHELLCODE[:16], carrier, out.name)

            with open(out.name, "rb") as f:
                header = f.read(8)

            expected = signatures[fmt]
            if header[:len(expected)] == expected:
                results.add_pass(f"{fmt} signature intact")
            else:
                results.add_fail(f"{fmt} signature", f"got {header[:4].hex()}")
        finally:
            os.unlink(carrier)
            os.unlink(out.name)

    return results


# ===== Edge cases =====

def test_edge_cases():
    print("\n[TEST] Edge cases")
    results = TestResults()

    carrier = _make_carrier("PNG", (100, 100))
    try:
        steg = Steganography(bits_per_channel=1)

        # Empty payload
        out = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
        out.close()
        try:
            steg.embed(b"", carrier, out.name)
            extracted = steg.extract(out.name)
            if extracted == bytearray():
                results.add_pass("empty payload roundtrip")
            else:
                results.add_fail("empty payload", f"got {len(extracted)} bytes")
        finally:
            os.unlink(out.name)

        # Single byte
        out = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
        out.close()
        try:
            steg.embed(b"\xCC", carrier, out.name)
            extracted = steg.extract(out.name)
            if extracted == bytearray(b"\xCC"):
                results.add_pass("single byte 0xCC")
            else:
                results.add_fail("single byte", f"got {extracted.hex()}")
        finally:
            os.unlink(out.name)

        # All zeros
        payload = b"\x00" * 32
        out = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
        out.close()
        try:
            steg.embed(payload, carrier, out.name)
            extracted = steg.extract(out.name)
            if extracted == bytearray(payload):
                results.add_pass("all-zero payload")
            else:
                results.add_fail("all-zero payload", "mismatch")
        finally:
            os.unlink(out.name)

        # All 0xFF
        payload = b"\xFF" * 32
        out = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
        out.close()
        try:
            steg.embed(payload, carrier, out.name)
            extracted = steg.extract(out.name)
            if extracted == bytearray(payload):
                results.add_pass("all-0xFF payload")
            else:
                results.add_fail("all-0xFF payload", "mismatch")
        finally:
            os.unlink(out.name)

        # Overflow detection
        tiny = _make_carrier("PNG", (4, 4))
        try:
            big = b"\x41" * 1000
            try:
                steg.embed(big, tiny, "/dev/null")
                results.add_fail("overflow detection", "should have raised ValueError")
            except ValueError:
                results.add_pass("overflow raises ValueError")
        finally:
            os.unlink(tiny)

        # Invalid bpc
        try:
            Steganography(bits_per_channel=5)
            results.add_fail("invalid bpc", "should have raised ValueError")
        except ValueError:
            results.add_pass("invalid bpc=5 raises ValueError")

    finally:
        os.unlink(carrier)

    return results


# ===== Max capacity fill =====

def test_max_capacity_fill():
    print("\n[TEST] Fill to max capacity")
    results = TestResults()

    carrier = _make_carrier("PNG", (50, 50))
    out = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
    out.close()
    try:
        steg = Steganography(bits_per_channel=2)
        cap = steg.capacity(carrier)
        payload = os.urandom(cap)

        steg.embed(payload, carrier, out.name)
        extracted = steg.extract(out.name)
        if extracted == bytearray(payload):
            results.add_pass(f"max fill ({cap} bytes)")
        else:
            results.add_fail(f"max fill", f"mismatch at {cap} bytes")
    finally:
        os.unlink(carrier)
        os.unlink(out.name)

    return results


# ===== CLI integration =====

def test_cli_steganography():
    print("\n[TEST] CLI steganography integration")
    results = TestResults()

    project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    main_py = os.path.join(project_dir, "main.py")

    carrier = _make_carrier("PNG", (100, 100))

    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(TEST_SHELLCODE)
        sc_file = f.name

    steg_out = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
    steg_out.close()
    extract_out = tempfile.NamedTemporaryFile(suffix=".bin", delete=False)
    extract_out.close()

    try:
        # Embed
        r = subprocess.run(
            [sys.executable, main_py,
             "-i", sc_file, "-e", "xor", "-k", "4141", "-f", "raw",
             "--steg-embed", carrier, "-o", steg_out.name],
            capture_output=True, text=True, timeout=30,
        )
        if r.returncode == 0:
            results.add_pass("CLI embed exit 0")
        else:
            results.add_fail("CLI embed", f"exit {r.returncode}: {r.stderr[:200]}")

        # Extract
        r2 = subprocess.run(
            [sys.executable, main_py,
             "-i", sc_file,
             "--steg-extract", steg_out.name,
             "-o", extract_out.name],
            capture_output=True, text=True, timeout=30,
        )
        if r2.returncode == 0:
            results.add_pass("CLI extract exit 0")
        else:
            results.add_fail("CLI extract", f"exit {r2.returncode}: {r2.stderr[:200]}")

        if os.path.exists(extract_out.name):
            with open(extract_out.name, "rb") as f:
                data = f.read()
            if len(data) > 0:
                results.add_pass(f"CLI extracted {len(data)} bytes")
            else:
                results.add_fail("CLI extract data", "empty")

        # Capacity check
        r3 = subprocess.run(
            [sys.executable, main_py,
             "-i", sc_file,
             "--steg-capacity", carrier],
            capture_output=True, text=True, timeout=30,
        )
        combined = r3.stdout + r3.stderr
        if "Max payload" in combined or "capacity" in combined.lower():
            results.add_pass("CLI capacity check")
        else:
            results.add_fail("CLI capacity", f"output: {combined[:200]}")

    finally:
        for p in [carrier, sc_file, steg_out.name, extract_out.name]:
            if os.path.exists(p):
                os.unlink(p)

    return results


# ===== C resource loader integration =====

def _find_compiler():
    """Locate a working C compiler, return (compiler_args, is_available)."""
    import shutil
    # Try cl.exe (MSVC) first, then gcc, then cc
    for compiler in ["cl", "gcc", "cc", "x86_64-w64-mingw32-gcc"]:
        if shutil.which(compiler):
            return compiler, True
    return None, False


def test_c_loader_extraction():
    """Compile steg_loader.c and verify it extracts the same payload Python embedded."""
    print("\n[TEST] C resource loader extraction")
    results = TestResults()

    compiler, available = _find_compiler()
    if not available:
        print("  [SKIP] No C compiler found (cl/gcc/cc)")
        return results

    test_dir = os.path.dirname(os.path.abspath(__file__))
    loader_src = os.path.join(test_dir, "steg_loader.c")

    if not os.path.exists(loader_src):
        results.add_fail("steg_loader.c exists", "file not found")
        return results

    # Build into a temp directory
    build_dir = tempfile.mkdtemp(prefix="steg_build_")
    if sys.platform == "win32":
        loader_exe = os.path.join(build_dir, "steg_loader.exe")
    else:
        loader_exe = os.path.join(build_dir, "steg_loader")

    try:
        # Compile
        if compiler == "cl":
            compile_cmd = [compiler, "/nologo", "/O2", "/W3",
                           loader_src, f"/Fe:{loader_exe}",
                           f"/Fo:{build_dir}\\"]
        else:
            compile_cmd = [compiler, "-O2", "-Wall", "-o", loader_exe, loader_src]

        comp = subprocess.run(compile_cmd, capture_output=True, text=True, timeout=30)
        if comp.returncode != 0:
            results.add_fail("compile steg_loader.c",
                             f"exit {comp.returncode}: {(comp.stderr or comp.stdout)[:300]}")
            return results
        results.add_pass(f"compiled with {compiler}")

        # Test at each bpc level
        for bpc in [1, 2, 4]:
            carrier = _make_carrier("BMP", (100, 100))
            steg_bmp = tempfile.NamedTemporaryFile(suffix=".bmp", delete=False)
            steg_bmp.close()
            dump_out = tempfile.NamedTemporaryFile(suffix=".bin", delete=False)
            dump_out.close()

            try:
                # Embed with Python
                payload = os.urandom(64)
                steg = Steganography(bits_per_channel=bpc)
                steg.embed(payload, carrier, steg_bmp.name)

                # Extract with C loader in dump mode
                r = subprocess.run(
                    [loader_exe, steg_bmp.name, "--bpc", str(bpc),
                     "--dump-to", dump_out.name],
                    capture_output=True, text=True, timeout=10,
                )

                if r.returncode != 0:
                    results.add_fail(
                        f"C loader bpc={bpc} extract",
                        f"exit {r.returncode}: {r.stderr[:200]}"
                    )
                    continue

                with open(dump_out.name, "rb") as f:
                    c_extracted = f.read()

                if c_extracted == payload:
                    results.add_pass(f"C loader bpc={bpc} matches Python embed (64B)")
                else:
                    # Show first divergence
                    for idx, (a, b) in enumerate(zip(c_extracted, payload)):
                        if a != b:
                            results.add_fail(
                                f"C loader bpc={bpc} match",
                                f"first diff at byte {idx}: C=0x{a:02x} Py=0x{b:02x}, "
                                f"C_len={len(c_extracted)} Py_len={len(payload)}"
                            )
                            break
                    else:
                        results.add_fail(
                            f"C loader bpc={bpc} match",
                            f"length mismatch: C={len(c_extracted)} Py={len(payload)}"
                        )

            finally:
                for p in [carrier, steg_bmp.name, dump_out.name]:
                    if os.path.exists(p):
                        os.unlink(p)

        # Test with a larger payload (encrypt + embed pipeline)
        carrier = _make_carrier("BMP", (200, 200))
        steg_bmp = tempfile.NamedTemporaryFile(suffix=".bmp", delete=False)
        steg_bmp.close()
        dump_out = tempfile.NamedTemporaryFile(suffix=".bin", delete=False)
        dump_out.close()

        try:
            big_payload = os.urandom(1024)
            steg = Steganography(bits_per_channel=1)
            steg.embed(big_payload, carrier, steg_bmp.name)

            r = subprocess.run(
                [loader_exe, steg_bmp.name, "--dump-to", dump_out.name],
                capture_output=True, text=True, timeout=10,
            )

            if r.returncode == 0:
                with open(dump_out.name, "rb") as f:
                    c_big = f.read()
                if c_big == big_payload:
                    results.add_pass("C loader 1KB payload roundtrip")
                else:
                    results.add_fail("C loader 1KB", f"len C={len(c_big)} Py={len(big_payload)}")
            else:
                results.add_fail("C loader 1KB extract", f"exit {r.returncode}")
        finally:
            for p in [carrier, steg_bmp.name, dump_out.name]:
                if os.path.exists(p):
                    os.unlink(p)

        # Test max-fill at bpc=2 with C extraction
        carrier = _make_carrier("BMP", (80, 80))
        steg_bmp = tempfile.NamedTemporaryFile(suffix=".bmp", delete=False)
        steg_bmp.close()
        dump_out = tempfile.NamedTemporaryFile(suffix=".bin", delete=False)
        dump_out.close()

        try:
            steg = Steganography(bits_per_channel=2)
            cap = steg.capacity(carrier)
            max_payload = os.urandom(cap)
            steg.embed(max_payload, carrier, steg_bmp.name)

            r = subprocess.run(
                [loader_exe, steg_bmp.name, "--bpc", "2",
                 "--dump-to", dump_out.name],
                capture_output=True, text=True, timeout=10,
            )

            if r.returncode == 0:
                with open(dump_out.name, "rb") as f:
                    c_max = f.read()
                if c_max == max_payload:
                    results.add_pass(f"C loader max-fill ({cap}B) bpc=2")
                else:
                    results.add_fail(f"C loader max-fill", f"len C={len(c_max)} expected={cap}")
            else:
                results.add_fail("C loader max-fill extract", f"exit {r.returncode}")
        finally:
            for p in [carrier, steg_bmp.name, dump_out.name]:
                if os.path.exists(p):
                    os.unlink(p)

    finally:
        # Clean up build artifacts
        import shutil as _shutil
        _shutil.rmtree(build_dir, ignore_errors=True)

    return results


def run_all_tests():
    all_results = []
    all_results.append(test_bit_conversion())
    all_results.append(test_capacity())
    all_results.append(test_roundtrip())
    all_results.append(test_signature_preservation())
    all_results.append(test_edge_cases())
    all_results.append(test_max_capacity_fill())
    all_results.append(test_cli_steganography())
    all_results.append(test_c_loader_extraction())

    total_passed = sum(r.passed for r in all_results)
    total_failed = sum(r.failed for r in all_results)
    all_failures = []
    for r in all_results:
        all_failures.extend(r.failures)

    print(f"\n{'=' * 60}")
    print(f"STEGANOGRAPHY TESTS: {total_passed} passed, {total_failed} failed")
    if all_failures:
        print("\nAll failures:")
        for name, error in all_failures:
            print(f"  - {name}: {error}")
    print(f"{'=' * 60}")
    return total_failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
