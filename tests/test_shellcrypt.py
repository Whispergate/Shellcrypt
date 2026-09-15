"""
Comprehensive test suite for Shellcrypt.
Tests encryption/decryption, encoding/decoding, compression/decompression,
output formats, and CLI roundtrips.
"""
import subprocess
import sys
import os
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.crypters import Encrypt, Encode, Compress, ShellcodeFormatter

TEST_SHELLCODE = bytearray(b'\x31\xc0\x50\x68\x63\x61\x6c\x63\x54\x59\x50\x40\xfe\xff\x00\x01')

OUTPUT_FORMATS = ["c", "csharp", "nim", "go", "py", "ps1", "vba", "vbscript", "raw", "rust", "js", "zig"]
CIPHERS = ["aes_128", "aes_ecb", "aes_cbc", "chacha20", "rc4", "salsa20", "xor", "xor_complex"]
SYMMETRIC_CIPHERS = ["xor", "xor_complex", "rc4"]
KEYED_CIPHERS = ["aes_128", "aes_ecb", "aes_cbc", "chacha20", "salsa20"]
ENCODINGS = ["alpha32", "ascii85", "base64", "words256"]
COMPRESSIONS = ["lznt", "rle"]


class TestResults:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.failures = []

    def add_pass(self, test_name):
        self.passed += 1
        print(f"  [PASS] {test_name}")

    def add_fail(self, test_name, error):
        self.failed += 1
        self.failures.append((test_name, str(error)))
        print(f"  [FAIL] {test_name}: {error}")

    def summary(self):
        print("\n" + "=" * 60)
        print(f"SUMMARY: {self.passed} passed, {self.failed} failed")
        if self.failures:
            print("\nFailed tests:")
            for name, error in self.failures:
                print(f"  - {name}: {error}")
        print("=" * 60)
        return self.failed == 0


# ===== Output Format Tests =====

def test_output_formats():
    print("\n[TEST] Output formats")
    results = TestResults()
    formatter = ShellcodeFormatter()
    arrays = {"key": bytearray([0x41, 0x42]), "sh3llc0d3": TEST_SHELLCODE}

    for fmt in OUTPUT_FORMATS:
        try:
            output = formatter.generate(fmt, arrays)
            if output is not None and len(output) > 0:
                results.add_pass(f"Format: {fmt}")
            else:
                results.add_fail(f"Format: {fmt}", "Empty output")
        except Exception as e:
            results.add_fail(f"Format: {fmt}", str(e))

    return results


def test_format_syntax_validity():
    print("\n[TEST] Format syntax validity")
    results = TestResults()
    formatter = ShellcodeFormatter()
    arrays = {"key": bytearray([0x41] * 16), "shellcode": TEST_SHELLCODE}

    checks = {
        "c": lambda o: "unsigned char key[16]" in o and "unsigned char shellcode[16]" in o,
        "csharp": lambda o: "byte[] key = new byte[16]" in o and "byte[] shellcode = new byte[16]" in o,
        "rust": lambda o: "let key: [u8; 16]" in o and "let shellcode: [u8; 16]" in o,
        "go": lambda o: "var key = []byte{" in o and "var shellcode = []byte{" in o,
        "zig": lambda o: "var key: [16]u8 = .{" in o and "var shellcode: [16]u8 = .{" in o,
        "nim": lambda o: "var key: array[16, byte]" in o and "var shellcode: array[16, byte]" in o,
        "py": lambda o: 'key = b"""' in o and 'shellcode = b"""' in o,
        "ps1": lambda o: "[Byte[]] $key" in o and "[Byte[]] $shellcode" in o,
        "vba": lambda o: "key = Array(" in o and "shellcode = Array(" in o,
        "js": lambda o: "const key = new Uint8Array(16)" in o and "const shellcode = new Uint8Array(16)" in o,
    }

    for fmt, check in checks.items():
        try:
            output = formatter.generate(fmt, arrays)
            if check(output):
                results.add_pass(f"Syntax: {fmt}")
            else:
                results.add_fail(f"Syntax: {fmt}", f"Unexpected structure")
        except Exception as e:
            results.add_fail(f"Syntax: {fmt}", str(e))

    return results


def test_custom_array_name():
    print("\n[TEST] Custom array name (-a flag)")
    results = TestResults()
    formatter = ShellcodeFormatter()
    arrays = {"key": bytearray([0x41]), "my_payload": TEST_SHELLCODE}

    for fmt in ["c", "csharp", "rust", "go", "py", "nim", "zig"]:
        try:
            output = formatter.generate(fmt, arrays)
            if "my_payload" in output:
                results.add_pass(f"Custom name in {fmt}")
            else:
                results.add_fail(f"Custom name in {fmt}", "Array name not found")
        except Exception as e:
            results.add_fail(f"Custom name in {fmt}", str(e))

    return results


def test_raw_format():
    print("\n[TEST] Raw format output")
    results = TestResults()
    formatter = ShellcodeFormatter()

    arrays = {"key": bytearray([0x41]), "nonce": bytearray([0x42] * 16), "payload": TEST_SHELLCODE}
    output = formatter.generate("raw", arrays)
    if output == TEST_SHELLCODE:
        results.add_pass("Raw returns shellcode bytes only (skips key/nonce)")
    else:
        results.add_fail("Raw output", f"Got {len(output)} bytes, expected {len(TEST_SHELLCODE)}")

    return results


def test_single_byte_key_formatting():
    print("\n[TEST] Single-byte key formatting")
    results = TestResults()
    formatter = ShellcodeFormatter()

    for val, label in [(0x00, "0x00"), (0xFF, "0xff"), (0x0A, "0x0a")]:
        arrays = {"key": bytearray([val]), "sc": TEST_SHELLCODE}
        output = formatter.generate("c", arrays)
        if label in output:
            results.add_pass(f"Single byte {label}")
        else:
            results.add_fail(f"Single byte {label}", "Missing leading 0x prefix")

    return results


def test_vba_line_wrapping():
    print("\n[TEST] VBA line wrapping")
    results = TestResults()
    formatter = ShellcodeFormatter()
    big_data = bytearray(range(256)) * 4
    arrays = {"sc": big_data}
    output = formatter.generate("vba", arrays)

    for line in output.split("\n"):
        if len(line) > 1024:
            results.add_fail("VBA line length", f"Line too long: {len(line)} chars")
            return results

    if output.rstrip().endswith(")"):
        results.add_pass("VBA wrapping and closing paren")
    else:
        results.add_fail("VBA closing", "Missing closing parenthesis")

    return results


# ===== Encryption / Decryption Tests =====

def test_encryption_produces_output():
    print("\n[TEST] Encryption produces output")
    results = TestResults()
    cryptor = Encrypt()
    key_16 = bytearray([0x41] * 16)
    key_32 = bytearray([0x41] * 32)
    nonce = bytearray([0x42] * 16)

    for cipher in CIPHERS:
        try:
            key = key_16 if "aes" in cipher else key_32
            encrypted = cryptor.encrypt(cipher, TEST_SHELLCODE.copy(), key, nonce)
            if encrypted != TEST_SHELLCODE and len(encrypted) > 0:
                results.add_pass(f"Encrypt: {cipher}")
            else:
                results.add_fail(f"Encrypt: {cipher}", "Output unchanged or empty")
        except Exception as e:
            results.add_fail(f"Encrypt: {cipher}", str(e))

    return results


def test_symmetric_cipher_roundtrip():
    print("\n[TEST] Symmetric cipher roundtrip (encrypt twice = original)")
    results = TestResults()
    cryptor = Encrypt()
    key = bytearray([0x41] * 32)
    nonce = bytearray([0x42] * 16)

    for cipher in SYMMETRIC_CIPHERS:
        try:
            encrypted = cryptor.encrypt(cipher, TEST_SHELLCODE.copy(), key, nonce)
            decrypted = cryptor.encrypt(cipher, encrypted, key, nonce)
            if decrypted == TEST_SHELLCODE:
                results.add_pass(f"Roundtrip: {cipher}")
            else:
                results.add_fail(f"Roundtrip: {cipher}", "Mismatch")
        except Exception as e:
            results.add_fail(f"Roundtrip: {cipher}", str(e))

    return results


def test_decrypt_methods():
    print("\n[TEST] Decrypt methods (encrypt then decrypt)")
    results = TestResults()
    cryptor = Encrypt()
    key_16 = bytearray([0x41] * 16)
    key_32 = bytearray([0x41] * 32)
    nonce_16 = bytearray([0x42] * 16)

    for cipher in CIPHERS:
        try:
            key = key_16 if "aes" in cipher else key_32
            encrypted = cryptor.encrypt(cipher, TEST_SHELLCODE.copy(), key, nonce_16)
            nonce_for_decrypt = cryptor.nonce
            decrypted = cryptor.decrypt(cipher, encrypted, key, nonce_for_decrypt)
            if decrypted == TEST_SHELLCODE:
                results.add_pass(f"Decrypt: {cipher}")
            else:
                results.add_fail(f"Decrypt: {cipher}", f"Mismatch: got {decrypted.hex()}, expected {TEST_SHELLCODE.hex()}")
        except Exception as e:
            results.add_fail(f"Decrypt: {cipher}", str(e))

    return results


def test_xor_null_key():
    print("\n[TEST] XOR with null key (identity)")
    results = TestResults()
    cryptor = Encrypt()
    encrypted = cryptor.encrypt("xor", TEST_SHELLCODE.copy(), bytearray([0x00]), bytearray(16))
    if encrypted == TEST_SHELLCODE:
        results.add_pass("XOR 0x00 key = identity")
    else:
        results.add_fail("XOR 0x00 key", "Expected identity")
    return results


def test_chacha20_salsa20_nonce_capture():
    print("\n[TEST] ChaCha20/Salsa20 nonce capture")
    results = TestResults()
    key = bytearray([0x41] * 32)

    for cipher in ["chacha20", "salsa20"]:
        cryptor = Encrypt()
        cryptor.encrypt(cipher, TEST_SHELLCODE.copy(), key, None)
        if cryptor.nonce is not None and len(cryptor.nonce) == 8:
            results.add_pass(f"{cipher} nonce captured (8 bytes)")
        else:
            nlen = len(cryptor.nonce) if cryptor.nonce else 0
            results.add_fail(f"{cipher} nonce", f"Expected 8 bytes, got {nlen}")

    return results


def test_aes_padding():
    print("\n[TEST] AES padding/unpadding")
    results = TestResults()
    cryptor = Encrypt()
    key = bytearray([0x41] * 16)
    nonce = bytearray([0x42] * 16)

    for size in [1, 15, 16, 17, 31, 32, 48, 100]:
        data = bytearray(range(size % 256)) * (size // 256 + 1)
        data = bytearray(data[:size])
        for cipher in ["aes_128", "aes_ecb", "aes_cbc"]:
            try:
                encrypted = cryptor.encrypt(cipher, data.copy(), key, nonce)
                decrypted = cryptor.decrypt(cipher, encrypted, key, nonce)
                if decrypted == data:
                    results.add_pass(f"{cipher} size={size}")
                else:
                    results.add_fail(f"{cipher} size={size}", f"Mismatch: {len(decrypted)} vs {len(data)}")
            except Exception as e:
                results.add_fail(f"{cipher} size={size}", str(e))

    return results


# ===== Encoding / Decoding Tests =====

def test_encoding_roundtrip():
    print("\n[TEST] Encoding roundtrip (all 256 byte values)")
    results = TestResults()
    encoder = Encode()
    data = bytearray(range(256))

    for encoding in ENCODINGS:
        try:
            encoded = encoder.encode(encoding, data.copy())
            decoded = encoder.decode(encoding, encoded)
            if decoded == data:
                results.add_pass(f"Roundtrip: {encoding}")
            else:
                mismatches = sum(1 for a, b in zip(decoded, data) if a != b)
                results.add_fail(f"Roundtrip: {encoding}", f"{mismatches} byte mismatches")
        except Exception as e:
            results.add_fail(f"Roundtrip: {encoding}", str(e))

    return results


def test_encoding_empty_input():
    print("\n[TEST] Encoding empty input")
    results = TestResults()
    encoder = Encode()
    empty = bytearray()

    for encoding in ENCODINGS:
        try:
            encoded = encoder.encode(encoding, empty)
            decoded = encoder.decode(encoding, encoded)
            if decoded == empty:
                results.add_pass(f"Empty: {encoding}")
            else:
                results.add_fail(f"Empty: {encoding}", f"Got {len(decoded)} bytes")
        except Exception as e:
            results.add_fail(f"Empty: {encoding}", str(e))

    return results


def test_words256_unique_words():
    print("\n[TEST] words256 has 256 unique words")
    results = TestResults()
    words = Encode._Encode__build_wordlist()
    if len(words) == 256:
        results.add_pass("Wordlist length = 256")
    else:
        results.add_fail("Wordlist length", f"Got {len(words)}")
    if len(set(words)) == 256:
        results.add_pass("All words unique")
    else:
        results.add_fail("Uniqueness", f"Only {len(set(words))} unique")
    return results


# ===== Compression / Decompression Tests =====

def test_compression_roundtrip():
    print("\n[TEST] Compression roundtrip")
    results = TestResults()
    compressor = Compress()

    for method in COMPRESSIONS:
        try:
            compressed = compressor.compress(method, TEST_SHELLCODE.copy())
            decompressed = compressor.decompress(method, compressed)
            if bytearray(decompressed) == TEST_SHELLCODE:
                results.add_pass(f"Roundtrip: {method}")
            else:
                results.add_fail(f"Roundtrip: {method}", "Mismatch")
        except Exception as e:
            results.add_fail(f"Roundtrip: {method}", str(e))

    return results


def test_rle_long_runs():
    print("\n[TEST] RLE with runs > 255 bytes")
    results = TestResults()
    compressor = Compress()
    data = bytearray([0x41] * 300 + [0x42] * 600 + [0x43])

    compressed = compressor.compress("rle", data)
    for i in range(1, len(compressed), 2):
        if compressed[i] > 255:
            results.add_fail("RLE count overflow", f"Count byte = {compressed[i]}")
            return results

    decompressed = compressor.decompress("rle", compressed)
    if bytearray(decompressed) == data:
        results.add_pass("RLE long run roundtrip (300+600 bytes)")
    else:
        results.add_fail("RLE long run", f"Mismatch: got {len(decompressed)} expected {len(data)}")

    return results


def test_rle_single_bytes():
    print("\n[TEST] RLE with no repeats")
    results = TestResults()
    compressor = Compress()
    data = bytearray(range(256))

    compressed = compressor.compress("rle", data)
    decompressed = compressor.decompress("rle", compressed)
    if bytearray(decompressed) == data:
        results.add_pass("RLE no-repeat roundtrip")
    else:
        results.add_fail("RLE no-repeat", "Mismatch")

    return results


# ===== Full Pipeline Tests =====

def test_full_pipeline_roundtrip():
    print("\n[TEST] Full pipeline roundtrip (compress -> encrypt -> encode / decode -> decrypt -> decompress)")
    results = TestResults()
    cryptor = Encrypt()
    compressor = Compress()
    encoder = Encode()
    key = bytearray([0x41] * 16)
    nonce = bytearray([0x42] * 16)

    for cipher in ["xor", "rc4", "aes_128", "aes_cbc"]:
        for encoding in ["base64", "alpha32"]:
            for compression in ["rle"]:
                label = f"{compression}->{cipher}->{encoding}"
                try:
                    data = TEST_SHELLCODE.copy()

                    step1 = compressor.compress(compression, data)
                    step2 = cryptor.encrypt(cipher, bytearray(step1), key, nonce)
                    enc_nonce = cryptor.nonce
                    step3 = encoder.encode(encoding, step2)

                    d1 = encoder.decode(encoding, step3)
                    d2 = cryptor.decrypt(cipher, d1, key, enc_nonce)
                    d3 = compressor.decompress(compression, d2)

                    if bytearray(d3) == TEST_SHELLCODE:
                        results.add_pass(f"Pipeline: {label}")
                    else:
                        results.add_fail(f"Pipeline: {label}", "Final mismatch")
                except Exception as e:
                    results.add_fail(f"Pipeline: {label}", str(e))

    return results


def test_full_pipeline_chacha20():
    print("\n[TEST] Full pipeline with ChaCha20")
    results = TestResults()
    cryptor = Encrypt()
    compressor = Compress()
    encoder = Encode()
    key = bytearray([0x41] * 32)

    try:
        data = TEST_SHELLCODE.copy()
        step1 = compressor.compress("rle", data)
        step2 = cryptor.encrypt("chacha20", bytearray(step1), key, None)
        nonce = cryptor.nonce
        step3 = encoder.encode("base64", step2)

        d1 = encoder.decode("base64", step3)
        d2 = cryptor.decrypt("chacha20", d1, key, nonce)
        d3 = compressor.decompress("rle", d2)

        if bytearray(d3) == TEST_SHELLCODE:
            results.add_pass("Pipeline: rle->chacha20->base64")
        else:
            results.add_fail("Pipeline: rle->chacha20->base64", "Mismatch")
    except Exception as e:
        results.add_fail("Pipeline: rle->chacha20->base64", str(e))

    return results


# ===== CLI Integration Tests =====

def test_cli_encrypt_decrypt_roundtrip():
    print("\n[TEST] CLI encrypt/decrypt roundtrip")
    results = TestResults()

    script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    shellcrypt_path = os.path.join(script_dir, "shellcrypt.py")

    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(TEST_SHELLCODE)
        input_file = f.name

    try:
        key_hex = "41" * 16
        nonce_hex = "42" * 16

        for cipher in ["xor", "xor_complex", "rc4", "aes_128", "aes_ecb", "aes_cbc"]:
            with tempfile.NamedTemporaryFile(suffix=".enc", delete=False) as ef:
                enc_file = ef.name
            with tempfile.NamedTemporaryFile(suffix=".dec", delete=False) as df:
                dec_file = df.name

            try:
                subprocess.run(
                    [sys.executable, shellcrypt_path,
                     "-i", input_file, "-e", cipher, "-k", key_hex, "-n", nonce_hex,
                     "-f", "raw", "-o", enc_file],
                    capture_output=True, text=True, timeout=30
                )

                subprocess.run(
                    [sys.executable, shellcrypt_path,
                     "-i", enc_file, "-e", cipher, "-k", key_hex, "-n", nonce_hex,
                     "--decrypt", "-o", dec_file],
                    capture_output=True, text=True, timeout=30
                )

                with open(dec_file, "rb") as f:
                    decrypted = f.read()

                if bytearray(decrypted) == TEST_SHELLCODE:
                    results.add_pass(f"CLI roundtrip: {cipher}")
                else:
                    results.add_fail(f"CLI roundtrip: {cipher}",
                                     f"Mismatch: {decrypted.hex()} vs {TEST_SHELLCODE.hex()}")
            except subprocess.TimeoutExpired:
                results.add_fail(f"CLI roundtrip: {cipher}", "Timeout")
            except Exception as e:
                results.add_fail(f"CLI roundtrip: {cipher}", str(e))
            finally:
                for p in [enc_file, dec_file]:
                    if os.path.exists(p):
                        os.unlink(p)

        for cipher in ["chacha20", "salsa20"]:
            key_hex_32 = "41" * 32
            with tempfile.NamedTemporaryFile(suffix=".enc", delete=False) as ef:
                enc_file = ef.name
            with tempfile.NamedTemporaryFile(suffix=".dec", delete=False) as df:
                dec_file = df.name

            try:
                enc_result = subprocess.run(
                    [sys.executable, shellcrypt_path,
                     "-i", input_file, "-e", cipher, "-k", key_hex_32,
                     "-f", "raw", "-o", enc_file],
                    capture_output=True, text=True, timeout=30
                )

                enc_output = enc_result.stdout + enc_result.stderr
                nonce_line = None
                for line in enc_output.split("\n"):
                    if "nonce" in line.lower():
                        import re
                        match = re.search(r'[0-9a-fA-F]{16}', line)
                        if match:
                            nonce_line = match.group(0)

                if nonce_line is None:
                    results.add_fail(f"CLI roundtrip: {cipher}", "Could not extract nonce from output")
                    continue

                subprocess.run(
                    [sys.executable, shellcrypt_path,
                     "-i", enc_file, "-e", cipher, "-k", key_hex_32,
                     "-n", nonce_line, "--decrypt", "-o", dec_file],
                    capture_output=True, text=True, timeout=30
                )

                with open(dec_file, "rb") as f:
                    decrypted = f.read()

                if bytearray(decrypted) == TEST_SHELLCODE:
                    results.add_pass(f"CLI roundtrip: {cipher}")
                else:
                    results.add_fail(f"CLI roundtrip: {cipher}",
                                     f"Mismatch: {decrypted.hex()} vs {TEST_SHELLCODE.hex()}")
            except subprocess.TimeoutExpired:
                results.add_fail(f"CLI roundtrip: {cipher}", "Timeout")
            except Exception as e:
                results.add_fail(f"CLI roundtrip: {cipher}", str(e))
            finally:
                for p in [enc_file, dec_file]:
                    if os.path.exists(p):
                        os.unlink(p)
    finally:
        os.unlink(input_file)

    return results


def test_cli_full_pipeline():
    print("\n[TEST] CLI full pipeline (compress + encrypt + encode / decode + decrypt + decompress)")
    results = TestResults()

    script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    shellcrypt_path = os.path.join(script_dir, "shellcrypt.py")

    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(TEST_SHELLCODE)
        input_file = f.name

    key_hex = "41" * 16
    nonce_hex = "42" * 16

    with tempfile.NamedTemporaryFile(suffix=".enc", delete=False) as ef:
        enc_file = ef.name
    with tempfile.NamedTemporaryFile(suffix=".dec", delete=False) as df:
        dec_file = df.name

    try:
        subprocess.run(
            [sys.executable, shellcrypt_path,
             "-i", input_file, "-e", "xor", "-k", key_hex, "-n", nonce_hex,
             "-d", "base64", "-c", "rle",
             "-f", "raw", "-o", enc_file],
            capture_output=True, text=True, timeout=30
        )

        subprocess.run(
            [sys.executable, shellcrypt_path,
             "-i", enc_file, "-e", "xor", "-k", key_hex, "-n", nonce_hex,
             "-d", "base64", "-c", "rle",
             "--decrypt", "-o", dec_file],
            capture_output=True, text=True, timeout=30
        )

        with open(dec_file, "rb") as f:
            decrypted = f.read()

        if bytearray(decrypted) == TEST_SHELLCODE:
            results.add_pass("CLI full pipeline: rle->xor->base64 roundtrip")
        else:
            results.add_fail("CLI full pipeline", f"Mismatch: {decrypted.hex()} vs {TEST_SHELLCODE.hex()}")
    except Exception as e:
        results.add_fail("CLI full pipeline", str(e))
    finally:
        for p in [input_file, enc_file, dec_file]:
            if os.path.exists(p):
                os.unlink(p)

    return results


def test_cli_output_formats():
    print("\n[TEST] CLI output formats")
    results = TestResults()

    script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    shellcrypt_path = os.path.join(script_dir, "shellcrypt.py")

    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(TEST_SHELLCODE)
        input_file = f.name

    try:
        for fmt in OUTPUT_FORMATS:
            try:
                result = subprocess.run(
                    [sys.executable, shellcrypt_path,
                     "-i", input_file, "-e", "xor", "-k", "4141",
                     "-f", fmt, "-a", "test"],
                    capture_output=True, text=True, timeout=30
                )
                if result.returncode == 0:
                    results.add_pass(f"CLI format: {fmt}")
                else:
                    results.add_fail(f"CLI format: {fmt}", f"Exit code: {result.returncode}")
            except Exception as e:
                results.add_fail(f"CLI format: {fmt}", str(e))
    finally:
        os.unlink(input_file)

    return results


# ===== Edge Case Tests =====

def test_large_shellcode():
    print("\n[TEST] Large shellcode (4096 bytes)")
    results = TestResults()
    cryptor = Encrypt()
    encoder = Encode()
    large_data = bytearray(os.urandom(4096))
    key = bytearray([0x41] * 16)
    nonce = bytearray([0x42] * 16)

    for cipher in ["xor", "aes_128"]:
        try:
            encrypted = cryptor.encrypt(cipher, large_data.copy(), key, nonce)
            decrypted = cryptor.decrypt(cipher, encrypted, key, cryptor.nonce)
            if decrypted == large_data:
                results.add_pass(f"Large data: {cipher}")
            else:
                results.add_fail(f"Large data: {cipher}", "Mismatch")
        except Exception as e:
            results.add_fail(f"Large data: {cipher}", str(e))

    for encoding in ENCODINGS:
        try:
            encoded = encoder.encode(encoding, large_data.copy())
            decoded = encoder.decode(encoding, encoded)
            if decoded == large_data:
                results.add_pass(f"Large data encoding: {encoding}")
            else:
                results.add_fail(f"Large data encoding: {encoding}", "Mismatch")
        except Exception as e:
            results.add_fail(f"Large data encoding: {encoding}", str(e))

    return results


def test_single_byte_shellcode():
    print("\n[TEST] Single byte shellcode")
    results = TestResults()
    cryptor = Encrypt()
    data = bytearray([0xCC])
    key = bytearray([0x41] * 16)
    nonce = bytearray([0x42] * 16)

    for cipher in CIPHERS:
        try:
            k = key if "aes" in cipher else bytearray([0x41] * 32)
            encrypted = cryptor.encrypt(cipher, data.copy(), k, nonce)
            decrypted = cryptor.decrypt(cipher, encrypted, k, cryptor.nonce)
            if decrypted == data:
                results.add_pass(f"Single byte: {cipher}")
            else:
                results.add_fail(f"Single byte: {cipher}", f"Got {decrypted.hex()}")
        except Exception as e:
            results.add_fail(f"Single byte: {cipher}", str(e))

    return results


# ===== Run All =====

def run_all_tests():
    all_results = []

    all_results.append(test_output_formats())
    all_results.append(test_format_syntax_validity())
    all_results.append(test_custom_array_name())
    all_results.append(test_raw_format())
    all_results.append(test_single_byte_key_formatting())
    all_results.append(test_vba_line_wrapping())

    all_results.append(test_encryption_produces_output())
    all_results.append(test_symmetric_cipher_roundtrip())
    all_results.append(test_decrypt_methods())
    all_results.append(test_xor_null_key())
    all_results.append(test_chacha20_salsa20_nonce_capture())
    all_results.append(test_aes_padding())

    all_results.append(test_encoding_roundtrip())
    all_results.append(test_encoding_empty_input())
    all_results.append(test_words256_unique_words())

    all_results.append(test_compression_roundtrip())
    all_results.append(test_rle_long_runs())
    all_results.append(test_rle_single_bytes())

    all_results.append(test_full_pipeline_roundtrip())
    all_results.append(test_full_pipeline_chacha20())

    all_results.append(test_large_shellcode())
    all_results.append(test_single_byte_shellcode())

    all_results.append(test_cli_output_formats())
    all_results.append(test_cli_encrypt_decrypt_roundtrip())
    all_results.append(test_cli_full_pipeline())

    total_passed = sum(r.passed for r in all_results)
    total_failed = sum(r.failed for r in all_results)
    all_failures = []
    for r in all_results:
        all_failures.extend(r.failures)

    print("\n" + "=" * 60)
    print(f"FINAL RESULTS: {total_passed} passed, {total_failed} failed")
    if all_failures:
        print("\nAll failures:")
        for name, error in all_failures:
            print(f"  - {name}: {error}")
    print("=" * 60)

    return total_failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
