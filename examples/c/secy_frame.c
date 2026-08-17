/*
 * secy_frame.c — IEEE 802.1AE SecTAG pack/unpack (teaching subset)
 *
 * Layout: TCI (1) | SL (1) | PN (4 BE) | [ SCI (8 BE) if TCI.SC = 1 ]
 *
 * TCI (802.1AE Figure 9-1, bit 8 = MSB):
 *   0x80 V     version — must be 0 today
 *   0x40 ES
 *   0x20 SC    explicit SCI present
 *   0x10 SCB
 *   0x08 E     confidentiality
 *   0x04 C     user data changed by the cipher
 *   0x03 AN
 *
 * Build: make
 * Run:   ./secy_frame
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define TCI_SC 0x20u
#define TCI_E 0x08u
#define TCI_C 0x04u
#define TCI_AN 0x03u

typedef struct {
    uint8_t tci;
    uint8_t sl;
    uint32_t pn;
    uint64_t sci;
    int has_sci;
} sectag_fields_t;

static void u32_be_put(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)((v >> 24) & 0xff);
    p[1] = (uint8_t)((v >> 16) & 0xff);
    p[2] = (uint8_t)((v >> 8) & 0xff);
    p[3] = (uint8_t)(v & 0xff);
}

static uint32_t u32_be_get(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) |
           (uint32_t)p[3];
}

static void u64_be_put(uint8_t *p, uint64_t v) {
    for (int i = 7; i >= 0; i--) p[7 - i] = (uint8_t)((v >> (i * 8)) & 0xff);
}

static uint64_t u64_be_get(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}

static int sectag_pack(const sectag_fields_t *f, uint8_t *out, size_t out_cap) {
    int need = 2 + 4 + (f->has_sci ? 8 : 0);
    if ((size_t)need > out_cap) return -1;
    out[0] = f->tci;
    out[1] = f->sl;
    u32_be_put(out + 2, f->pn);
    if (f->has_sci) u64_be_put(out + 6, f->sci);
    return need;
}

static int sectag_unpack(const uint8_t *in, size_t in_len, sectag_fields_t *f) {
    if (in_len < 6u) return -1;
    f->tci = in[0];
    f->sl = in[1];
    f->pn = u32_be_get(in + 2);
    f->has_sci = (f->tci & TCI_SC) != 0;
    if (f->has_sci) {
        if (in_len < 14u) return -1;
        f->sci = u64_be_get(in + 6);
        return 14;
    }
    f->sci = 0;
    return 6;
}

static void hex(const char *label, const uint8_t *buf, size_t n) {
    printf("%s (%zu B): ", label, n);
    for (size_t i = 0; i < n; i++) printf("%02x", buf[i]);
    printf("\n");
}

int main(void) {
    /* V=0, SC=1, E=1, C=1, AN=0  → TCI 0x2C */
    sectag_fields_t a = {.tci = (uint8_t)(TCI_SC | TCI_E | TCI_C | (0u & TCI_AN)),
                         .sl = 0,
                         .pn = 0x00000001u,
                         .sci = 0x02000000000a0001ull,
                         .has_sci = 1};
    uint8_t wire[16];
    int n = sectag_pack(&a, wire, sizeof(wire));
    if (n < 0) return 1;
    hex("Packed SecTAG", wire, (size_t)n);

    sectag_fields_t b;
    memset(&b, 0, sizeof(b));
    if (sectag_unpack(wire, (size_t)n, &b) != n) return 1;
    printf("Parsed: TCI=0x%02x SL=%u PN=%u SCI=0x%016llx has_sci=%d\n", b.tci, b.sl, b.pn,
           (unsigned long long)b.sci, b.has_sci);

    sectag_fields_t c = {.tci = 0x40u | TCI_E | TCI_C, .sl = 40, .pn = 9u, .sci = 0, .has_sci = 0};
    uint8_t w2[8];
    int n2 = sectag_pack(&c, w2, sizeof(w2));
    hex("ES=1 no-SCI SecTAG", w2, (size_t)n2);
    return 0;
}
