/* Host-side unit test for sniffer_codec.c (build: gcc -Wall -Wextra -I../src ...). */
#include "sniffer_codec.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static int failures;
#define CHECK(cond)                                                                                \
	do {                                                                                       \
		if (!(cond)) {                                                                     \
			fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);            \
			failures++;                                                                \
		}                                                                                  \
	} while (0)

static uint16_t rd16(const uint8_t *p)
{
	return (uint16_t)(p[0] | (p[1] << 8));
}

/* Re-implementation of the reference Wireshark TLV walk (packet-dect-nr-tap.c):
 * header bytes 2..3 are the TLV chain length in bytes, TLVs advance by 8 bytes,
 * value length field (bytes 2..3 of each TLV) must not exceed 4. */
static int walk_reference(const uint8_t *rec, size_t len, uint16_t *types, int max)
{
	uint16_t tlvs_len = rd16(rec + 2);
	uint32_t end = 8 + tlvs_len;
	int n = 0;

	if (len < 8 + 8 * 8) {
		return -1; /* MIN_LENGTH of reference dissector */
	}
	for (uint32_t off = 8; off < end; off += 8) {
		uint16_t vlen = rd16(rec + off + 2);
		if (vlen > 4 || n >= max) {
			return -2;
		}
		types[n++] = rd16(rec + off);
	}
	return n;
}

int main(void)
{
	/* CRC-16/CCITT-FALSE check value. */
	CHECK(sniff_crc16((const uint8_t *)"123456789", 9) == 0x29B1);

	/* Record for a 80-bit PCC + 20-byte PDC with metrics. */
	uint8_t body[30];
	for (unsigned i = 0; i < sizeof(body); i++) {
		body[i] = (uint8_t)(0x10 + i);
	}
	struct sniff_rx_info info = {
		.phy_type = 1,
		.pdc_len = 20,
		.channel = 1677,
		.seq = 0x1234,
		.has_metrics = true,
		.metrics = {.pcc_rssi2 = -87, .pcc_snr = 40, .pdc_rssi2 = -84, .pdc_snr = -8},
	};
	uint8_t rec[256];
	size_t n = sniff_build_tap_record(rec, sizeof(rec), &info, body);
	CHECK(n == 8 + 8 * 8 + 10 + 20);
	CHECK(rec[0] == 1);
	CHECK(rd16(rec + 2) == 64); /* TLV chain bytes */
	CHECK(rd16(rec + 4) == 30); /* modem length */
	uint16_t types[16];
	int cnt = walk_reference(rec, n, types, 16);
	CHECK(cnt == 8);
	CHECK(types[0] == 1 && types[1] == 2 && types[2] == 7 && types[3] == 8);
	CHECK(types[4] == 3 && types[5] == 4 && types[6] == 5 && types[7] == 6);
	CHECK(rec[8 + 4] == 2 && rd16(rec + 8 + 4) == 2); /* data type = 80-bit with PDC */
	CHECK(rd16(rec + 8 + 8 + 4) == 0);                /* header status valid */
	CHECK(rd16(rec + 8 + 16 + 4) == 0x1234);          /* transaction id */
	CHECK(rd16(rec + 8 + 24 + 4) == 1677);            /* channel */
	CHECK((int16_t)rd16(rec + 8 + 32 + 4) == -87);
	CHECK(memcmp(rec + 8 + 64, body, 30) == 0);

	/* Without metrics and without PDC: padded to the minimum, PDC absent. */
	struct sniff_rx_info info2 = {.phy_type = 0, .pdc_len = 0, .channel = 1, .seq = 7};
	n = sniff_build_tap_record(rec, sizeof(rec), &info2, body);
	CHECK(n == 8 + 8 * 8 + 5);
	cnt = walk_reference(rec, n, types, 16);
	CHECK(cnt == 8);
	CHECK(types[0] == 1 && types[1] == 2 && types[2] == 7 && types[3] == 8);
	CHECK(types[4] == 0 && types[7] == 0);
	CHECK(rd16(rec + 8 + 4) == 3);     /* 40-bit, PDC absent */
	CHECK(rd16(rec + 8 + 8 + 4) == 2); /* header status: valid, no PDC */

	/* Buffer too small must fail cleanly. */
	CHECK(sniff_build_tap_record(rec, 10, &info2, body) == 0);

	/* Frame encode + decode roundtrip, plus resync after garbage and CRC error. */
	uint8_t cmd[16];
	uint8_t pl[6] = {0x3D, 0x06, 0xFF, 0x7F, 0x00, 0x00};
	size_t fl = sniff_frame_encode(cmd, sizeof(cmd), SNIFF_FT_CMD, pl, 6);
	CHECK(fl == 13);
	struct sniff_decoder d;
	sniff_decoder_init(&d);
	uint8_t stream[64];
	size_t sl = 0;
	stream[sl++] = 0xA5;
	stream[sl++] = 0x00;
	stream[sl++] = 0xA5; /* garbage incl. partial sync */
	memcpy(stream + sl, cmd, fl);
	sl += fl;
	/* corrupted frame first */
	uint8_t bad[16];
	memcpy(bad, cmd, fl);
	bad[6] ^= 0x01;
	memcpy(stream + sl, bad, fl);
	sl += fl;
	memcpy(stream + sl, cmd, fl);
	sl += fl;
	int good = 0;
	for (size_t i = 0; i < sl; i++) {
		if (sniff_decoder_feed(&d, stream[i])) {
			good++;
			CHECK(d.type == SNIFF_FT_CMD);
			CHECK(d.len == 6);
			CHECK(memcmp(d.payload, pl, 6) == 0);
		}
	}
	CHECK(good == 2);
	CHECK(d.crc_errors == 1);

	/* Oversized LEN must be rejected without overflowing the payload buffer. */
	sniff_decoder_init(&d);
	uint8_t big[] = {0xA5, 0x5A, 0x02, 0xFF, 0xFF, 0, 0};
	for (size_t i = 0; i < sizeof(big); i++) {
		CHECK(!sniff_decoder_feed(&d, big[i]));
	}

	/* Golden vector for the Python test: PING frame and a small record. */
	uint8_t ping[8];
	size_t pl2 = sniff_frame_encode(ping, sizeof(ping), SNIFF_FT_CMD, NULL, 0);
	printf("GOLDEN_PING=");
	for (size_t i = 0; i < pl2; i++) {
		printf("%02x", ping[i]);
	}
	printf("\n");

	uint8_t gbody[5] = {0x10, 0x79, 0xF3, 0xC0, 0x71};
	struct sniff_rx_info g = {.phy_type = 0, .pdc_len = 0, .channel = 1677, .seq = 1};
	size_t gn = sniff_build_tap_record(rec, sizeof(rec), &g, gbody);
	printf("GOLDEN_REC=");
	for (size_t i = 0; i < gn; i++) {
		printf("%02x", rec[i]);
	}
	printf("\n");

	if (failures) {
		fprintf(stderr, "%d check(s) failed\n", failures);
		return 1;
	}
	printf("ALL C TESTS PASSED\n");
	return 0;
}
