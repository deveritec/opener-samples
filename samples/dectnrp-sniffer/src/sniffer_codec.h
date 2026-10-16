/*
 * Copyright (c) 2026 Deveritec GmbH
 * SPDX-License-Identifier: Apache-2.0
 *
 * Pure C (no Zephyr dependencies) encoding/decoding for the DECT NR+ sniffer:
 *  - UART frame format between target and host PC
 *  - DECT-NR-TAP record (LINKTYPE_DECT_NR_TAP = 304) built per packet
 */
#ifndef DECTNRP_SNIFFER_CODEC_H
#define DECTNRP_SNIFFER_CODEC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ---- UART frame format --------------------------------------------------
 *  SYNC0 SYNC1 | TYPE (1) | LEN (2, LE) | PAYLOAD (LEN) | CRC16 (2, LE)
 *  CRC16-CCITT (init 0xFFFF, poly 0x1021) over TYPE, LEN and PAYLOAD.
 */
#define SNIFF_SYNC0          0xA5
#define SNIFF_SYNC1          0x5A
#define SNIFF_FRAME_OVERHEAD 7
#define SNIFF_MAX_PAYLOAD    64 /* largest command payload accepted by target */

enum sniff_frame_type {
	SNIFF_FT_DATA = 0x01, /* target -> host: one DECT-NR-TAP record */
	SNIFF_FT_CMD = 0x02,  /* host -> target: command */
	SNIFF_FT_RSP = 0x03,  /* target -> host: response to a command */
};

enum sniff_cmd {
	SNIFF_CMD_PING = 0x10,       /* no payload */
	SNIFF_CMD_SET_CONFIG = 0x11, /* u16 channel, u32 network_id (LE) */
	SNIFF_CMD_START = 0x12,      /* no payload */
	SNIFF_CMD_STOP = 0x13,       /* no payload */
};

/* CMD payload: [cmd id (1)][arguments]
 * RSP payload: [cmd id (1)][status: int8, 0 = OK, otherwise negative errno]
 * DATA payload: one complete DECT-NR-TAP record (see below). */
#define SNIFF_RSP_LEN 2

/* ---- DECT-NR-TAP record (see DSRCorporation/dect-nr-tap) ----------------
 * 8-byte header, followed by 8-byte TLV entries, followed by PCC || PDC.
 */
#define SNIFF_TAP_HDR_LEN  8
#define SNIFF_TAP_TLV_LEN  8
/* Reference dissector rejects packets shorter than 8 + 8 * 8 bytes. */
#define SNIFF_TAP_MIN_TLVS 8

enum sniff_tap_tlv_type {
	SNIFF_TAP_PAD = 0, /* not defined by spec: fills up to the minimum TLV count */
	SNIFF_TAP_DATA_TYPE = 1,
	SNIFF_TAP_HEADER_STATUS = 2,
	SNIFF_TAP_PCC_RSSI2 = 3,
	SNIFF_TAP_PCC_SNR = 4,
	SNIFF_TAP_PDC_RSSI2 = 5,
	SNIFF_TAP_PDC_SNR = 6,
	SNIFF_TAP_TRANSACTION_ID = 7,
	SNIFF_TAP_CHANNEL = 8,
};

struct sniff_pcc_metrics {
	int16_t pcc_rssi2; /* Q14.1 dBm  */
	int16_t pcc_snr;   /* Q13.2 dB   */
	int16_t pdc_rssi2; /* Q14.1 dBm  */
	int16_t pdc_snr;   /* Q13.2 dB   */
};

struct sniff_rx_info {
	uint8_t phy_type; /* 0: PHF type 1 (40-bit PCC), otherwise PHF type 2 (80-bit PCC) */
	uint16_t pdc_len; /* 0 if PDC is absent (CRC error / not received) */
	uint16_t channel;
	uint16_t seq;     /* stored as transaction ID, wraps at 65536 */
	bool has_metrics; /* true if pcc/pdc metrics are valid */
	struct sniff_pcc_metrics metrics;
};

/* Maximum DECT-NR-TAP record size for a given maximum PCC+PDC size. */
#define SNIFF_TAP_MAX_RECORD(max_body)                                                             \
	(SNIFF_TAP_HDR_LEN + SNIFF_TAP_MIN_TLVS * SNIFF_TAP_TLV_LEN + (max_body))

uint16_t sniff_crc16_update(uint16_t crc, uint8_t byte);
uint16_t sniff_crc16(const uint8_t *data, size_t len);

uint8_t sniff_pcc_len(uint8_t phy_type);

/* Build a DECT-NR-TAP record. pcc_pdc must hold pcc_len + pdc_len bytes.
 * Returns the record length, or 0 if out_size is too small. */
size_t sniff_build_tap_record(uint8_t *out, size_t out_size, const struct sniff_rx_info *info,
			      const uint8_t *pcc_pdc);

/* Encode a UART frame. Returns the frame length, or 0 if out_size is too small. */
size_t sniff_frame_encode(uint8_t *out, size_t out_size, uint8_t type, const uint8_t *payload,
			  uint16_t len);

/* Byte-wise UART frame decoder for the target (commands from host). */
struct sniff_decoder {
	uint8_t state;
	uint8_t type;
	uint16_t len;
	uint16_t pos;
	uint16_t crc_rx;
	uint16_t crc;
	uint32_t crc_errors;
	uint8_t payload[SNIFF_MAX_PAYLOAD];
};

void sniff_decoder_init(struct sniff_decoder *d);

/* Feeds one byte. Returns true when a valid frame is complete; the frame is
 * then in d->type, d->len and d->payload until the next call. */
bool sniff_decoder_feed(struct sniff_decoder *d, uint8_t byte);

#endif /* DECTNRP_SNIFFER_CODEC_H */
