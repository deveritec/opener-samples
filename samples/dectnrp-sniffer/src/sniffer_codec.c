/*
 * Copyright (c) 2026 Deveritec GmbH
 * SPDX-License-Identifier: Apache-2.0
 */
#include "sniffer_codec.h"

#include <string.h>

enum dec_state {
	DEC_SYNC0,
	DEC_SYNC1,
	DEC_TYPE,
	DEC_LEN0,
	DEC_LEN1,
	DEC_PAYLOAD,
	DEC_CRC0,
	DEC_CRC1,
};

static void put_le16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v & 0xFF);
	p[1] = (uint8_t)(v >> 8);
}

uint16_t sniff_crc16_update(uint16_t crc, uint8_t byte)
{
	crc ^= (uint16_t)byte << 8;
	for (int i = 0; i < 8; i++) {
		crc = (crc & 0x8000) ? (uint16_t)((crc << 1) ^ 0x1021) : (uint16_t)(crc << 1);
	}
	return crc;
}

uint16_t sniff_crc16(const uint8_t *data, size_t len)
{
	uint16_t crc = 0xFFFF;

	for (size_t i = 0; i < len; i++) {
		crc = sniff_crc16_update(crc, data[i]);
	}
	return crc;
}

uint8_t sniff_pcc_len(uint8_t phy_type)
{
	/* Same mapping as the dectnrp_driver sample: phy_type 0 -> 40-bit PCC. */
	return (phy_type == 0) ? 5 : 10;
}

/* One TLV: type (2) | length of value (2) | value (2 used, 2 zero padding).
 * The length field carries the value size, which is how the reference
 * Wireshark dissector advances through the TLV chain. */
static void put_tlv(uint8_t *p, uint16_t type, uint16_t value, uint8_t value_len)
{
	memset(p, 0, SNIFF_TAP_TLV_LEN);
	put_le16(p, type);
	put_le16(p + 2, value_len);
	if (value_len == 2) {
		put_le16(p + 4, value);
	}
}

size_t sniff_build_tap_record(uint8_t *out, size_t out_size, const struct sniff_rx_info *info,
			      const uint8_t *pcc_pdc)
{
	const uint8_t pcc_len = sniff_pcc_len(info->phy_type);
	const size_t body = (size_t)pcc_len + info->pdc_len;
	uint8_t data_type;
	uint8_t hdr_status;
	size_t tlvs;
	size_t total;
	uint8_t *p;

	if (info->pdc_len > 0) {
		data_type = (info->phy_type == 0) ? 1 : 2;
		hdr_status = 0; /* valid, PDC included */
	} else {
		data_type = (info->phy_type == 0) ? 3 : 4;
		hdr_status = 2; /* valid, PDC absent */
	}

	/* Mandatory: data type, header status, transaction ID, channel.
	 * Optional: four PCC/PDC metrics. Pad to the reference minimum. */
	tlvs = info->has_metrics ? 8 : 4;
	if (tlvs < SNIFF_TAP_MIN_TLVS) {
		tlvs = SNIFF_TAP_MIN_TLVS;
	}

	total = SNIFF_TAP_HDR_LEN + tlvs * SNIFF_TAP_TLV_LEN + body;
	if ((out_size < total) || (body > 0xFFFF) || (body > 0 && pcc_pdc == NULL)) {
		return 0;
	}

	/* Header. Byte 2..3 carries the TLV chain length in bytes, as expected by
	 * the Wireshark dissector (see README, "Known deviations"). */
	out[0] = 1; /* version */
	out[1] = 0;
	put_le16(out + 2, (uint16_t)(tlvs * SNIFF_TAP_TLV_LEN));
	put_le16(out + 4, (uint16_t)body);
	put_le16(out + 6, 0);

	p = out + SNIFF_TAP_HDR_LEN;
	put_tlv(p, SNIFF_TAP_DATA_TYPE, data_type, 2);
	p += SNIFF_TAP_TLV_LEN;
	put_tlv(p, SNIFF_TAP_HEADER_STATUS, hdr_status, 2);
	p += SNIFF_TAP_TLV_LEN;
	put_tlv(p, SNIFF_TAP_TRANSACTION_ID, info->seq, 2);
	p += SNIFF_TAP_TLV_LEN;
	put_tlv(p, SNIFF_TAP_CHANNEL, info->channel, 2);
	p += SNIFF_TAP_TLV_LEN;

	if (info->has_metrics) {
		put_tlv(p, SNIFF_TAP_PCC_RSSI2, (uint16_t)info->metrics.pcc_rssi2, 2);
		p += SNIFF_TAP_TLV_LEN;
		put_tlv(p, SNIFF_TAP_PCC_SNR, (uint16_t)info->metrics.pcc_snr, 2);
		p += SNIFF_TAP_TLV_LEN;
		put_tlv(p, SNIFF_TAP_PDC_RSSI2, (uint16_t)info->metrics.pdc_rssi2, 2);
		p += SNIFF_TAP_TLV_LEN;
		put_tlv(p, SNIFF_TAP_PDC_SNR, (uint16_t)info->metrics.pdc_snr, 2);
		p += SNIFF_TAP_TLV_LEN;
	}

	/* Padding entries (type 0, zero-length value). */
	while (p < out + SNIFF_TAP_HDR_LEN + tlvs * SNIFF_TAP_TLV_LEN) {
		put_tlv(p, SNIFF_TAP_PAD, 0, 0);
		p += SNIFF_TAP_TLV_LEN;
	}

	if (body > 0) {
		memcpy(p, pcc_pdc, body);
	}
	return total;
}

size_t sniff_frame_encode(uint8_t *out, size_t out_size, uint8_t type, const uint8_t *payload,
			  uint16_t len)
{
	size_t total = (size_t)len + SNIFF_FRAME_OVERHEAD;
	uint16_t crc;

	if ((out_size < total) || (len > 0 && payload == NULL)) {
		return 0;
	}

	out[0] = SNIFF_SYNC0;
	out[1] = SNIFF_SYNC1;
	out[2] = type;
	put_le16(out + 3, len);
	if (len > 0) {
		memcpy(out + 5, payload, len);
	}

	crc = sniff_crc16(out + 2, (size_t)len + 3);
	put_le16(out + 5 + len, crc);
	return total;
}

void sniff_decoder_init(struct sniff_decoder *d)
{
	memset(d, 0, sizeof(*d));
	d->state = DEC_SYNC0;
}

bool sniff_decoder_feed(struct sniff_decoder *d, uint8_t b)
{
	switch (d->state) {
	case DEC_SYNC0:
		if (b == SNIFF_SYNC0) {
			d->state = DEC_SYNC1;
		}
		break;

	case DEC_SYNC1:
		if (b == SNIFF_SYNC1) {
			d->state = DEC_TYPE;
		} else if (b != SNIFF_SYNC0) {
			d->state = DEC_SYNC0;
		} /* else: stay, b may be the start of a new sync */
		break;

	case DEC_TYPE:
		d->type = b;
		d->crc = sniff_crc16_update(0xFFFF, b);
		d->state = DEC_LEN0;
		break;

	case DEC_LEN0:
		d->len = b;
		d->crc = sniff_crc16_update(d->crc, b);
		d->state = DEC_LEN1;
		break;

	case DEC_LEN1:
		d->len |= (uint16_t)b << 8;
		d->crc = sniff_crc16_update(d->crc, b);
		if (d->len > SNIFF_MAX_PAYLOAD) {
			d->crc_errors++;
			d->state = DEC_SYNC0;
		} else {
			d->pos = 0;
			d->state = (d->len > 0) ? DEC_PAYLOAD : DEC_CRC0;
		}
		break;

	case DEC_PAYLOAD:
		d->payload[d->pos++] = b;
		d->crc = sniff_crc16_update(d->crc, b);
		if (d->pos == d->len) {
			d->state = DEC_CRC0;
		}
		break;

	case DEC_CRC0:
		d->crc_rx = b;
		d->state = DEC_CRC1;
		break;

	case DEC_CRC1:
		d->crc_rx |= (uint16_t)b << 8;
		d->state = DEC_SYNC0;
		if (d->crc_rx == d->crc) {
			return true;
		}
		d->crc_errors++;
		break;

	default:
		d->state = DEC_SYNC0;
		break;
	}
	return false;
}
