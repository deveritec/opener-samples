/*
 * Copyright (c) 2026 Deveritec GmbH
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 * @brief DECTNRP helper providing access to a simplified test message and MAC
 * operations.
 *
 */

#include "dectnrp_mac_helper.h"

/**
 * @brief Test frame with one SDU containing User Flow 1 IE (and padding).
 *
 */
static uint8_t frame[] = {
	/* PHY header */
	0x10,             /* Header format=0, packetlength-type=SLOTS, packet length=1 slot */
	0x78,             /* Short Network ID */
	0xee, 0xff,       /* Transmitter ID (short id)*/
	0x71,             /* Transmit Power=7(0dBm), DF MCS=1 */
	0xff, 0xff,       /* Receiver Id */
	0x00, 0x00, 0x00, /* Feedback Format0 - no feedback */

	/* MAC header type */
	0x00, /* Data header, without security */
	/* MAC data header */
	0x00, 0x17, /* No reset, sequence number=0x17 */

	/* MAC mux header */
	0x43, 0xd, /* Medium SDU, User Flow 1 IE, 13 bytes payload */
	/* User Flow 1 IE + user payload Hello World!\n*/
	0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21, 0x0a,

	/* MAC mux header */
	0x40, 0x11, /* Medium SDU, Padding IE, 17 bytes payload */
	/* Padding IE */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00

};

uint8_t *sample_frame = &frame[0];
const size_t sample_frame_size = sizeof(frame);
const uint8_t sample_frame_phy_header_type = 1;
const struct dectnrp_transport_parameters sample_frame_parameters = {
	.beta = 1,
	.mu = 1,
	.tbs = 37,
	.mcs = 1,
	.slots = 1,
};

void pcc_set_short_network_id(uint8_t *pcc, uint32_t network_id)
{
	pcc[1] = network_id & 0xff;
}

void pcc_set_transmitter_short_id(uint8_t *pcc, uint16_t short_device_id)
{
	UNALIGNED_PUT(sys_cpu_to_be16(short_device_id), (uint16_t *)(&pcc[2]));
}

void pcc_set_receiver_short_id(uint8_t *pcc, uint16_t short_device_id)
{
	UNALIGNED_PUT(sys_cpu_to_be16(short_device_id), (uint16_t *)(&pcc[5]));
}

uint16_t pcc_decode_transmitter_short_id(const uint8_t *pcc, size_t len)
{

	__ASSERT(len >= DECTNRP_PHY_HEADER_TYPE1_SIZE,
		 "buffer len < DECTNRP_PHY_HEADER_TYPE1_SIZE");
	uint16_t raw = *(uint16_t *)(&pcc[2]);
	return sys_be16_to_cpu(raw);
}
