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

#ifndef DECTNRP_MAC_HELPER_H_
#define DECTNRP_MAC_HELPER_H_

#include <stddef.h>
#include <stdint.h>
#include <zephyr/net/dectnrp_driver.h>

/**
 * @brief Pointer to the sample frame.
 */
extern uint8_t *sample_frame;

/**
 * @brief Size of sample_frame.
 */
extern const size_t sample_frame_size;

/**
 * @brief PHY header type of sample_frame.
 */
extern const uint8_t sample_frame_phy_header_type;

/**
 * @brief Transport parameters of sample_frame.
 */
extern const struct dectnrp_transport_parameters sample_frame_parameters;

/**
 * @brief Encode short part of given @p network_id into given @p pcc.
 *
 * @param pcc
 * @param network_id
 */
void pcc_set_short_network_id(uint8_t *pcc, uint32_t network_id);

/**
 * @brief Encode short transmitter id from given @p short_device_id into given
 * @p pcc.
 *
 * @param pcc
 * @param short_device_id
 */
void pcc_set_transmitter_short_id(uint8_t *pcc, uint16_t short_device_id);

/**
 * @brief Encode short receiver id from given @p short_device_id into given @p
 * pcc.
 *
 * @param pcc
 * @param short_device_id
 */
void pcc_set_receiver_short_id(uint8_t *pcc, uint16_t short_device_id);

/**
 * @brief Decode short transmitter id from given \p pcc.
 *
 * @attention Provided buffer @p pcc must have at least
 * DECTNRP_PHY_HEADER_TYPE1_SIZE.
 *
 * @param pcc pointer to buffer containing PCC.
 * @param len length of given @p pcc
 * @return uint16_t transmitter id
 */
uint16_t pcc_decode_transmitter_short_id(const uint8_t *pcc, size_t len);

#endif /* DECTNRP_MAC_HELPER_H_ */
