/*
 * Copyright (c) 2026 Deveritec GmbH
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 * @brief DECTNRP operations - interface for operation management.
 *
 */

#include <zephyr/net/dectnrp_driver.h>

/**
 * @brief Allocate a new tx operation \p op and preset its values.
 *
 * @param[out] op Return value for preseted transmit operation.
 * @param ctx Context related to interface the operation shall be executed on.
 * @param pkt
 * @return int -ENOMEM if there is no memory left to allocate memory for the new
 * op.
 * @return int 0 if no error occured.
 */
int dectnrp_alloc_tx_operation(struct dectnrp_driver_op **new_op, struct net_if *iface,
			       uint16_t channel, struct net_pkt *pkt);

/**
 * @brief Allocate a new rx operation \p op and preset its values.
 *
 * @param[out] op Return value for preseted receive operation.
 * @return int -ENOMEM if there is no memory left to allocate memory for the new
 * op.
 * @return int 0 if no error occured.
 */
int dectnrp_alloc_rx_operation(struct dectnrp_driver_op **op, struct net_if *iface,
			       uint16_t channel);

/**
 * @brief Allocate a new rssi1 operation \p op and preset its values.
 *
 * @param[out] op Return value for preseted rssi operation.
 * @param ctx Context related to interface the operation shall be executed on.
 * @param start_time Time of scan chart in modem ticks
 * @param subslots Duration of the rssi1 operation in number of subslots.
 * @param channel Channel number the scan shall observe.
 * @param result_buf pointer to rssi1 measurement buffer
 * @return int -ENOMEM if there is no memory left to allocate memory for the new
 * op.
 * @return int 0 if no error occured.
 */
int dectnrp_alloc_rssi1_operation(struct dectnrp_driver_op **new_op, struct net_if *iface,
				  uint16_t channel, net_time_t start_time, uint32_t subslots,
				  struct dectnrp_rssi1_result *result);

/**
 * @brief Free the given operation \p op.
 *
 * @param op Operation to free the memory of.
 */
void dectnrp_free_operation(struct dectnrp_driver_op *op);
