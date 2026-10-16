/*
 * Copyright (c) 2024 Deveritec GmbH.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 * @brief DECTNRP operations - operation management.
 *
 */

#include "dectnrp_operation.h"
#include <zephyr/kernel.h>
#include <zephyr/net/dectnrp_driver.h>

K_MEM_SLAB_DEFINE_STATIC(operations_slab, sizeof(struct dectnrp_driver_op), 10, 4);

/**
 * @brief Allocate a new operation and initialize basic fields common to all
 * operations.
 *
 * @param ctx
 * @return struct dectnrp_driver_op*
 */
static struct dectnrp_driver_op *alloc_operation(enum dectnrp_driver_op_type type,
						 struct net_if *iface, uint16_t channel)
{

	struct dectnrp_driver_op *op = NULL;
	int ret = k_mem_slab_alloc(&operations_slab, (void **)&op, K_MSEC(10));
	if (ret == 0) {
		memset(op, 0, sizeof(struct dectnrp_driver_op));
		op->type = type;
		op->channel = channel;
	}
	return op;
}

int dectnrp_alloc_tx_operation(struct dectnrp_driver_op **new_op, struct net_if *iface,
			       uint16_t channel, struct net_pkt *pkt)
{
	struct dectnrp_driver_op *op = alloc_operation(DECTNRP_DRIVER_OP_TX, iface, channel);
	if (op) {
		op->tx.pkt = pkt;
		*new_op = op;
		return 0;
	} else {
		return -ENOMEM;
	}
}

int dectnrp_alloc_rx_operation(struct dectnrp_driver_op **new_op, struct net_if *iface,
			       uint16_t channel)
{
	struct dectnrp_driver_op *op = alloc_operation(DECTNRP_DRIVER_OP_RX, iface, channel);
	if (op) {
		op->rx.expected_rssi = 0;
		*new_op = op;
		return 0;
	} else {
		return -ENOMEM;
	}
}

int dectnrp_alloc_rssi1_operation(struct dectnrp_driver_op **new_op, struct net_if *iface,
				  uint16_t channel, net_time_t start_time, uint32_t subslots,
				  struct dectnrp_rssi1_result *result)
{

	struct dectnrp_driver_op *op = alloc_operation(DECTNRP_DRIVER_OP_RSSI1, iface, channel);
	if (op) {
		/* RSSI1 scans are expected to start on the scheduled frame boundary. */
		op->rssi1.mode.is_scheduled = (start_time != 0);
		op->start_time = start_time;
		op->rssi1.subslots = subslots;
		op->rssi1.result = result;
		memset(result->subslot, 0, sizeof(result->subslot));
		result->channel = channel;

		*new_op = op;
		return 0;
	} else {
		return -ENOMEM;
	}
}

void dectnrp_free_operation(struct dectnrp_driver_op *op)
{
	__ASSERT(op != NULL, "op == NULL");

	if (op->type == DECTNRP_DRIVER_OP_TX) {
		net_pkt_unref(op->tx.pkt);
		op->tx.pkt = NULL;
	}
	k_mem_slab_free(&operations_slab, (void *)op);
}
