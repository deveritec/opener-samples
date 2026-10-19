/*
 * Copyright (c) 2026 Codium Electronique
 * Copyright (c) 2026 Deveritec GmbH
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(dectnrp_driver_sample, CONFIG_SAMPLE_DRIVER_DECTNRP_LOG_LEVEL);

#include "dectnrp_driver_utils.h"
#include "dectnrp_mac_helper.h"
#include "dectnrp_operation.h"
#include <opener/build_info.h>
#include <zephyr/drivers/hwinfo.h>
#include <zephyr/kernel.h>
#include <zephyr/net/dectnrp_driver.h>
#include <zephyr/net/dectnrp_net_l2.h>
#include <zephyr/net/net_if.h>
#include <zephyr/random/random.h>
#include <zephyr/drivers/gpio.h>

#define MS_PER_FRAME 10
#define TIME_2_MODEMTICKS(TIME_MS)                                                                 \
	(DECTNRP_MODEMTICKS_PER_SYMBOL * DECTNRP_SYMBOLS_PER_FRAME * TIME_MS / MS_PER_FRAME)

extern struct k_fifo dectnrp_event_fifo;

static const struct gpio_dt_spec led0 = GPIO_DT_SPEC_GET(DT_ALIAS(led0), gpios);
static const struct gpio_dt_spec led1 = GPIO_DT_SPEC_GET(DT_ALIAS(led1), gpios);
static const struct gpio_dt_spec led2 = GPIO_DT_SPEC_GET(DT_ALIAS(led2), gpios);

static uint32_t network_id = CONFIG_DECTNRP_SAMPLE_NETWORK_ID;

enum state {
	DEVICE_STATE_UNSYNCHRONIZED,
	DEVICE_STATE_SYNCHRONIZING,
	DEVICE_STATE_SYNCHRONIZED,
	DEVICE_STATE_DESYNCHRONIZING,
};

static struct local_device {
	enum state state;
	uint32_t long_device_id;
	uint16_t short_device_id;
} local_device;

static struct remote_device {
	uint16_t short_device_id;
	net_time_t last_start_time;
} remote_device;

struct dectnrp_event_wrapper {
	void *fifo_reserved; /* 1st word reserved for use by FIFO */
	/** Event issued by dectnrp-driver. */
	struct dectnrp_driver_event event;
	/** Packet reference to received packet containing PCC and PDC.
	   Only used/valid if event->code == DECTNRP_EVENT_MSG_RECEIVED. */
	struct net_pkt *pkt;
};

/**
 * @brief Iterates over \p rssi1 and prints rssi1 results.
 *
 * @param result
 */
static void print_dbm(struct dectnrp_rssi1_result *result)
{
	uint8_t buffer[256];
	uint8_t *current = &buffer[0];
	size_t remaining = sizeof(buffer);

	size_t written = snprintf(current, remaining, "subslots[dBm]:[");
	if (written > 0 || (written < remaining)) {
		remaining -= written;
		current += written;
	}

	size_t size = sizeof(result->subslot);
	for (uint32_t subslot = 0; subslot < size; subslot++) {
		int16_t subslot_dbm = (int16_t)((0xff00 | result->subslot[subslot]));
		char comma = (subslot < size - 1) ? ',' : ' ';

		written = snprintf(current, remaining, "%d%c", subslot_dbm, comma);
		if (written > 0 || (written < remaining)) {
			remaining -= written;
			current += written;
		}
		if (remaining < 2) {
			break;
		}
	}

	remaining -= snprintf(current, remaining, "]");
	if (written > 0 || (written < remaining)) {
		remaining -= written;
		current += written;
	}

	LOG_INF("RSSI1 scan on carrier:%u", result->channel);
	LOG_INF("%s", buffer);
}

/**
 * @brief Does a blocking RSSI1 operation.
 *
 *  * Allocates and creates a rx-operation
 *  * Schedules it imediately via dectnrp_driver
 *  * Wait for the results and print them
 *
 * @param iface
 * @param duration_ms Length of the rssi1 operation in frames.
 */
static void rssi1_scan(struct net_if *iface, uint8_t frames)
{

	__ASSERT(iface != NULL, "iface == NULL");

	struct dectnrp_rssi1_result result;
	struct dectnrp_driver_op *op = NULL;
	const uint32_t subslots = frames * DECTNRP_SUBSLOTS_PER_FRAME;
	int ret = dectnrp_alloc_rssi1_operation(&op, iface, CONFIG_DECTNRP_SAMPLE_CHANNEL, 0,
						subslots, &result);
	if (ret != 0) {
		LOG_ERR("dectnrp_alloc_rssi1_operation failed, %d", ret);
	} else {

		ret = dectnrp_driver_schedule(iface, op);
		if (ret != 0) {
			LOG_ERR("dectnrp_driver_schedule(rssi1) failed, %d", ret);
			dectnrp_free_operation(op);
		} else {
			bool rssi1_finished = false;
			while (!rssi1_finished && (ret == 0)) {

				uint32_t timeout = 5 * (MS_PER_FRAME * frames);
				struct dectnrp_event_wrapper *item =
					k_fifo_get(&dectnrp_event_fifo, K_MSEC(timeout));

				struct dectnrp_driver_event *event = &item->event;

				if (event->code == DECTNRP_EVENT_OP_FINISHED) {
					__ASSERT(event->op_finished.op != NULL,
						 "event->op_finished.op == NULL");
					__ASSERT(op == event->op_finished.op,
						 "op != event->op_finished.op");
					__ASSERT(op->rssi1.result != NULL,
						 "op->rssi1.result == NULL");

					if (event->op_finished.op->status == 0) {
						print_dbm(op->rssi1.result);
					} else {
						LOG_ERR("RSSI1-scan failed,%d",
							event->op_finished.op->status);
					}

					dectnrp_free_operation(event->op_finished.op);
					rssi1_finished = true;
				} else {
					LOG_ERR("event->code=%u", event->code);
				}

				k_free(item);
			}
		}
	}
}

/**
 * @brief Allocates and creates a rx-operation and schedules it imediately via
 * dectnrp_driver.
 *
 * @param iface
 * @param duration_ms Length of the rx operation in modem ticks.
 * @return int
 */
static int receive(struct net_if *iface, uint32_t duration_ms, bool *received)
{

	__ASSERT(iface != NULL, "iface == NULL");
	__ASSERT(received != NULL, "received == NULL");

	*received = false;
	struct dectnrp_driver_op *op = NULL;
	int ret = dectnrp_alloc_rx_operation(&op, iface, CONFIG_DECTNRP_SAMPLE_CHANNEL);
	if (ret != 0) {
		LOG_ERR("dectnrp_alloc_rx_operation failed, %d", ret);
	} else {

		op->rx.duration = TIME_2_MODEMTICKS(duration_ms);

		LOG_INF("receive ...");

		ret = dectnrp_driver_schedule(iface, op);
		if (ret != 0) {
			LOG_ERR("dectnrp_driver_schedule(rx) failed, %d", ret);
			dectnrp_free_operation(op);
		} else {
			bool rx_finished = false;
			bool rx = false;
			while (!rx_finished && (ret == 0)) {

				uint32_t timeout = duration_ms + duration_ms / 2;
				struct dectnrp_event_wrapper *item =
					k_fifo_get(&dectnrp_event_fifo, K_MSEC(timeout));
				if (item == NULL) {
					LOG_ERR("receive event(s) missing");
					dectnrp_free_operation(op);
					op = NULL;
					ret = -EIO;
				} else {

					struct dectnrp_driver_event *event = &item->event;

					if (event->code == DECTNRP_EVENT_MSG_RECEIVED) {

						__ASSERT(item->pkt != NULL, "item->pkt == NULL");

						uint8_t pcc_len =
							event->msg_received.phy_type == 0
								? DECTNRP_PHY_HEADER_TYPE1_SIZE
								: DECTNRP_PHY_HEADER_TYPE2_SIZE;
						uint32_t pdc_len = event->msg_received.pdc_len;

						/* We just use a simple short cut and read pcc and
						 * pdc directly out of the packet. */
						uint8_t *pcc = net_pkt_data(item->pkt);
						uint8_t *pdc = &pcc[pcc_len];
						remote_device.short_device_id =
							pcc_decode_transmitter_short_id(pcc,
											pcc_len);
						remote_device.last_start_time =
							event->msg_received.start_time;
						rx = true;

						// LOG_INF("RX:");
						LOG_HEXDUMP_INF(pcc, pcc_len, "RX:PCC:");
						LOG_HEXDUMP_INF(pdc, pdc_len, "PDC:");

						net_pkt_unref(item->pkt);

					} else if (event->code == DECTNRP_EVENT_OP_FINISHED) {
						__ASSERT(event->op_finished.op != NULL,
							 "event->op_finished.op == NULL");
						__ASSERT(op == event->op_finished.op,
							 "op != event->op_finished.op");
						dectnrp_free_operation(event->op_finished.op);
						LOG_INF("receive complete");
						rx_finished = true;
						*received = rx;

					} else if (event->code == DECTNRP_EVENT_MSG_ERROR) {
						LOG_ERR("MSG_ERROR:0x%x",
							event->message_error.status);
					} else {
						LOG_ERR("event->code=%u", event->code);
					}

					k_free(item);
				}
			}
		}
	}

	return ret;
}

/**
 * @brief Allocates and creates a net_pkt from given data and its parameters and
 * transmits it via dectnrp_driver.
 *
 * @param iface
 * @param data
 * @param size
 * @param parameters
 * @return int
 */
static int transmit(struct net_if *iface, const uint8_t *data, size_t size, uint8_t phy_header_type,
		    const struct dectnrp_transport_parameters *parameters, net_time_t start_time)
{

	__ASSERT(iface != NULL, "iface == NULL");
	__ASSERT(data != NULL, "data == NULL");
	__ASSERT(parameters != NULL, "parameters == NULL");
	int ret = 0;

	struct net_pkt *pkt =
		net_pkt_alloc_with_buffer(iface, DECTNRP_MTU, AF_PACKET, IPPROTO_RAW, K_MSEC(50));
	if (!pkt) {
		LOG_ERR("Could not allocate pkt");
		ret = -ENOMEM;
	} else {

		struct dectnrp_driver_op *op = NULL;
		int ret =
			dectnrp_alloc_tx_operation(&op, iface, CONFIG_DECTNRP_SAMPLE_CHANNEL, pkt);
		if (ret != 0) {
			LOG_ERR("dectnrp_alloc_tx_operation failed, %d", ret);
			net_pkt_unref(pkt);
		} else {

			struct net_buf *frame_buf = pkt->frags;
			net_buf_add_mem(frame_buf, data, size);

			op->tx.transport_parameters = *parameters;
			op->tx.phy_header_type = phy_header_type;
			op->start_time = start_time;

			LOG_INF("transmit");

			ret = dectnrp_driver_schedule(iface, op);
			if (ret != 0) {
				LOG_ERR("dectnrp_driver_schedule(tx) failed, %d", ret);
			} else {
				/* Block unitil tx operation has been completed. */
				struct dectnrp_event_wrapper *item =
					k_fifo_get(&dectnrp_event_fifo, K_MSEC(10));
				if (item == NULL) {
					LOG_ERR("transmit complete event missing");
					dectnrp_free_operation(op);
					op = NULL;
					ret = -EIO;
				} else {
					struct dectnrp_driver_event *event = &item->event;
					__ASSERT(event->code == DECTNRP_EVENT_OP_FINISHED,
						 "unexpected event");
					__ASSERT(event->op_finished.op == op,
						 "event->op_finished.op != op");
					LOG_INF("transmit complete");

					k_free(item);
				}
			}
			dectnrp_free_operation(op);
		}
	}
	return ret;
}

int main()
{
	LOG_DBG("Opener version %d.%d.%d-%s%c", OPENER_VERSION_MAJOR, OPENER_VERSION_MINOR,
		OPENER_PATCHLEVEL, STRINGIFY(OPENER_GIT_COMMIT), OPENER_DIRTY ? '+' : '=');

	LOG_DBG("Opener dectnrp driver sample started");

	/* LEDs config */
	gpio_pin_configure_dt(&led0, GPIO_OUTPUT_INACTIVE);
	gpio_pin_configure_dt(&led1, GPIO_OUTPUT_INACTIVE);
	gpio_pin_configure_dt(&led2, GPIO_OUTPUT_INACTIVE);

	/* Get the DECT network interface */
	struct net_if *iface = net_if_get_first_by_type(&NET_L2_GET_NAME(DECTNRP));
	if (!iface) {
		LOG_ERR("net_if_get_first_by_type failed");
		return -ENODEV;
	} else if (!net_if_is_up(iface)) {
		LOG_ERR("net_if_is_up failed");
		return -ENOENT;

	} else {

		k_sleep(K_MSEC(1000));

		/* Assign our network id to the dectnrp_driver. */
		int ret = dectnrp_driver_set_network_id(iface, network_id);
		if (ret != 0) {
			LOG_ERR("dectnrp_driver_set_network_id failed, %d", ret);
			return -EIO;
		}

		/* Assign local long device id from hardware/chip id. */
		local_device.long_device_id = 0;
		size_t status = hwinfo_get_device_id((uint8_t *)&local_device.long_device_id,
						     sizeof(local_device.long_device_id));
		if (status != sizeof(local_device.long_device_id)) {
			LOG_ERR("hwinfo_get_device_id failed,%u", ret);
			/* If long id is not assigned from chip we fall back to default long id.
			 */
			local_device.long_device_id = CONFIG_DECTNRP_SAMPLE_LONG_DEVICE_ID;
		}
		/* Assign random short device id. */
		local_device.short_device_id = sys_rand32_get();
		local_device.state = DEVICE_STATE_UNSYNCHRONIZED;
		/* Remote peer not known yet.*/
		remote_device.short_device_id = DECTNRP_SHORT_BROADCAST_ADDRESS;

		LOG_INF("-------------------------");
		LOG_INF("Local device:");
		LOG_INF(" DEVICE_STATE_UNSYNCHRONIZED");
		LOG_INF(" - network id 0x%x", network_id);
		LOG_INF(" - long device id 0x%x", local_device.long_device_id);
		LOG_INF(" - short device id 0x%x", local_device.short_device_id);
		LOG_INF(" - channel %u", CONFIG_DECTNRP_SAMPLE_CHANNEL);
		LOG_INF("-------------------------");

		gpio_pin_set_dt(&led0, 1);

		/* In unsynchronized mode we start with the full period. */
		uint32_t period = CONFIG_DECTNRP_SAMPLE_PERIOD;
		/* In unsynchronized mode we start with imediate messages the full period.
		 */
		net_time_t tx_start_time = 0;

		/* Read current network/modem-time from driver. */
		net_time_t net_time = 0;
		ret = dectnrp_driver_get_time(iface, &net_time);
		if (ret != 0) {
			LOG_ERR("Error while reading network time from driver,%d", ret);
		} else {
			LOG_INF("Network time=%" PRIu64 "", net_time);
		}

		/* Do a RSSI1 scan for a full frame. */
		const uint8_t frames = 1;
		rssi1_scan(iface, frames);

		/* Do periodically receive and send sample_frame via dectnrp_driver. */
		do {
			bool received = false;
			ret = receive(iface, period, &received);
			if (ret != 0) {
				LOG_ERR("receive failed, %d", ret);
				if (local_device.state != DEVICE_STATE_UNSYNCHRONIZED) {
					local_device.state = DEVICE_STATE_DESYNCHRONIZING;
				}
				/* If receive failed we idle for a full period. */
				k_sleep(K_MSEC(period));
			} else if (received) {
				if (local_device.state != DEVICE_STATE_SYNCHRONIZED) {
					local_device.state = DEVICE_STATE_SYNCHRONIZING;
				}
				k_sleep(K_MSEC(period / 2));
			} else if (!received) {
				if (local_device.state != DEVICE_STATE_UNSYNCHRONIZED) {
					local_device.state = DEVICE_STATE_DESYNCHRONIZING;
				}
			}

			switch (local_device.state) {
			case DEVICE_STATE_SYNCHRONIZING:
				/* We have received a packet.
				   Now we know our remote peer and its timing to which we can
				   synchronize. */
				local_device.state = DEVICE_STATE_SYNCHRONIZED;
				gpio_pin_set_dt(&led1, 1);

				LOG_INF("-------------------------");
				LOG_INF("Local device:");
				LOG_INF(" DEVICE_STATE_SYNCHRONIZED");
				LOG_INF("Remote device:");
				LOG_INF(" - short device id 0x%x", remote_device.short_device_id);
				LOG_INF("-------------------------");

				__attribute__((fallthrough));
			case DEVICE_STATE_SYNCHRONIZED:
				/* Update the time of our next packet to be sent.
				   In synchornized mode we have a dedicated start time when to send.
				 */
				tx_start_time = remote_device.last_start_time +
						TIME_2_MODEMTICKS(period / 2);
				break;
			case DEVICE_STATE_DESYNCHRONIZING:
				/* We have not received a packet (or reception failed).
				   We go back to unsynchronized mode.
				   Remote peer not known anymore.*/
				remote_device.short_device_id = DECTNRP_SHORT_BROADCAST_ADDRESS;
				local_device.state = DEVICE_STATE_UNSYNCHRONIZED;
				gpio_pin_set_dt(&led1, 0);

				LOG_INF("DEVICE_STATE_UNSYNCHRONIZED");

				__attribute__((fallthrough));
			case DEVICE_STATE_UNSYNCHRONIZED:
				/* In unsynchronized mode we send imediately. */
				tx_start_time = 0;
				break;
			}

			/* Update tx packet. */
			uint8_t *pcc = &sample_frame[0];
			pcc_set_short_network_id(pcc, network_id);
			pcc_set_transmitter_short_id(pcc, local_device.short_device_id);
			pcc_set_receiver_short_id(pcc, remote_device.short_device_id);

			ret = transmit(iface, &sample_frame[0], sample_frame_size,
				       sample_frame_phy_header_type, &sample_frame_parameters,
				       tx_start_time);
			if (ret != 0) {
				LOG_ERR("transmit failed, %d", ret);
			}

		} while (true);
	}

	return 0;
}
