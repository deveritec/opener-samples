/*
 * Copyright (c) 2026 Codium Electronique
 * Copyright (c) 2026 Deveritec GmbH
 * SPDX-License-Identifier: Apache-2.0
 *
 * DECT NR+ sniffer: receives DECT NR+ packets continuously with the
 * dectnrp driver and streams them as DECT-NR-TAP records (LINKTYPE 304)
 * over UART to the host, where a Wireshark extcap turns them into live
 * captures.
 *
 * Host -> target commands: PING, SET_CONFIG (channel, network ID),
 * START, STOP. Target -> host: DATA (one record per packet) and RSP.
 */
#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/devicetree.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_l2.h>
#include <zephyr/net/net_pkt.h>
#include <zephyr/sys/byteorder.h>

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "dectnrp_driver_utils.h"
#include "dectnrp_mac_helper.h"
#include "dectnrp_operation.h"

#include "sniffer_codec.h"

LOG_MODULE_REGISTER(dectnrp_sniffer, LOG_LEVEL_INF);

#define MS_PER_FRAME 10
#define TIME_2_MODEMTICKS(TIME_MS)                                                                 \
	(DECTNRP_MODEMTICKS_PER_SYMBOL * DECTNRP_SYMBOLS_PER_FRAME * TIME_MS / MS_PER_FRAME)

#define SNIFF_MAX_RECORD     SNIFF_TAP_MAX_RECORD(CONFIG_DECTNRP_SNIFFER_MAX_BODY)
#define STATS_PERIOD_WINDOWS 5

/* Event wrapper as delivered by dectnrp_driver through dectnrp_event_fifo
 * (same layout as in the dectnrp-driver sample). */
extern struct k_fifo dectnrp_event_fifo;

struct dectnrp_event_wrapper {
	void *fifo_reserved; /* 1st word reserved for use by FIFO */
	struct dectnrp_driver_event event;
	struct net_pkt *pkt; /* PCC followed by PDC, valid for MSG_RECEIVED */
};

struct tx_item {
	uint8_t type;
	uint16_t len;
	uint8_t payload[SNIFF_MAX_RECORD];
};

struct cmd_item {
	uint8_t id;
	uint8_t len;
	uint8_t args[SNIFF_MAX_PAYLOAD];
};

static const struct device *const uart_dev = DEVICE_DT_GET(DT_CHOSEN(zephyr_console));
static struct net_if *iface;

K_MSGQ_DEFINE(tx_msgq, sizeof(struct tx_item), CONFIG_DECTNRP_SNIFFER_TX_QUEUE_DEPTH, 4);
K_MSGQ_DEFINE(cmd_msgq, sizeof(struct cmd_item), 4, 4);

/* Sniffer state, only touched by the main thread (except cmd_msgq/tx_msgq). */
static uint16_t channel = CONFIG_DECTNRP_SNIFFER_DEFAULT_CHANNEL;
static uint32_t network_id = CONFIG_DECTNRP_SNIFFER_DEFAULT_NETWORK_ID;
static bool running;
static uint16_t seq;

static uint32_t stat_records;
static uint32_t stat_rx_dropped;
static uint32_t stat_rx_errors;
static uint32_t stat_tx_dropped;
static uint32_t stat_cmd_dropped;

/* UART receive state, only used in the UART ISR. */
static struct sniff_decoder cmd_decoder;

/* ---------------------------------------------------------------------- */
/* UART transmit path: frames are queued by the RX loop and sent by a thread */

static void queue_tx(uint8_t type, const uint8_t *payload, uint16_t len, k_timeout_t timeout,
		     uint32_t *drop_counter)
{
	struct tx_item item;

	item.type = type;
	item.len = len;
	memcpy(item.payload, payload, len);
	if (k_msgq_put(&tx_msgq, &item, timeout) != 0) {
		(*drop_counter)++;
	}
}

static void tx_thread_fn(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p1);
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	static uint8_t frame[SNIFF_MAX_RECORD + SNIFF_FRAME_OVERHEAD];
	struct tx_item item;

	while (true) {
		k_msgq_get(&tx_msgq, &item, K_FOREVER);
		size_t n =
			sniff_frame_encode(frame, sizeof(frame), item.type, item.payload, item.len);

		for (size_t i = 0; i < n; i++) {
			uart_poll_out(uart_dev, frame[i]);
		}
	}
}

K_THREAD_DEFINE(tx_thread, 1536, tx_thread_fn, NULL, NULL, NULL,
		CONFIG_DECTNRP_SNIFFER_TX_THREAD_PRIO, 0, 0);

static void send_rsp(uint8_t cmd, int status)
{
	uint8_t rsp[SNIFF_RSP_LEN] = {cmd, (uint8_t)(int8_t)status};

	queue_tx(SNIFF_FT_RSP, rsp, sizeof(rsp), K_MSEC(100), &stat_tx_dropped);
}

/* ---------------------------------------------------------------------- */
/* UART receive path: interrupt driven, decodes commands from the host     */

static void uart_isr(const struct device *dev, void *user_data)
{
	ARG_UNUSED(user_data);

	uint8_t buf[32];

	while (uart_irq_update(dev) && uart_irq_is_pending(dev)) {
		if (!uart_irq_rx_ready(dev)) {
			continue;
		}

		int n = uart_fifo_read(dev, buf, sizeof(buf));

		for (int i = 0; i < n; i++) {
			if (!sniff_decoder_feed(&cmd_decoder, buf[i])) {
				continue;
			}
			if (cmd_decoder.type != SNIFF_FT_CMD || cmd_decoder.len < 1) {
				continue;
			}

			struct cmd_item item;

			item.id = cmd_decoder.payload[0];
			item.len = (uint8_t)(cmd_decoder.len - 1);
			memcpy(item.args, &cmd_decoder.payload[1], item.len);
			if (k_msgq_put(&cmd_msgq, &item, K_NO_WAIT) != 0) {
				stat_cmd_dropped++;
			}
		}
	}
}

/* ---------------------------------------------------------------------- */
/* Commands                                                                */

static void handle_cmd(const struct cmd_item *cmd)
{
	switch (cmd->id) {
	case SNIFF_CMD_PING:
		send_rsp(cmd->id, 0);
		break;

	case SNIFF_CMD_SET_CONFIG: {
		if (cmd->len != 6) {
			send_rsp(cmd->id, -EINVAL);
			break;
		}

		uint16_t new_channel = sys_get_le16(&cmd->args[0]);
		uint32_t new_network_id = sys_get_le32(&cmd->args[2]);
		int ret = 0;

		if (new_network_id != network_id) {
			ret = dectnrp_driver_set_network_id(iface, new_network_id);
			if (ret != 0) {
				LOG_ERR("dectnrp_driver_set_network_id failed, %d", ret);
				send_rsp(cmd->id, ret);
				break;
			}
			network_id = new_network_id;
		}
		/* A channel change takes effect with the next RX window. */
		channel = new_channel;
		LOG_INF("config: channel %u, network-id 0x%08x", channel, network_id);
		send_rsp(cmd->id, 0);
		break;
	}

	case SNIFF_CMD_START:
		running = true;
		LOG_INF("start");
		send_rsp(cmd->id, 0);
		break;

	case SNIFF_CMD_STOP:
		/* Commands are only handled between RX windows, so no RX
		 * operation is pending when this acknowledgement is sent. */
		running = false;
		LOG_INF("stop");
		send_rsp(cmd->id, 0);
		break;

	default:
		LOG_WRN("unknown command 0x%02x", cmd->id);
		send_rsp(cmd->id, -ENOTSUP);
		break;
	}
}

/* ---------------------------------------------------------------------- */
/* RX path                                                                 */

/* Per-packet RSSI/SNR is not part of the dectnrp driver API that this sample
 * was checked against. When dectnrp_driver_event.msg_received provides PCC/PDC
 * RSSI2 and SNR (Q14.1 dBm / Q13.2 dB), fill in m and return true. Until then
 * the RSSI/SNR entries are omitted and the record uses padding entries. */
static bool get_pcc_metrics(const struct dectnrp_driver_event *event, struct sniff_pcc_metrics *m)
{
	bool have_metrics = false;
	m->pcc_rssi2 = 0;
	m->pcc_snr = 0;
	if (event->msg_received.rssi2_valid) {
		/* Q14.1 dBm  */
		m->pdc_rssi2 = event->msg_received.rssi2;
		have_metrics = true;
	}
	if (event->msg_received.snr_valid) {
		/* Q13.2 dB   */
		m->pdc_snr = event->msg_received.snr;
		have_metrics = true;
	}
	return have_metrics;
}

static void handle_received(const struct dectnrp_event_wrapper *item)
{
	static uint8_t record[SNIFF_MAX_RECORD];
	const struct dectnrp_driver_event *event = &item->event;
	uint8_t phy_type = event->msg_received.phy_type;
	uint8_t pcc_len =
		(phy_type == 0) ? DECTNRP_PHY_HEADER_TYPE1_SIZE : DECTNRP_PHY_HEADER_TYPE2_SIZE;
	uint32_t pdc_len = event->msg_received.pdc_len;
	size_t body = (size_t)pcc_len + pdc_len;

	if ((pcc_len != sniff_pcc_len(phy_type)) || (body > CONFIG_DECTNRP_SNIFFER_MAX_BODY) ||
	    (net_pkt_get_len(item->pkt) < body)) {
		stat_rx_dropped++;
		return;
	}

	struct sniff_rx_info info = {
		.phy_type = phy_type,
		.pdc_len = (uint16_t)pdc_len,
		.channel = channel,
		.seq = seq++,
		.has_metrics = false,
		/* STF start time of the packet in modem ticks, set by the dectnrp driver. */
		.has_modem_time = true,
		.modem_time = (uint64_t)event->msg_received.start_time,
	};

	info.has_metrics = get_pcc_metrics(event, &info.metrics);

	/* We read PCC and PDC directly out of the packet, as the dectnrp sample does. */
	const uint8_t *pcc_pdc = net_pkt_data(item->pkt);
	size_t n = sniff_build_tap_record(record, sizeof(record), &info, pcc_pdc);

	if (n == 0) {
		stat_rx_dropped++;
		return;
	}
	queue_tx(SNIFF_FT_DATA, record, (uint16_t)n, K_NO_WAIT, &stat_tx_dropped);
	stat_records++;
}

/* One RX operation of CONFIG_DECTNRP_SNIFFER_WINDOW_MS on the current channel.
 * Returns when the operation has finished. */
static int rx_window(void)
{
	const uint32_t window_ms = CONFIG_DECTNRP_SNIFFER_WINDOW_MS;
	struct dectnrp_driver_op *op = NULL;
	bool finished = false;

	int ret = dectnrp_alloc_rx_operation(&op, iface, channel);

	if (ret != 0) {
		LOG_ERR("dectnrp_alloc_rx_operation failed, %d", ret);
		return ret;
	}

	op->rx.duration = TIME_2_MODEMTICKS(window_ms);

	ret = dectnrp_driver_schedule(iface, op);
	if (ret != 0) {
		LOG_ERR("dectnrp_driver_schedule(rx) failed, %d", ret);
		dectnrp_free_operation(op);
		return ret;
	}

	while (!finished) {
		uint32_t timeout = window_ms + window_ms / 2;
		struct dectnrp_event_wrapper *item =
			k_fifo_get(&dectnrp_event_fifo, K_MSEC(timeout));

		if (item == NULL) {
			LOG_ERR("rx window: event timeout");
			dectnrp_free_operation(op);
			return -ETIMEDOUT;
		}

		struct dectnrp_driver_event *event = &item->event;

		switch (event->code) {
		case DECTNRP_EVENT_MSG_RECEIVED:
			if (item->pkt != NULL) {
				handle_received(item);
				net_pkt_unref(item->pkt);
			}
			break;

		case DECTNRP_EVENT_OP_FINISHED:
			if (event->op_finished.op->status != 0) {
				stat_rx_errors++;
			}
			dectnrp_free_operation(event->op_finished.op);
			finished = true;
			break;

		case DECTNRP_EVENT_MSG_ERROR:
			stat_rx_errors++;
			break;

		default:
			LOG_WRN("unexpected event code %u", event->code);
			break;
		}
		k_free(item);
	}
	return 0;
}

static void log_stats(void)
{
	LOG_INF("records %u, rx dropped %u, rx errors %u, tx dropped %u, cmd dropped %u",
		stat_records, stat_rx_dropped, stat_rx_errors, stat_tx_dropped, stat_cmd_dropped);
}

int main(void)
{
	iface = net_if_get_first_by_type(&NET_L2_GET_NAME(DECTNRP));
	if (!iface) {
		LOG_ERR("net_if_get_first_by_type failed");
		return -ENODEV;
	}
	if (!net_if_is_up(iface)) {
		LOG_ERR("net_if_is_up failed");
		return -ENOENT;
	}
	if (!device_is_ready(uart_dev)) {
		LOG_ERR("UART device not ready");
		return -ENODEV;
	}

	k_sleep(K_MSEC(1000));

	sniff_decoder_init(&cmd_decoder);
	uart_irq_callback_user_data_set(uart_dev, uart_isr, NULL);
	uart_irq_rx_enable(uart_dev);

	int ret = dectnrp_driver_set_network_id(iface, network_id);

	if (ret != 0) {
		LOG_ERR("dectnrp_driver_set_network_id failed, %d", ret);
		return -EIO;
	}

	LOG_INF("-------------------------");
	LOG_INF("DECT NR+ sniffer");
	LOG_INF(" - network id 0x%08x", network_id);
	LOG_INF(" - channel %u", channel);
	LOG_INF(" - window %u ms", CONFIG_DECTNRP_SNIFFER_WINDOW_MS);
	LOG_INF("-------------------------");

	unsigned int windows = 0;

	while (true) {
		struct cmd_item cmd;

		if (!running) {
			/* Idle: wait for commands only. */
			if (k_msgq_get(&cmd_msgq, &cmd, K_MSEC(100)) == 0) {
				handle_cmd(&cmd);
			}
			continue;
		}

		/* Between RX windows: apply all pending commands. */
		while (k_msgq_get(&cmd_msgq, &cmd, K_NO_WAIT) == 0) {
			handle_cmd(&cmd);
		}
		if (!running) {
			continue;
		}

		ret = rx_window();
		if (ret != 0) {
			LOG_ERR("rx window failed, %d", ret);
			k_sleep(K_MSEC(10));
		}

		if (++windows % STATS_PERIOD_WINDOWS == 0) {
			log_stats();
		}
	}

	return 0;
}
