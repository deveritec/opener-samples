/*
 * Copyright (c) 2026 Deveritec GmbH
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 * @brief dectnrp low level driver helper utilities
 *
 * @note References are to the ETSI TS 103 636 DECTNRP NR+ V2.2.1 (2026-05)
 * standard If not further noted all references in this file refer to ETSI TS
 * 103 636-4.
 */

#ifndef __DECTNRP_DRIVER_UTILS_H__
#define __DECTNRP_DRIVER_UTILS_H__

#include <zephyr/net/dectnrp_driver.h>

/**
 * @brief Read hardware capabilities from dectnrp_driver related to given @p
 * iface.
 *
 * @param iface
 * @return enum dectnrp_hw_caps
 */
static inline int dectnrp_driver_get_hw_capabilities(struct net_if *iface)
{
	const struct dectnrp_driver_api *driver = net_if_get_device(iface)->api;
	if (!driver) {
		return 0;
	} else if (driver->get_hw_capabilities == NULL) {
		return 0;
	} else {
		return driver->get_hw_capabilities(net_if_get_device(iface));
	}
}

/**
 * @brief Read capabilities from dectnrp_driver related to given @p iface.
 *
 * @param iface
 * @param[out] caps
 * @return int
 * @retval 0 success
 * @retval -ENOENT driver interface not ready
 * @retval -ENOTSUP function not supported by driver
 */
static inline int dectnrp_driver_get_capabilities(struct net_if *iface,
						  struct dectnrp_device_capabilities *caps)
{
	const struct dectnrp_driver_api *driver = net_if_get_device(iface)->api;
	if (!driver) {
		return -ENOENT;
	} else if (driver->get_capabilities == NULL) {
		return -ENOTSUP;
	} else {
		return driver->get_capabilities(net_if_get_device(iface), caps);
		return 0;
	}
}

/**
 * @brief Set the network id @p network_id used by the dectnrp_driver related to
 * given @p iface.
 *
 * @param iface
 * @param network_id Network id set for descrambling/scrambling of packets.
 * @return int
 * @retval 0 success
 * @retval -ENOENT driver interface not ready
 * @retval -ENOTSUP function not supported by driver
 */
static inline int dectnrp_driver_set_network_id(struct net_if *iface, uint32_t network_id)
{

	const struct dectnrp_driver_api *driver = net_if_get_device(iface)->api;
	if (!driver) {
		return -ENOENT;
	} else if (driver->configure == NULL) {
		return -ENOTSUP;
	} else {
		return driver->configure(net_if_get_device(iface), DECTNRP_CONFIG_TYPE_NETWORK_ID,
					 &(const struct dectnrp_config){.network_id = network_id});
	}
}

/**
 * @brief Get current modem time stamp from dectnrp_driver
 * related to given @p iface.
 *
 * @attention The returned @p time may a several ticks in the past!
 *
 * @param iface
 * @param time
 * @return int
 * @retval 0 success
 * @retval -ENOENT driver interface not ready
 * @retval -ENOTSUP function not supported by driver
 */
static inline int dectnrp_driver_get_time(struct net_if *iface, net_time_t *time)
{
	const struct dectnrp_driver_api *driver = net_if_get_device(iface)->api;

	if (!driver) {
		return -ENOENT;
	} else if (driver->get_time == NULL) {
		return -ENOTSUP;
	} else {
		return driver->get_time(net_if_get_device(iface), time);
	}
}

/**
 * @brief Schedule given driver operation @p op at the dectnrp_driver
 * related to given @p iface.
 *
 * @param iface
 * @param op
 * @return int
 * @retval 0 success
 * @retval -ENOENT driver interface not ready
 * @retval -ENOTSUP function not supported by driver
 */
static inline int dectnrp_driver_schedule(struct net_if *iface, struct dectnrp_driver_op *op)
{
	const struct dectnrp_driver_api *driver = net_if_get_device(iface)->api;

	if (!driver) {
		return -ENOENT;
	} else if (driver->schedule == NULL) {
		return -ENOTSUP;
	} else {
		return driver->schedule(net_if_get_device(iface), op);
	}
}

/**
 * @brief Registers the given @p event_handler with the dectnrp_driver
 * related to given @p iface.
 *
 * @param iface
 * @param event_handler
 * @return int
 * @retval 0 success
 * @retval -ENOENT driver interface not ready
 * @retval -ENOTSUP function not supported by driver
 */
static inline int dectnrp_driver_register_event_handler(struct net_if *iface,
							dectnrp_driver_event_cb_t event_handler)
{
	const struct dectnrp_driver_api *driver = net_if_get_device(iface)->api;

	if (!driver) {
		return -ENOENT;
	} else if (driver->configure == NULL) {
		return -ENOTSUP;
	} else {
		const struct dectnrp_config config = {.event_handler = event_handler};
		return driver->configure(net_if_get_device(iface),
					 DECTNRP_CONFIG_TYPE_EVENT_HANDLER, &config);
	}
}

/**
 * @brief Start the dectnrp_driver related to given @p iface.
 *
 * @param iface
 * @return int
 * @retval 0 success
 * @retval -ENOENT driver interface not ready
 * @retval -ENOTSUP function not supported by driver
 */
static inline int dectnrp_driver_start(struct net_if *iface)
{
	const struct dectnrp_driver_api *driver = net_if_get_device(iface)->api;

	if (!driver) {
		return -ENOENT;
	} else if (driver->start == NULL) {
		return -ENOTSUP;
	} else {
		return driver->start(net_if_get_device(iface));
	}
}

/**
 * @brief Stop the dectnrp_driver related to given @p iface.
 *
 * @param iface
 * @return int
 * @retval 0 success
 * @retval -ENOENT driver interface not ready
 * @retval -ENOTSUP function not supported by driver
 */
static inline int dectnrp_driver_stop(struct net_if *iface)
{
	const struct dectnrp_driver_api *driver = net_if_get_device(iface)->api;

	if (!driver) {
		return -ENOENT;
	} else if (driver->stop == NULL) {
		return -ENOTSUP;
	} else {
		return driver->stop(net_if_get_device(iface));
	}
}

/**
 * @brief Activate/deactivate rx-filtering messages at the dectnrp_driver on
 * given @p iface for given receiver @p short_addr.
 *
 * @attention This only applies to packages of PHY TYPE 2! Packages are filtered
 * by the receiver identity encoded in the PHY TYPE 2 header. PHY TYPE 1
 * packages have not short address attached and are not be filtered!
 *
 * @param iface
 * @param short_addr Short receiver address used for filtering. If zero the
 * filter is switched off.
 * @return int
 * @retval 0 success
 * @retval -ENOENT driver interface not ready
 * @retval -ENOTSUP function not supported by driver
 */
static inline int dectnrp_driver_filter_short_receiver_addr(struct net_if *iface,
							    uint16_t short_addr)
{
	const struct dectnrp_driver_api *driver = net_if_get_device(iface)->api;

	if (!driver) {
		return -ENOENT;
	} else if (driver->get_hw_capabilities == NULL || driver->configure == NULL) {
		return -ENOTSUP;
	} else if (driver->get_hw_capabilities(net_if_get_device(iface)) & DECTNRP_HW_FILTER) {

		const struct dectnrp_config config = {
			.filter_short_receiver_addr = {.activate = short_addr != 0x0,
						       .value = short_addr}};
		return driver->configure(net_if_get_device(iface),
					 DECTNRP_CONFIG_TYPE_FILTER_SHORT_RECEIVER_ADDR, &config);
	} else {
		return -ENOTSUP;
	}
}

/**
 * @brief Activate/deactivate rx-filtering messages at the dectnrp_driver on
 * given @p iface for given @p short_network_id.
 *
 * @param iface
 * @param short_network_id Short network id used for filtering. If zero the
 * filter is switched off.
 * @return int
 * @retval 0 success
 * @retval -ENOENT driver interface not ready
 * @retval -ENOTSUP function not supported by driver
 */
static inline int dectnrp_driver_filter_short_network_id(struct net_if *iface,
							 uint8_t short_network_id)
{
	const struct dectnrp_driver_api *driver = net_if_get_device(iface)->api;

	if (!driver) {
		return -ENOENT;
	} else if (driver->get_hw_capabilities == NULL || driver->configure == NULL) {
		return -ENOTSUP;
	} else if (driver->get_hw_capabilities(net_if_get_device(iface)) & DECTNRP_HW_FILTER) {

		const struct dectnrp_config config = {
			.filter_short_network_id = {.activate = short_network_id != 0x0,
						    .value = short_network_id}};
		return driver->configure(net_if_get_device(iface),
					 DECTNRP_CONFIG_TYPE_FILTER_SHORT_NETWORK_ID, &config);
	} else {
		return -ENOTSUP;
	}
}

#endif /* __DECTNRP_DRIVER_UTILS_H__ */
