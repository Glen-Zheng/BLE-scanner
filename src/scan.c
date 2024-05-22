/*
 * Copyright (c) 2018 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <zephyr/kernel.h>
#include <zephyr/sys/byteorder.h>
#include <string.h>
#include <bluetooth/scan.h>

#include <zephyr/logging/log.h>
#include <stdlib.h>
#include <stdint.h>
LOG_MODULE_REGISTER(nrf_bt_scan, CONFIG_BT_SCAN_LOG_LEVEL);

#define BT_SCAN_UUID_128_SIZE 16

#define MODE_CHECK                                                                                 \
	(BT_SCAN_NAME_FILTER | BT_SCAN_ADDR_FILTER | BT_SCAN_SHORT_NAME_FILTER |                   \
	 BT_SCAN_APPEARANCE_FILTER | BT_SCAN_UUID_FILTER | BT_SCAN_MANUFACTURER_DATA_FILTER)

/* Scan filter mutex. */
K_MUTEX_DEFINE(scan_mutex);

/* Scanning control structure used to
 * compare matching filters, their mode and event generation.
 */
struct bt_scan_control {
	/* Number of active filters. */
	uint8_t filter_cnt;

	/* Number of matched filters. */
	uint8_t filter_match_cnt;

	/* Indicates whether at least one filter has been fitted. */
	bool filter_match;

	/* Indicates in which mode filters operate. */
	bool all_mode;

	/* Inform that device is connectable. */
	bool connectable;

	/* Data needed to establish connection and advertising information. */
	struct bt_scan_device_info device_info;

	/* Scan filter status. */
	struct bt_scan_filter_match filter_status;
};

/* Name filter structure.
 */
struct bt_scan_name_filter {
	/* Names that the main application will scan for,
	 * and that will be advertised by the peripherals.
	 */
	char target_name[CONFIG_BT_SCAN_NAME_CNT][CONFIG_BT_SCAN_NAME_MAX_LEN];

	/* Name filter counter. */
	uint8_t cnt;

	/* Flag to inform about enabling or disabling this filter.
	 */
	bool enabled;
};

/* Short names filter structure.
 */
struct bt_scan_short_name_filter {
	struct {
		/* Short names that the main application will scan for,
		 * and that will be advertised by the peripherals.
		 */
		char target_name[CONFIG_BT_SCAN_SHORT_NAME_MAX_LEN];

		/* Minimum length of the short name. */
		uint8_t min_len;
	} name[CONFIG_BT_SCAN_SHORT_NAME_CNT];

	/* Short name filter counter. */
	uint8_t cnt;

	/* Flag to inform about enabling or disabling this filter. */
	bool enabled;
};

/* BLE Addresses filter structure.
 */
struct bt_scan_addr_filter {
	/* Addresses advertised by the peripherals. */
	bt_addr_le_t target_addr[CONFIG_BT_SCAN_ADDRESS_CNT];

	/* Address filter counter. */
	uint8_t cnt;

	/* Flag to inform about enabling or disabling this filter. */
	bool enabled;
};

/* Structure for storing different types of UUIDs */
struct bt_scan_uuid {
	/* Pointer to the appropriate type of UUID. **/
	struct bt_uuid *uuid;
	union {
		/* 16-bit UUID. */
		struct bt_uuid_16 uuid_16;

		/* 32-bit UUID. */
		struct bt_uuid_32 uuid_32;

		/* 128-bit UUID. */
		struct bt_uuid_128 uuid_128;
	} uuid_data;
};

/* UUIDs filter structure.
 */
struct bt_scan_uuid_filter {
	/* UUIDs that the main application will scan for,
	 * and that will be advertised by the peripherals.
	 */
	struct bt_scan_uuid uuid[CONFIG_BT_SCAN_UUID_CNT];

	/* UUID filter counter. */
	uint8_t cnt;

	/* Flag to inform about enabling or disabling this filter. */
	bool enabled;
};

struct bt_scan_appearance_filter {
	/* Apperances that the main application will scan for,
	 * and that will be advertised by the peripherals.
	 */
	uint16_t appearance[CONFIG_BT_SCAN_APPEARANCE_CNT];

	/* Appearance filter counter. */
	uint8_t cnt;

	/* Flag to inform about enabling or disabling this filter. */
	bool enabled;
};

/* Manufacturer data filter structure.
 */
struct bt_scan_manufacturer_data_filter {
	struct {
		/* Manufacturer data that the main application will scan for,
		 * and that will be advertised by the peripherals.
		 */
		uint8_t data[CONFIG_BT_SCAN_MANUFACTURER_DATA_MAX_LEN];

		/* Length of the manufacturere data that the main application
		 * will scan for.
		 */
		uint8_t data_len;
	} manufacturer_data[CONFIG_BT_SCAN_MANUFACTURER_DATA_CNT];

	/* Name filter counter. */
	uint8_t cnt;

	/* Flag to inform about enabling or disabling this filter. */
	bool enabled;
};

/* Filters data.
 * This structure contains all filter data and the information
 * about enabling and disabling any type of filters.
 * Flag all_filter_mode informs about the filter mode.
 * If this flag is set, then all types of enabled filters
 * must be matched for the module to send a notification to
 * the main application. Otherwise, it is enough to
 * match one of filters to send notification.
 */
struct bt_scan_filters {
	/* Name filter data. */
	struct bt_scan_name_filter name;

	/* Short name filter data. */
	struct bt_scan_short_name_filter short_name;

	/* Address filter data. */
	struct bt_scan_addr_filter addr;

	/* UUID filter data. */
	struct bt_scan_uuid_filter uuid;

	/* Appearance filter data. */
	struct bt_scan_appearance_filter appearance;

	/* Manufacturer data filter data. */
	struct bt_scan_manufacturer_data_filter manufacturer_data;

	/* Filter mode. If true, all set filters must be
	 * matched to generate an event.
	 */
	bool all_mode;
};

#if CONFIG_BT_SCAN_CONN_ATTEMPTS_FILTER
/* Connection attempts filter device */
struct conn_attempts_device {
	/* Filtered device address. */
	bt_addr_le_t addr;

	/* Number of the connection attempts. */
	size_t attempts;
};

/* Connection attempts filter. */
struct conn_attempts_filter {
	/* Array of the filtered devices. */
	struct conn_attempts_device device[CONFIG_BT_SCAN_CONN_ATTEMPTS_FILTER_LEN];

	/* The oldest device index. */
	uint32_t oldest_idx;

	/* Count of the filtered devices. */
	size_t count;
};
#endif /* CONFIG_BT_SCAN_CONN_ATTEMPTS_FILTER */

#if CONFIG_BT_SCAN_BLOCKLIST
/* Connection blocklist */
struct conn_blocklist {
	/* Array of the blocklist devices. */
	bt_addr_le_t addr[CONFIG_BT_SCAN_BLOCKLIST_LEN];

	/* Blocklist device count. */
	uint32_t count;
};
#endif /* CONFIG_BT_SCAN_BLOCKLIST */

/* Scanning module instance. Options for the different scanning modes.
 * This structure stores all module settings. It is used to enable
 * or disable scanning modes and to configure filters.
 */
static struct bt_scan {
	/* Filter data. */
	struct bt_scan_filters scan_filters;

#if CONFIG_BT_CENTRAL
	/* If set to true, the module automatically connects
	 * after a filter match.
	 */
	bool connect_if_match;
#endif /* CONFIG_BT_CENTRAL */

	/* Scan parameters required to initialize the module.
	 * Can be initialized as NULL. If NULL, the parameters required to
	 * initialize the module are loaded from the static configuration.
	 */
	struct bt_le_scan_param scan_param;

	/* Connection parameters. Can be initialized as NULL.
	 * If NULL, the default static configuration is used.
	 */
	struct bt_le_conn_param conn_param;

#if CONFIG_BT_SCAN_CONN_ATTEMPTS_FILTER
	/* Scan Connection attempts filter. */
	struct conn_attempts_filter attempts_filter;
#endif /* CONFIG_BT_SCAN_CONN_ATTEMPTS_FILTER */

#if CONFIG_BT_SCAN_BLOCKLIST
	/* Scan device blocklist. */
	struct conn_blocklist blocklist;
#endif /* CONFIG_BT_SCAN_BLOCKLIST */

} bt_scan;

static sys_slist_t callback_list;

void bt_scan_cb_register(struct bt_scan_cb *cb)
{
	if (!cb) {
		return;
	}

	sys_slist_append(&callback_list, &cb->node);
}

static void notify_filter_matched(struct bt_scan_device_info *device_info,
				  struct bt_scan_filter_match *filter_match, bool connectable)
{
	struct bt_scan_cb *cb;

	SYS_SLIST_FOR_EACH_CONTAINER(&callback_list, cb, node) {
		if (cb->cb_addr->filter_match) {
			cb->cb_addr->filter_match(device_info, filter_match, connectable);
		}
	}
}

static void notify_filter_no_match(struct bt_scan_device_info *device_info, bool connectable)
{
	struct bt_scan_cb *cb;

	SYS_SLIST_FOR_EACH_CONTAINER(&callback_list, cb, node) {
		if (cb->cb_addr->filter_no_match) {
			cb->cb_addr->filter_no_match(device_info, connectable);
		}
	}
}

#if CONFIG_BT_CENTRAL
static void notify_connecting(struct bt_scan_device_info *device_info, struct bt_conn *conn)
{
	struct bt_scan_cb *cb;

	SYS_SLIST_FOR_EACH_CONTAINER(&callback_list, cb, node) {
		if (cb->cb_addr->connecting) {
			cb->cb_addr->connecting(device_info, conn);
		}
	}
}

static void notify_connecting_error(struct bt_scan_device_info *device_info)
{
	struct bt_scan_cb *cb;

	SYS_SLIST_FOR_EACH_CONTAINER(&callback_list, cb, node) {
		if (cb->cb_addr->connecting_error) {
			cb->cb_addr->connecting_error(device_info);
		}
	}
}
#endif /* CONFIG_BT_CENTRAL */

#if CONFIG_BT_SCAN_BLOCKLIST
static bool blocklist_device_check(const bt_addr_le_t *addr)
{
	bool blocklist_device = false;

	k_mutex_lock(&scan_mutex, K_FOREVER);

	for (size_t i = 0; i < bt_scan.blocklist.count; i++) {
		if (bt_addr_le_cmp(&bt_scan.blocklist.addr[i], addr) == 0) {
			blocklist_device = true;

			break;
		}
	}

	k_mutex_unlock(&scan_mutex);

	return blocklist_device;
}
#endif /* CONFIG_BT_SCAN_BLOCKLIST */

#if CONFIG_BT_SCAN_CONN_ATTEMPTS_FILTER
static void attempts_filter_force_add(struct conn_attempts_filter *filter, const bt_addr_le_t *addr)
{
	/* Overwrite the oldest device */
	filter->device[filter->oldest_idx].attempts = 0;
	bt_addr_le_copy(&filter->device[filter->oldest_idx].addr, addr);

	if (filter->oldest_idx == (ARRAY_SIZE(filter->device) - 1)) {
		filter->oldest_idx = 0;

		return;
	}

	filter->oldest_idx++;
}

static void scan_attempts_filter_device_add(const bt_addr_le_t *addr)
{
	struct conn_attempts_filter *filter = &bt_scan.attempts_filter;
	char addr_str[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(addr, addr_str, sizeof(addr_str));

	k_mutex_lock(&scan_mutex, K_FOREVER);

	/* Check if device is already in the filter array. */
	for (size_t i = 0; i < filter->count; i++) {
		struct conn_attempts_device *device = &filter->device[i];

		if (bt_addr_le_cmp(addr, &device->addr) == 0) {
			LOG_DBG("Device %s is already in the filter array", addr_str);
			goto out;
		}
	}

	if (filter->count >= ARRAY_SIZE(filter->device)) {
		LOG_DBG("Force adding %s device filter", addr_str);
		attempts_filter_force_add(filter, addr);
	} else {
		bt_addr_le_copy(&filter->device[filter->count].addr, addr);
		filter->count++;
	}

out:
	k_mutex_unlock(&scan_mutex);
}

static void device_conn_attempts_count(struct bt_conn *conn)
{
	const bt_addr_le_t *addr = bt_conn_get_dst(conn);
	struct conn_attempts_filter *filter = &bt_scan.attempts_filter;

	k_mutex_lock(&scan_mutex, K_FOREVER);

	for (size_t i = 0; i < filter->count; i++) {
		struct conn_attempts_device *device = &filter->device[i];

		if (bt_addr_le_cmp(addr, &device->addr) == 0) {
			if (device->attempts < CONFIG_BT_SCAN_CONN_ATTEMPTS_COUNT) {
				device->attempts++;
			}

			break;
		}
	}

	k_mutex_unlock(&scan_mutex);
}

static bool conn_attempts_exceeded(const bt_addr_le_t *addr)
{
	struct conn_attempts_filter *filter = &bt_scan.attempts_filter;
	char addr_str[BT_ADDR_LE_STR_LEN];
	bool attempts_exceeded = false;

	bt_addr_le_to_str(addr, addr_str, sizeof(addr_str));

	k_mutex_lock(&scan_mutex, K_FOREVER);

	/* Check if the device is in the filter array. */
	for (size_t i = 0; i < filter->count; i++) {
		struct conn_attempts_device *device = &filter->device[i];

		if (bt_addr_le_cmp(addr, &device->addr) == 0) {
			if (device->attempts >= CONFIG_BT_SCAN_CONN_ATTEMPTS_COUNT) {
				LOG_DBG("Connection attempts count for %s exceeded", addr_str);
				attempts_exceeded = true;
			}

			break;
		}
	}

	k_mutex_unlock(&scan_mutex);

	return attempts_exceeded;
}

#endif /* CONFIG_BT_SCAN_CONN_ATTEMPTS_FILTER */

static bool scan_device_filter_check(const bt_addr_le_t *addr)
{
#if CONFIG_BT_SCAN_BLOCKLIST
	if (blocklist_device_check(addr)) {
		return false;
	}
#endif /* CONFIG_BT_SCAN_BLOCKLIST */

#if CONFIG_BT_SCAN_CONN_ATTEMPTS_FILTER
	if (conn_attempts_exceeded(addr)) {
		return false;
	}
#endif /* CONFIG_BT_SCAN_CONN_ATTEMPTS_FILTER */

	return true;
}

#if CONFIG_BT_CENTRAL
static void scan_connect_with_target(struct bt_scan_control *control, const bt_addr_le_t *addr)
{
	int err;

	/* Return if the automatic connection is disabled. */
	if (!bt_scan.connect_if_match) {
		return;
	}

	/* Establish connection. */
	struct bt_conn *conn;

	/* Stop scanning. */
	bt_scan_stop();

	err = bt_conn_le_create(addr, BT_CONN_LE_CREATE_CONN, &bt_scan.conn_param, &conn);

	LOG_DBG("Connecting (%d)", err);

	if (err) {
		/* If an error occurred, send an event to
		 * the all interested.
		 */
		notify_connecting_error(&control->device_info);
	} else {
		notify_connecting(&control->device_info, conn);
		bt_conn_unref(conn);
	}
}
#endif /* CONFIG_BT_CENTRAL */

static bool adv_addr_compare(const bt_addr_le_t *target_addr, struct bt_scan_control *control)
{
	const bt_addr_le_t *addr = bt_scan.scan_filters.addr.target_addr;
	uint8_t counter = bt_scan.scan_filters.addr.cnt;

	for (size_t i = 0; i < counter; i++) {
		if (bt_addr_le_cmp(target_addr, &addr[i]) == 0) {
			control->filter_status.addr.addr = &addr[i];

			return true;
		}
	}

	return false;
}

static bool is_addr_filter_enabled(void)
{
	return CONFIG_BT_SCAN_ADDRESS_CNT && bt_scan.scan_filters.addr.enabled;
}

static void check_addr(struct bt_scan_control *control, const bt_addr_le_t *addr)
{
	if (is_addr_filter_enabled()) {
		if (adv_addr_compare(addr, control)) {
			control->filter_match_cnt++;

			/* Information about the filters matched. */
			control->filter_status.addr.match = true;
			control->filter_match = true;
		}
	}
}

static int scan_addr_filter_add(const bt_addr_le_t *target_addr)
{
	char addr[BT_ADDR_LE_STR_LEN];
	bt_addr_le_t *addr_filter = bt_scan.scan_filters.addr.target_addr;
	uint8_t counter = bt_scan.scan_filters.addr.cnt;

	/* If no memory for filter. */
	if (counter >= CONFIG_BT_SCAN_ADDRESS_CNT) {
		return -ENOMEM;
	}

	/* Check for duplicated filter. */
	for (size_t i = 0; i < counter; i++) {
		if (bt_addr_le_cmp(target_addr, &addr_filter[i]) == 0) {
			return 0;
		}
	}

	/* Add target address to filter. */
	bt_addr_le_copy(&addr_filter[counter], target_addr);

	LOG_DBG("Filter set on address type %i", addr_filter[counter].type);

	bt_addr_le_to_str(target_addr, addr, sizeof(addr));

	LOG_DBG("Address: %s", addr);

	/* Increase the address filter counter. */
	bt_scan.scan_filters.addr.cnt++;

	return 0;
}

static bool adv_name_cmp(const uint8_t *data, uint8_t data_len, const char *target_name)
{
	return strncmp(target_name, data, data_len) == 0;
}

static bool adv_name_compare(const struct bt_data *data, struct bt_scan_control *control)
{
	struct bt_scan_name_filter const *name_filter = &bt_scan.scan_filters.name;
	uint8_t counter = bt_scan.scan_filters.name.cnt;
	uint8_t data_len = data->data_len;

	/* Compare the name found with the name filter. */
	for (size_t i = 0; i < counter; i++) {
		if (adv_name_cmp(data->data, data_len, name_filter->target_name[i])) {

			control->filter_status.name.name = name_filter->target_name[i];
			control->filter_status.name.len = data_len;

			return true;
		}
	}

	return false;
}

static inline bool is_name_filter_enabled(void)
{
	return CONFIG_BT_SCAN_NAME_CNT && bt_scan.scan_filters.name.enabled;
}

static void name_check(struct bt_scan_control *control, const struct bt_data *data)
{
	if (is_name_filter_enabled()) {
		if (adv_name_compare(data, control)) {
			control->filter_match_cnt++;

			/* Information about the filters matched. */
			control->filter_status.name.match = true;
			control->filter_match = true;
		}
	}
}

static int scan_name_filter_add(const char *name)
{
	uint8_t counter = bt_scan.scan_filters.name.cnt;
	size_t name_len;

	/* If no memory for filter. */
	if (counter >= CONFIG_BT_SCAN_NAME_CNT) {
		return -ENOMEM;
	}

	name_len = strlen(name);

	/* Check the name length. */
	if ((name_len == 0) || (name_len > CONFIG_BT_SCAN_NAME_MAX_LEN)) {
		return -EINVAL;
	}

	/* Check for duplicated filter. */
	for (size_t i = 0; i < counter; i++) {
		if (!strcmp(bt_scan.scan_filters.name.target_name[i], name)) {
			return 0;
		}
	}

	/* Add name to filter. */
	memcpy(bt_scan.scan_filters.name.target_name[counter], name, name_len);

	bt_scan.scan_filters.name.cnt++;

	LOG_DBG("Adding filter on %s name", name);

	return 0;
}

static bool adv_short_name_cmp(const uint8_t *data, uint8_t data_len, const char *target_name,
			       uint8_t short_name_min_len)
{
	if ((data_len >= short_name_min_len) && (strncmp(target_name, data, data_len) == 0)) {
		return true;
	}

	return false;
}

static bool adv_short_name_compare(const struct bt_data *data, struct bt_scan_control *control)
{
	const struct bt_scan_short_name_filter *name_filter = &bt_scan.scan_filters.short_name;
	uint8_t counter = bt_scan.scan_filters.short_name.cnt;
	uint8_t data_len = data->data_len;

	/* Compare the name found with the name filters. */
	for (size_t i = 0; i < counter; i++) {
		if (adv_short_name_cmp(data->data, data_len, name_filter->name[i].target_name,
				       name_filter->name[i].min_len)) {

			control->filter_status.short_name.name = name_filter->name[i].target_name;
			control->filter_status.short_name.len = data_len;

			return true;
		}
	}

	return false;
}

static inline bool is_short_name_filter_enabled(void)
{
	return CONFIG_BT_SCAN_SHORT_NAME_CNT && bt_scan.scan_filters.short_name.enabled;
}

static void short_name_check(struct bt_scan_control *control, const struct bt_data *data)
{
	if (is_short_name_filter_enabled()) {
		if (adv_short_name_compare(data, control)) {
			control->filter_match_cnt++;

			/* Information about the filters matched. */
			control->filter_status.short_name.match = true;
			control->filter_match = true;
		}
	}
}

static int scan_short_name_filter_add(const struct bt_scan_short_name *short_name)
{
	uint8_t counter = bt_scan.scan_filters.short_name.cnt;
	struct bt_scan_short_name_filter *short_name_filter = &bt_scan.scan_filters.short_name;
	uint8_t name_len;

	/* If no memory for filter. */
	if (counter >= CONFIG_BT_SCAN_SHORT_NAME_CNT) {
		return -ENOMEM;
	}

	name_len = strlen(short_name->name);

	/* Check the name length. */
	if ((name_len == 0) || (name_len > CONFIG_BT_SCAN_SHORT_NAME_MAX_LEN)) {
		return -EINVAL;
	}

	/* Check for duplicated filter. */
	for (size_t i = 0; i < counter; i++) {
		if (!strcmp(short_name_filter->name[i].target_name, short_name->name)) {
			return 0;
		}
	}

	/* Add name to the filter. */
	short_name_filter->name[counter].min_len = short_name->min_len;
	memcpy(short_name_filter->name[counter].target_name, short_name->name, name_len);

	bt_scan.scan_filters.short_name.cnt++;

	LOG_DBG("Adding filter on %s name", short_name->name);

	return 0;
}

static bool find_uuid(const uint8_t *data, uint8_t data_len, uint8_t uuid_type,
		      const struct bt_scan_uuid *target_uuid)
{
	uint8_t uuid_len;

	switch (uuid_type) {
	case BT_UUID_TYPE_16:
		uuid_len = sizeof(uint16_t);
		break;

	case BT_UUID_TYPE_32:
		uuid_len = sizeof(uint32_t);
		break;

	case BT_UUID_TYPE_128:
		uuid_len = BT_SCAN_UUID_128_SIZE * sizeof(uint8_t);
		break;

	default:
		return false;
	}

	for (size_t i = 0; i < data_len; i += uuid_len) {
		struct bt_uuid_128 uuid;

		if (!bt_uuid_create(&uuid.uuid, &data[i], uuid_len)) {
			return false;
		}

		if (bt_uuid_cmp(&uuid.uuid, target_uuid->uuid) == 0) {
			return true;
		}
	}

	return false;
}

static bool adv_uuid_compare(const struct bt_data *data, uint8_t uuid_type,
			     struct bt_scan_control *control)
{
	const struct bt_scan_uuid_filter *uuid_filter = &bt_scan.scan_filters.uuid;
	const bool all_filters_mode = bt_scan.scan_filters.all_mode;
	const uint8_t counter = bt_scan.scan_filters.uuid.cnt;
	uint8_t data_len = data->data_len;
	uint8_t uuid_match_cnt = 0;

	for (size_t i = 0; i < counter; i++) {

		if (find_uuid(data->data, data_len, uuid_type, &uuid_filter->uuid[i])) {
			control->filter_status.uuid.uuid[uuid_match_cnt] =
				uuid_filter->uuid[i].uuid;

			uuid_match_cnt++;

			/* In the normal filter mode,
			 * only one UUID is needed to match.
			 */
			if (!all_filters_mode) {
				break;
			}

		} else if (all_filters_mode) {
			break;
		}
	}

	control->filter_status.uuid.count = uuid_match_cnt;

	/* In the multifilter mode, all UUIDs must be found in
	 * the advertisement packets.
	 */
	if ((all_filters_mode && (uuid_match_cnt == counter)) ||
	    ((!all_filters_mode) && (uuid_match_cnt > 0))) {
		return true;
	}

	return false;
}

static bool is_uuid_filter_enabled(void)
{
	return CONFIG_BT_SCAN_UUID_CNT && bt_scan.scan_filters.uuid.enabled;
}

static void uuid_check(struct bt_scan_control *control, const struct bt_data *data, uint8_t type)
{
	if (is_uuid_filter_enabled()) {
		if (adv_uuid_compare(data, type, control)) {
			control->filter_match_cnt++;

			/* Information about the filters matched. */
			control->filter_status.uuid.match = true;
			control->filter_match = true;
		}
	}
}

static int scan_uuid_filter_add(struct bt_uuid *uuid)
{
	struct bt_scan_uuid *uuid_filter = bt_scan.scan_filters.uuid.uuid;
	uint8_t counter = bt_scan.scan_filters.uuid.cnt;
	struct bt_uuid_16 *uuid_16;
	struct bt_uuid_32 *uuid_32;
	struct bt_uuid_128 *uuid_128;

	/* If no memory. */
	if (counter >= CONFIG_BT_SCAN_UUID_CNT) {
		return -ENOMEM;
	}

	/* Check for duplicated filter. */
	for (size_t i = 0; i < counter; i++) {
		if (bt_uuid_cmp(uuid_filter[i].uuid, uuid) == 0) {
			return 0;
		}
	}

	/* Add UUID to the filter. */
	switch (uuid->type) {
	case BT_UUID_TYPE_16:
		uuid_16 = BT_UUID_16(uuid);

		uuid_filter[counter].uuid_data.uuid_16 = *uuid_16;
		uuid_filter[counter].uuid =
			(struct bt_uuid *)&uuid_filter[counter].uuid_data.uuid_16;
		break;

	case BT_UUID_TYPE_32:
		uuid_32 = BT_UUID_32(uuid);

		uuid_filter[counter].uuid_data.uuid_32 = *uuid_32;
		uuid_filter[counter].uuid =
			(struct bt_uuid *)&uuid_filter[counter].uuid_data.uuid_32;
		break;

	case BT_UUID_TYPE_128:
		uuid_128 = BT_UUID_128(uuid);

		uuid_filter[counter].uuid_data.uuid_128 = *uuid_128;
		uuid_filter[counter].uuid =
			(struct bt_uuid *)&uuid_filter[counter].uuid_data.uuid_128;
		break;

	default:
		return -EINVAL;
	}

	bt_scan.scan_filters.uuid.cnt++;
	LOG_DBG("Added filter on UUID type %x", uuid->type);

	return 0;
}

static bool find_appearance(const uint8_t *data, uint8_t data_len, const uint16_t *appearance)
{
	if (data_len != sizeof(uint16_t)) {
		return false;
	}

	uint16_t decoded_appearance = sys_get_le16(data);

	if (decoded_appearance == *appearance) {
		return true;
	}

	/* Could not find the appearance among the encoded data. */
	return false;
}

static bool adv_appearance_compare(const struct bt_data *data, struct bt_scan_control *control)
{
	const struct bt_scan_appearance_filter *appearance_filter =
		&bt_scan.scan_filters.appearance;
	const uint8_t counter = bt_scan.scan_filters.appearance.cnt;
	uint8_t data_len = data->data_len;

	/* Verify if the advertised appearance matches
	 * the provided appearance.
	 */
	for (size_t i = 0; i < counter; i++) {
		if (find_appearance(data->data, data_len, &appearance_filter->appearance[i])) {

			control->filter_status.appearance.appearance =
				&appearance_filter->appearance[i];

			return true;
		}
	}

	return false;
}

static inline bool is_appearance_filter_enabled(void)
{
	return CONFIG_BT_SCAN_APPEARANCE_CNT && bt_scan.scan_filters.appearance.enabled;
}

static void appearance_check(struct bt_scan_control *control, const struct bt_data *data)
{
	if (is_appearance_filter_enabled()) {
		if (adv_appearance_compare(data, control)) {
			control->filter_match_cnt++;

			/* Information about the filters matched. */
			control->filter_status.appearance.match = true;
			control->filter_match = true;
		}
	}
}

static int scan_appearance_filter_add(uint16_t appearance)
{
	uint16_t *appearance_filter = bt_scan.scan_filters.appearance.appearance;
	uint8_t counter = bt_scan.scan_filters.appearance.cnt;

	/* If no memory. */
	if (counter >= CONFIG_BT_SCAN_APPEARANCE_CNT) {
		return -ENOMEM;
	}

	/* Check for duplicated filter. */
	for (size_t i = 0; i < counter; i++) {
		if (appearance_filter[i] == appearance) {
			return 0;
		}
	}

	/* Add appearance to the filter. */
	appearance_filter[counter] = appearance;
	bt_scan.scan_filters.appearance.cnt++;

	LOG_DBG("Added filter on appearance %x", appearance);

	return 0;
}

static bool adv_manufacturer_data_cmp(const uint8_t *data, uint8_t data_len,
				      const uint8_t *target_data, uint8_t target_data_len)
{
	if (target_data_len > data_len) {
		return false;
	}

	if (memcmp(target_data, data, target_data_len) != 0) {
		return false;
	}

	return true;
}

static bool adv_manufacturer_data_compare(const struct bt_data *data,
					  struct bt_scan_control *control)
{
	const struct bt_scan_manufacturer_data_filter *md_filter =
		&bt_scan.scan_filters.manufacturer_data;
	uint8_t counter = bt_scan.scan_filters.manufacturer_data.cnt;

	/* Compare the name found with the name filter. */
	for (size_t i = 0; i < counter; i++) {
		if (adv_manufacturer_data_cmp(data->data, data->data_len,
					      md_filter->manufacturer_data[i].data,
					      md_filter->manufacturer_data[i].data_len)) {

			control->filter_status.manufacturer_data.data =
				md_filter->manufacturer_data[i].data;
			control->filter_status.manufacturer_data.len =
				md_filter->manufacturer_data[i].data_len;

			return true;
		}
	}

	return false;
}
static inline bool is_manufacturer_data_filter_enabled(void)
{
	return CONFIG_BT_SCAN_MANUFACTURER_DATA_CNT &&
	       bt_scan.scan_filters.manufacturer_data.enabled;
}

static void manufacturer_data_check(struct bt_scan_control *control, const struct bt_data *data)
{
	if (is_manufacturer_data_filter_enabled()) {
		if (adv_manufacturer_data_compare(data, control)) {
			control->filter_match_cnt++;

			/* Information about the filters matched. */
			control->filter_status.manufacturer_data.match = true;
			control->filter_match = true;
		}
	}
}

static int
scan_manufacturer_data_filter_add(const struct bt_scan_manufacturer_data *manufacturer_data)
{
	struct bt_scan_manufacturer_data_filter *md_filter =
		&bt_scan.scan_filters.manufacturer_data;
	uint8_t counter = bt_scan.scan_filters.manufacturer_data.cnt;

	/* If no memory for filter. */
	if (counter >= CONFIG_BT_SCAN_MANUFACTURER_DATA_CNT) {
		return -ENOMEM;
	}

	/* Check the data length. */
	if ((manufacturer_data->data_len == 0) ||
	    (manufacturer_data->data_len > CONFIG_BT_SCAN_MANUFACTURER_DATA_MAX_LEN)) {
		return -EINVAL;
	}

	/* Check for duplicated filter. */
	for (size_t i = 0; i < counter; i++) {
		if (adv_manufacturer_data_cmp(manufacturer_data->data, manufacturer_data->data_len,
					      md_filter->manufacturer_data[i].data,
					      md_filter->manufacturer_data[i].data_len)) {
			return 0;
		}
	}

	/* Add manufacturer data to filter. */
	memcpy(md_filter->manufacturer_data[counter].data, manufacturer_data->data,
	       manufacturer_data->data_len);
	md_filter->manufacturer_data[counter].data_len = manufacturer_data->data_len;

	bt_scan.scan_filters.manufacturer_data.cnt++;

	LOG_DBG("Adding filter on manufacturer data");

	return 0;
}

static bool check_filter_mode(uint8_t mode)
{
	return (mode & MODE_CHECK) != 0;
}

static void scan_default_param_set(void)
{
	struct bt_le_scan_param *scan_param = BT_LE_SCAN_PASSIVE;

	/* Set the default parameters. */
	bt_scan.scan_param = *scan_param;
}

#if CONFIG_BT_SCAN_CONN_ATTEMPTS_FILTER
static void connected(struct bt_conn *conn, uint8_t err)
{
	scan_attempts_filter_device_add(bt_conn_get_dst(conn));
	if (err) {
		device_conn_attempts_count(conn);
	}
}

static void disconnected(struct bt_conn *conn, uint8_t reason)
{
	device_conn_attempts_count(conn);
}

static struct bt_conn_cb conn_callbacks = {.connected = connected, .disconnected = disconnected};
#endif /* CONFIG_BT_SCAN_CONN_ATTEMPTS_FILTER */

static void scan_default_conn_param_set(void)
{
	struct bt_le_conn_param *conn_param = BT_LE_CONN_PARAM_DEFAULT;

	/* Set default Connection params. */
	bt_scan.conn_param = *conn_param;
}

int bt_scan_filter_add(enum bt_scan_filter_type type, const void *data)
{
	char *name;
	struct bt_scan_short_name *short_name;
	bt_addr_le_t *addr;
	struct bt_uuid *uuid;
	uint16_t appearance;
	struct bt_scan_manufacturer_data *manufacturer_data;
	int err = 0;

	if (!data) {
		return -EINVAL;
	}

	k_mutex_lock(&scan_mutex, K_FOREVER);

	switch (type) {
	case BT_SCAN_FILTER_TYPE_NAME:
		name = (char *)data;
		err = scan_name_filter_add(name);
		break;

	case BT_SCAN_FILTER_TYPE_SHORT_NAME:
		short_name = (struct bt_scan_short_name *)data;
		err = scan_short_name_filter_add(short_name);
		break;

	case BT_SCAN_FILTER_TYPE_ADDR:
		addr = (bt_addr_le_t *)data;
		err = scan_addr_filter_add(addr);
		break;

	case BT_SCAN_FILTER_TYPE_UUID:
		uuid = (struct bt_uuid *)data;
		err = scan_uuid_filter_add(uuid);
		break;

	case BT_SCAN_FILTER_TYPE_APPEARANCE:
		appearance = *((uint16_t *)data);
		err = scan_appearance_filter_add(appearance);
		break;

	case BT_SCAN_FILTER_TYPE_MANUFACTURER_DATA:
		manufacturer_data = (struct bt_scan_manufacturer_data *)data;
		err = scan_manufacturer_data_filter_add(manufacturer_data);
		break;

	default:
		err = -EINVAL;
		break;
	}

	k_mutex_unlock(&scan_mutex);

	return err;
}

void bt_scan_filter_remove_all(void)
{
	k_mutex_lock(&scan_mutex, K_FOREVER);

	struct bt_scan_name_filter *name_filter = &bt_scan.scan_filters.name;
	name_filter->cnt = 0;

	struct bt_scan_short_name_filter *short_name_filter = &bt_scan.scan_filters.short_name;
	short_name_filter->cnt = 0;

	struct bt_scan_addr_filter *addr_filter = &bt_scan.scan_filters.addr;
	addr_filter->cnt = 0;

	struct bt_scan_uuid_filter *uuid_filter = &bt_scan.scan_filters.uuid;
	uuid_filter->cnt = 0;

	struct bt_scan_appearance_filter *appearance_filter = &bt_scan.scan_filters.appearance;
	appearance_filter->cnt = 0;

	struct bt_scan_manufacturer_data_filter *manufacturer_data_filter =
		&bt_scan.scan_filters.manufacturer_data;
	manufacturer_data_filter->cnt = 0;

	k_mutex_unlock(&scan_mutex);
}

void bt_scan_filter_disable(void)
{
	/* Disable all filters. */
	bt_scan.scan_filters.name.enabled = false;
	bt_scan.scan_filters.short_name.enabled = false;
	bt_scan.scan_filters.addr.enabled = false;
	bt_scan.scan_filters.uuid.enabled = false;
	bt_scan.scan_filters.appearance.enabled = false;
	bt_scan.scan_filters.manufacturer_data.enabled = false;
}

int bt_scan_filter_enable(uint8_t mode, bool match_all)
{
	/* Check if the mode is correct. */
	if (!check_filter_mode(mode)) {
		return -EINVAL;
	}

	/* Disable filters. */
	bt_scan_filter_disable();

	struct bt_scan_filters *filters = &bt_scan.scan_filters;

	/* Turn on the filters of your choice. */
	if (mode & BT_SCAN_ADDR_FILTER) {
		filters->addr.enabled = true;
	}

	if (mode & BT_SCAN_NAME_FILTER) {
		filters->name.enabled = true;
	}

	if (mode & BT_SCAN_SHORT_NAME_FILTER) {
		filters->short_name.enabled = true;
	}

	if (mode & BT_SCAN_UUID_FILTER) {
		filters->uuid.enabled = true;
	}

	if (mode & BT_SCAN_APPEARANCE_FILTER) {
		filters->appearance.enabled = true;
	}

	if (mode & BT_SCAN_MANUFACTURER_DATA_FILTER) {
		filters->manufacturer_data.enabled = true;
	}

	/* Select the filter mode. */
	filters->all_mode = match_all;

	return 0;
}

int bt_scan_filter_status_get(struct bt_filter_status *status)
{
	if (!status) {
		return -EINVAL;
	}

	status->addr.enabled = bt_scan.scan_filters.addr.enabled;
	status->addr.cnt = bt_scan.scan_filters.addr.cnt;
	status->name.enabled = bt_scan.scan_filters.name.enabled;
	status->name.cnt = bt_scan.scan_filters.name.cnt;
	status->short_name.enabled = bt_scan.scan_filters.short_name.enabled;
	status->short_name.cnt = bt_scan.scan_filters.short_name.cnt;
	status->uuid.enabled = bt_scan.scan_filters.uuid.enabled;
	status->uuid.cnt = bt_scan.scan_filters.uuid.cnt;
	status->appearance.enabled = bt_scan.scan_filters.appearance.enabled;
	status->appearance.cnt = bt_scan.scan_filters.appearance.cnt;
	status->manufacturer_data.enabled = bt_scan.scan_filters.manufacturer_data.enabled;
	status->manufacturer_data.cnt = bt_scan.scan_filters.manufacturer_data.cnt;

	return 0;
}

int bt_scan_stop(void)
{
	return bt_le_scan_stop();
}

typedef struct {
	char *key;
	int value;
	int is_occupied;
} Entry;

typedef struct {
	Entry table[30];
} HashTable;

unsigned long hash(char *str)
{
	unsigned long hash = 5381;
	int c;
	while ((c = *str++)) {
		hash = ((hash << 5) + hash) + c;
	}
	return hash;
}

void init_table(HashTable *hashTable)
{
	for (int i = 0; i < 30; i++) {
		hashTable->table[i].key = NULL;
		hashTable->table[i].is_occupied = 0;
	}
}

void insert(HashTable *hashTable, char *key, int value)
{
	printk("insert called with %s %d", key, value);
	unsigned long index1 = hash(key) % 30;
	int original_index = index1;

	while (hashTable->table[index1].is_occupied) {
		if (strcmp(hashTable->table[index1].key, key) == 0) {
			hashTable->table[index1].value = value;
			return;
		}
		index1 = (index1 + 1) % 30;
		if (index1 == original_index) {
			printf("Error: Hash table is full\n");
			return;
		}
	}

	// hashTable->table[index1].key = strdup(key);
	hashTable->table[index1].key = key;
	hashTable->table[index1].value = value;
	hashTable->table[index1].is_occupied = 1;
}

int lookup(HashTable *hashTable, char *key)
{
	unsigned long index1 = hash(key) % 30;
	int original_index = index1;

	while (hashTable->table[index1].is_occupied) {
		if (hashTable->table[index1].key != NULL &&
		    strcmp(hashTable->table[index1].key, key) == 0) {
			return hashTable->table[index1].value;
		}
		index1 = (index1 + 1) % 30;
		if (index1 == original_index) {
			// Searched the entire table
			break;
		}
	}

	return -1;
}

void free_table(HashTable *hashTable)
{
	for (int i = 0; i < 30; i++) {
		if (hashTable->table[i].is_occupied && hashTable->table[i].key != NULL) {
			free(hashTable->table[i].key);
		}
	}
}
HashTable hashTable;

static struct bt_le_scan_cb scan_cb;
void bt_scan_init(const struct bt_scan_init_param *init)
{
	init_table(&hashTable);

	bt_le_scan_cb_register(&scan_cb);

	/* Disable all scanning filters. */
	memset(&bt_scan.scan_filters, 0, sizeof(bt_scan.scan_filters));

	/* If the pointer to the initialization structure exist,
	 * use it to scan the configuration.
	 */
	if (init) {
#if CONFIG_BT_CENTRAL
		bt_scan.connect_if_match = init->connect_if_match;
#endif /* CONFIG_BT_CENTRAL */

		if (init->scan_param) {
			bt_scan.scan_param = *init->scan_param;
		} else {
			/* Use the default static configuration. */
			scan_default_param_set();
		}

		if (init->conn_param) {
			bt_scan.conn_param = *init->conn_param;
		} else {
			/* Use the default static configuration. */
			scan_default_conn_param_set();
		}
	} else {
		/* If pointer is NULL, use the static default configuration. */
		scan_default_param_set();
		scan_default_conn_param_set();

#if CONFIG_BT_CENTRAL
		bt_scan.connect_if_match = false;
#endif /* CONFIG_BT_CENTRAL */
	}

#if CONFIG_BT_SCAN_CONN_ATTEMPTS_FILTER
	bt_conn_cb_register(&conn_callbacks);
#endif /* CONFIG_BT_SCAN_CONN_ATTEMPTS_FILTER */
}

void bt_scan_update_init_conn_params(struct bt_le_conn_param *new_conn_param)
{
	bt_scan.conn_param = *new_conn_param;
}

static void check_enabled_filters(struct bt_scan_control *control)
{
	control->filter_cnt = 0;

	if (is_addr_filter_enabled()) {
		control->filter_cnt++;
	}

	if (is_name_filter_enabled()) {
		control->filter_cnt++;
	}

	if (is_short_name_filter_enabled()) {
		control->filter_cnt++;
	}

	if (is_uuid_filter_enabled()) {
		control->filter_cnt++;
	}

	if (is_appearance_filter_enabled()) {
		control->filter_cnt++;
	}

	if (is_manufacturer_data_filter_enabled()) {
		control->filter_cnt++;
	}
}

static bool adv_data_found(struct bt_data *data, void *user_data)
{
	struct bt_scan_control *scan_control = (struct bt_scan_control *)user_data;

	switch (data->type) {
	case BT_DATA_NAME_COMPLETE:
		/* Check the name filter. */
		name_check(scan_control, data);
		break;

	case BT_DATA_NAME_SHORTENED:
		/* Check the short name filter. */
		short_name_check(scan_control, data);
		break;

	case BT_DATA_GAP_APPEARANCE:
		/* Check the appearance filter. */
		appearance_check(scan_control, data);
		break;

	case BT_DATA_UUID16_SOME:
	case BT_DATA_UUID16_ALL:
		/* Check the UUID filter. */
		uuid_check(scan_control, data, BT_UUID_TYPE_16);
		break;

	case BT_DATA_UUID32_SOME:
	case BT_DATA_UUID32_ALL:
		uuid_check(scan_control, data, BT_UUID_TYPE_32);
		break;

	case BT_DATA_UUID128_SOME:
	case BT_DATA_UUID128_ALL:
		/* Check the UUID filter. */
		uuid_check(scan_control, data, BT_UUID_TYPE_128);
		break;

	case BT_DATA_MANUFACTURER_DATA:
		/* Check the manufacturer data filter. */
		manufacturer_data_check(scan_control, data);
		break;

	default:
		break;
	}

	return true;
}

static void filter_state_check(struct bt_scan_control *control, const bt_addr_le_t *addr)
{
	if (!scan_device_filter_check(addr)) {
		return;
	}

	if (control->all_mode && (control->filter_match_cnt == control->filter_cnt)) {
		notify_filter_matched(&control->device_info, &control->filter_status,
				      control->connectable);
#if CONFIG_BT_CENTRAL
		scan_connect_with_target(control, addr);
#endif /* CONFIG_BT_CENTRAL */
	}

	/* In the normal filter mode, only one filter match is
	 * needed to generate the notification to the main application.
	 */
	else if ((!control->all_mode) && control->filter_match) {
		notify_filter_matched(&control->device_info, &control->filter_status,
				      control->connectable);
#if CONFIG_BT_CENTRAL
		scan_connect_with_target(control, addr);
#endif /* CONFIG_BT_CENTRAL */
	} else {
		notify_filter_no_match(&control->device_info, control->connectable);
	}
}
#define TIMEOUT_SECONDS 3
uint64_t start_time;
bool timeout_expired = false;
// uint64_t current_time;
bool first = true;

// static void print_adv_data(struct bt_data *data, void *user_data)
// {
// 	uint64_t current_time = k_uptime_get();

// 	if (first) {
// 		start_time = k_uptime_get();
// 		first = false;
// 	}

// 	if (!timeout_expired) {
// 		if ((current_time - start_time) >= (TIMEOUT_SECONDS * 1000)) {
// 			/* Timeout has elapsed, set the timeout_expired flag */
// 			timeout_expired = true;
// 		} else {
// 			printk("Advertising data type: %u, len: %u\n", data->type, data->data_len);
// 			printk("Raw data: ");
// 			for (int i = 0; i < data->data_len; i++) {
// 				printk("%02x ", data->data[i]);
// 			}
// 			printk("\n");

// 			/* Interpret and print specific information based on the data type */
// 			// switch (data->type) {
// 			// case BT_DATA_FLAGS:
// 			// 	/* Interpret flags data */
// 			// 	printk("Flags: 0x%02x\n", data->data[0]);
// 			// 	break;
// 			// case BT_DATA_UUID16_ALL:
// 			// 	/* Interpret list of 16-bit service UUIDs */
// 			// 	for (int i = 0; i < data->data_len; i += 2) {
// 			// 		uint16_t uuid = (data->data[i + 1] << 8) | data->data[i];
// 			// 		printk("UUID16: 0x%04x\n", uuid);
// 			// 	}
// 			// 	break;
// 			// case BT_DATA_UUID32_ALL:
// 			// 	/* Interpret list of 32-bit service UUIDs */
// 			// 	for (int i = 0; i < data->data_len; i += 4) {
// 			// 		uint32_t uuid = (data->data[i + 3] << 24) |
// 			// 				(data->data[i + 2] << 16) |
// 			// 				(data->data[i + 1] << 8) | data->data[i];
// 			// 		printk("UUID32: 0x%08x\n", uuid);
// 			// 	}
// 			// 	break;
// 			// case BT_DATA_NAME_COMPLETE:
// 			// 	printk("Device Name: %.*s\n", data->data_len, data->data);
// 			// 	break;
// 			// case BT_DATA_NAME_SHORTENED:
// 			// 	/* Print the device name */
// 			// 	printk("Device Name: %.*s\n", data->data_len, data->data);
// 			// 	break;
// 			// // Add more cases for other data types as needed
// 			// default:
// 			// 	/* Unknown or unhandled data type */
// 			// 	printk("Unhandled data type: %u%s\n", data->type, data->data);
// 			// 	break;
// 			// }
// 		}
// 	}
// }
#include <string.h>

//-------------------------------------------------------------------------------------------Above
// is the most recent code

// we're only scanning for stuff that "enter" the scanning options. We should make it so that we can
// track IDs. However, in the case of only scanning new entries atually it doesn't matter, an object
// would always be the best case.

// struct packet {

// 	u_int64_t time;
// 	u_int8_t type;
// 	char addr_id[];
// 	packet *p_next;
// };

// struct list {
// 	packet *p_head;
// };

// struct packet *insert(packet *new_packet)
// {
// 	if (p_head == NULL) {
// 		p_head = new_packet;
// 	} else {
// 		packet *Node = p_head;
// 		while (Node->p_next != NULL) {
// 			Node = Node->p_next;
// 		}
// 		Node->p_next = new_packet;
// 		// Node = nullptr;
// 	}
// }

// struct packet *createPacket(u_int64_t time, int8_t msg_type, char *addr_id)
// {
// 	struct packet *new_packet = (struct packet *)malloc(sizeof(struct packet));
// }

// only storing the type of message that is advertised because that is all is needed for occupancy
// checking. just dynamically allocate into an array that increases in size

// address of the block created hold by this pointer
// typedef struct {
// 	uint8_t *storeA;
// 	size_t size;

// }
// uint8_t *storage = (uint8_t *)malloc(10 * sizeof(uint8_t));
// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
uint8_t raw_type_storage[30] = {0x00};
char type[30]; // useless since can just output type as the byte data
int rssi[30] = {0};
int first_detected[30] = {0};
char *addresses[30];
// bt_data *payloads[30];
uint8_t *raw_data_buffers[30] = {NULL};
uint8_t raw_data_lens[30] = {0};

// void createTable()
// {

// }

// int last_detected[50];
// char addr_storage[50][17];

// commented the two above; have to create a hash map.

// it's key that the index only increases on every new packet, so we'll do [++index] in the
// very first function wher eit receives data and is currently printing "conectable device
// found..." in order to update the endtime we have to use hash table and use structs for
// once.

int index = 0;
int size = 1;

// before we stored all the types so that we can use them to detect "occupancy". now we
// won't do that anymore, we're just tracking stuff and printing. only complication is that
// the size of the raw data will be an issue.

void occupancy_status(int time)
{
	printk("Device number: %d \t", time);

	bool occupied = false;
	if (time < 6) {
		occupied = false;
	} else {
		for (int i = 6; i > 0; i--) {
			// printk(" % 02x ", storage[time - 1 - i]);
			if (raw_type_storage[time - 1 - i] == 0x02) {
				occupied = true;
				break;
			}
			if (raw_type_storage[time - 1 - i] == 0x03) {
				occupied = true;
				break;
			}
			if (raw_type_storage[time - 1 - i] == 0x05) {
				occupied = true;
				break;
			}
			if (raw_type_storage[time - 1 - i] == 0x06) {
				occupied = true;
				break;
			}
			if (raw_type_storage[time - 1 - i] == 0x07) {
				occupied = true;
				break;
			}
			if (raw_type_storage[time - 1 - i] == 0x08) {
				occupied = true;
				break;
			}
			if (raw_type_storage[time - 1 - i] == 0x09) {
				occupied = true;
				break;
			}
			if (raw_type_storage[time - 1 - i] == 0x0a) {
				occupied = true;
				break;
			}
			if (raw_type_storage[time - 1 - i] == 0x0b) {
				occupied = true;
				break;
			}
			if (raw_type_storage[time - 1 - i] == 0x0c) {
				occupied = true;
				break;
			}
			if (raw_type_storage[time - 1 - i] == 0x0d) {
				occupied = true;
				break;
			}
			if (raw_type_storage[time - 1 - i] == 0x0e) {
				occupied = true;
				break;
			}
			if (raw_type_storage[time - 1 - i] == 0x0f) {
				occupied = true;
				break;
			}
			if (raw_type_storage[time - 1 - i] == 0x10) {
				occupied = true;
				break;
			}
		}
	}
	if (occupied) {
		printk("Occupied \t ");
	} else {
		printk("Unoccupied \t");
	}
	index++;
}
// char *string_sub;

void print_table()
{
	printk("request went through\n");
	fflush(stdout);

	// printk("%s", string_sub);
	// printk("START");
	printk("+-------------------------------------+-------------------+-----------------+------"
	       "---------------------+------+---------------------------------\n"
	       "|            MAC ADDRESS              | INITIAL TIMESTAMP | FINAL TIMESTAMP | "
	       "MESSAGE TYPE (APPLE ONLY) | RSSI |             Payload             \n"
	       "+-------------------------------------+-------------------+-----------------+------"
	       "---------------------+------+---------------------------------\n");
	fflush(stdout);

	for (int i = 1; i < 30; ++i) {
		// printk(" %s", addresses[i]);
		if (addresses[i] != NULL) {
			printk("\t%s\t\t", addresses[i]);
			fflush(stdout);
		}
		k_sleep(K_MSEC(200));

		printk("%d ms \t", first_detected[i]);
		k_sleep(K_MSEC(200));

		fflush(stdout);
		printk("%d ms\t\t\t", lookup(&hashTable, addresses[i]));
		k_sleep(K_MSEC(200));

		fflush(stdout);
		printk("%02x \t\t ", raw_type_storage[i]);
		k_sleep(K_MSEC(200));

		fflush(stdout);
		printk("%d dBm \t", rssi[i]);
		k_sleep(K_MSEC(200));

		fflush(stdout);

		if (raw_data_buffers[i] != NULL) {
			for (int j = 0; j < raw_data_lens[i]; j++) {
				printk(" %02x", raw_data_buffers[i][j]);
			}
		} else {
			printk(" No payload data");
		}
		k_sleep(K_MSEC(200));

		printk("\n");
		// printk("%d \n", lookup(&hashTable, )) uint8_t raw_type_storage[50];
		// int rssi[50];
		// int first_detected[50];
		// int lookup(HashTable * hashTable, char *key)
	}
	fflush(stdout); // Ensure the output is flushed
	index = 0;
}
int index_improve = -1;

static void print_adv_data(struct bt_data *data, void *user_data)
{
	uint64_t current_time = k_uptime_get();

	if (first) {
		start_time = k_uptime_get();
		first = false;
	}
	// printf("Your boolean variable is: %s", x ? "true" : "false");

	printk("%d\n", timeout_expired);

	if (!timeout_expired) {
		if (((current_time - start_time) >= (TIMEOUT_SECONDS * 1000))) {
			/* Timeout has elapsed, set the timeout_expired flag */
			timeout_expired = true;
			// printk("xiang ni hao");
			// print_table();
		} else {
			// the else is unncessary
			printk("Advertising data type: %u, len: %u", data->type, data->data_len);
			printk("\n");
			// int timestamp_detected = k_uptime_get();
			// first_detected[index] = timestamp_detected;
			// printk("%" PRIu64 "ms\n", timestamp_detected);
			printk("Raw data: ");

			if (index < 30) {
				if (index_improve == -1) {
					raw_data_lens[index] = data->data_len;
					raw_data_buffers[index] =
						(uint8_t *)malloc(data->data_len * sizeof(uint8_t));
					if (raw_data_buffers[index]) {
						memcpy(raw_data_buffers[index], data->data,
						       data->data_len);
					} else {
						printk("Failed to allocate memory for raw data "
						       "buffer\n");
					}
				} else {
					raw_data_lens[index_improve] = data->data_len;
					raw_data_buffers[index_improve] =
						(uint8_t *)malloc(data->data_len * sizeof(uint8_t));
					if (raw_data_buffers[index_improve]) {
						memcpy(raw_data_buffers[index_improve], data->data,
						       data->data_len);
					} else {
						printk("Failed to allocate memory for raw data "
						       "buffer\n");
					}
				}
			}

			for (int i = 0; i < data->data_len; i++) {
				printk("%02x ", data->data[i]);
			}
			printk("\n");

			if (data->data && data->data_len >= 2 && data->data[0] == 0x4C &&
			    data->data[1] == 0x00) {

				// uint64_t timestamp = k_uptime_get();
				printk("APPLE DEVICE ");

				printk("\n");

				// int new_size = size + 1; // Double the size (can adjust
				// as needed) uint8_t *temp = realloc(storage, new_size *
				// sizeof(uint8_t)); if (temp != NULL) {
				// 	// Reallocation was successful
				// 	storage = temp;	 // Update the pointer
				// 	size = new_size; // Update the size
				// 	storage[index++] = data->data[2];
				// }
				// storage = temp;
				// storage[index++] = data->data[2];

				if (index < 30) {
					if (index_improve == -1) {
						raw_type_storage[index] = data->data[2];
					} else {
						raw_type_storage[index_improve] = data->data[2];
					}
				}
				// ALHOUGH WE WON'T BE TRACKING OCCUPANY, IE WE WON'T BE
				// ITERATING THROUGH THIS ARRAY, WE STILL NEED THIS SO THAT
				// WE CAN OUTPUT THE TYPE.

				switch (data->data[2]) {
				case 0x02:
					printk("iBeacon \n ");
					// printing in every case is not needed but can be
					// done
					// printk("%" PRIu64 "ms\n", k_uptime_get());
					break;
				case 0x03:
					printk("AirPrint \n");
					// printk("%" PRIu64 "ms\n", k_uptime_get());

					break;

				case 0x05:
					printk("AirDrop\n ");
					// printk("%" PRIu64 "ms\n", k_uptime_get());

					break;
				case 0x06:
					printk("HomeKit \n");
					// printk("%" PRIu64 "ms\n", k_uptime_get());

					break;
				case 0x07:
					printk("AirPods (Proximity Pairing) \n");
					// printk("%" PRIu64 "ms\n", k_uptime_get());

					break;
				case 0x08:
					printk("\"Hey Siri\"\n ");
					// printk("%" PRIu64 "ms\n", k_uptime_get());

					break;
				case 0x09:
				case 0x0a:
					printk("AirPlay\n ");
					// printk("%" PRIu64 "ms\n", k_uptime_get());

					break;
				case 0x0b:
					printk("Watch \n");
					// printk("%" PRIu64 "ms\n", k_uptime_get());

					break;
				case 0x0c:
					printk("HandOff \n");
					// printk("%" PRIu64 "ms\n", k_uptime_get());

					break;
				case 0x0d:
					printk("Wifi Settings (tethering target)\n");
					// printk("%" PRIu64 "ms\n", k_uptime_get());

					break;
				case 0x0e:
					printk("Instant Hotspot (tethering source) \n");
					// printk("%" PRIu64 "ms\n", k_uptime_get());

					break;
				case 0x0f:
					printk("WiFi Join (Nearby Action) \n");
					// printk("%" PRIu64 "ms\n", k_uptime_get());

					break;
				case 0x10:
					printk("Nearby (nearby Info) \n");
					// printk("%" PRIu64 "ms\n", k_uptime_get());

					break;
				case 0x12:
					printk("Handoff Related\n");
				default:
					printk("unrecognized \n");
					// printk("%" PRIu64 "ms\n", k_uptime_get());

					break;
				}
			} else {
				if (index < 30) {
					if (index_improve == -1) {

						raw_type_storage[index] = 0x00;
					} else {
						raw_type_storage[index_improve] = 0x00;
					}
				}
			}
			// printk("\n");
		}
	}
	//  else {
	// 	printk("xiang ni hao");
	// 	print_table();
	// }
}

// in essence, in C, a has table really is just an array of structs, but it creates that inherent
// connection between a key and a value. like you might think: what's the us eof lookup if we
// already have the array. I suppose it's just for the O(1).

// 	CURL *curl;
// 	CURLcode res;

// 	// Initialize libcurl
// 	curl_global_init(CURL_GLOBAL_ALL);

// 	// Initialize curl handle
// 	curl = curl_easy_init();

// 	if (curl) {
// 		// Set the URL
// 		curl_easy_setopt(curl, CURLOPT_URL, "https://api.example.com/data");

// 		// Perform the request
// 		res = curl_easy_perform(curl);

// 		// Check for errors
// 		if (res != CURLE_OK) {
// 			fprintf(stderr, "curl_easy_perform() failed: %s\n",
// 				curl_easy_strerror(res));
// 		}

// 		// Cleanup
// 		curl_easy_cleanup(curl);
// 	}

// 	// Cleanup libcurl
// 	curl_global_cleanup();
// #include "httplib.h"

// #include "nano-http.h"

// static void send_mac_address_request(const char *mac_address)
// {
// 	char url[64];
// 	snprintf(url, sizeof(url), "https://api.maclookup.app/v2/macs/%s", mac_address);

// 	struct http_request req;
// 	http_request_init(&req, HTTP_GET, url);

// 	struct http_response res;
// 	http_response_init(&res);

// 	if (http_request(&req, &res) != 0) {
// 		printf("Error: %s\n", res.status_message);
// 		return;
// 	}

// 	if (res.status_code == 200) {
// 		printf("Response body: %s\n", res.company);
// 	} else {
// 		printf("Error: %d %s\n", res.status_code, res.status_message);
// 	}

// 	http_request_free(&req);
// 	http_response_free(&res);
// }

// #include <curl/curl.h>

int addressSearch(char *addressarray[], char searchvalue[])
{
	for (int i = 0; i < 30; ++i) {
		if (strcmp(addressarray[i], searchvalue) == 0) {
			return i;
		}
	}
	return -1;
}

static void scan_recv(const struct bt_le_scan_recv_info *info, struct net_buf_simple *ad)
{
	/* Check if the received advertisement is connectable */
	// if (!timeout_expired) {
	if (index < 29) {
		printk("%d", index);
		char addr[BT_ADDR_LE_STR_LEN];
		bt_addr_le_to_str(info->addr, addr, sizeof(addr));
		// occupancy_status(index);
		// THIS IS WHERE WE CALL THE OCCUPANCY STATUS FUNCTION

		if (info->adv_props & BT_GAP_ADV_PROP_CONNECTABLE) {
			// displays only connectable devices; can change

			printk("Connectable Device found: %s, RSSI: %d dBm\n", addr, info->rssi);

			// printk("IM DUMBO %s", substring_addr);

			// CURL *curl;
			// CURLcode response;

			// curl_global_init(CURL_GLOBAL_ALL);
			// curl = curl_easy_init();

			// if (curl) // if initializes basically
			// {
			// 	curl_easy_setopt(curl, CURLOPT_URL,
			// 			 "api.maclookup.app/v2/macs/" +
			// substring_addr); 	response = curl_easy_perform(curl);

			// 	if (response != CURLE_OK) {
			// 		printk(stderr, "Request failed: %s\n",
			// 		       curl_easy_strerror(response));
			// 	} else {
			// 		printk(response);
			// 	}

			// 	curl_easy_cleanup(curl);
			// }
			// curl_global_cleanup();
		} else {
			printk("Unconnectable Device found: %s, RSSI: %d dBm\n", addr, info->rssi);
		}
		// if (index < 50) {

		char *string_alloc = malloc((BT_ADDR_LE_STR_LEN + 1) * sizeof(char));
		if (string_alloc != NULL) {
			// Copy the string into the allocated memory
			strcpy(string_alloc, addr);
			string_alloc[BT_ADDR_LE_STR_LEN] = '\0'; // Ensure null termination

			// Store the pointer to the allocated string in the addresses array
			// printk("%s", string_alloc);
			// string_sub = string_alloc;
		}
		index_improve = addressSearch(addresses, string_alloc);
		// really bad style but trying to get it to compile right now
		uint64_t get_time = k_uptime_get(); // also in a bad location
		if (addressSearch(addresses, string_alloc) == -1) {
			rssi[++index] = info->rssi;
			addresses[index] =
				string_alloc; // would usually put this in the string_alloc != null
					      // block,but trying to compile right now, so i want a
					      // string that i know is null terminated.

			first_detected[index] = get_time;
			printk("%" PRIu64 "ms\n", get_time);
		} else {
			printk("ALREADY SEEN. THE INDEX IS: %d", index_improve);
			rssi[addressSearch(addresses, string_alloc)] = info->rssi;
		}
		// CHECK IF THE ADDRESS IS ALREADY SAVED HERE, AND I GUESS UPDATE THE PAYLOAD AS
		// WELL based on the condition. Can probably create a separate function.

		// after function call, verything created is popped, unless we dynamically allocate.
		//  string_sub = addr;
		//  addresses[index] = string_sub;
		// printk("NIHAOMA %s", addresses[index]);
		// printk("YA");
		insert(&hashTable, string_alloc, get_time);
		/* Parse and print advertising data */
		// just put them all in here, since we are only looking for 50. it should
		// make orint table.
		// }
		bt_data_parse(ad, print_adv_data, NULL);
	} else if (index == 29) {
		// printk("xiang ni hao");
		print_table();
		index++;
	}
	//  else {
	// 	free_table(&hashTable);
	// 	print_table();
	// }
}

static struct bt_le_scan_cb scan_cb = {
	.recv = scan_recv,
};

int bt_scan_start(enum bt_scan_type scan_type)
{
	switch (scan_type) {
	case BT_SCAN_TYPE_SCAN_ACTIVE:
		bt_scan.scan_param.type = BT_LE_SCAN_TYPE_ACTIVE;
		break;

	case BT_SCAN_TYPE_SCAN_PASSIVE:
		bt_scan.scan_param.type = BT_LE_SCAN_TYPE_PASSIVE;
		break;

	default:
		return -EINVAL;
	}

	/* Start the scanning. */
	int err = bt_le_scan_start(&bt_scan.scan_param, NULL);

	if (!err) {
		LOG_DBG("Scanning");
	}

	return err;
}

int bt_scan_params_set(struct bt_le_scan_param *scan_param)
{
	bt_scan_stop();

	if (scan_param) {
		/* Assign new scanning parameters. */
		bt_scan.scan_param = *scan_param;
	} else {
		/* If NULL, use the default static configuration. */
		scan_default_param_set();
	}

	LOG_DBG("Scanning parameters have been changed successfully");

	return 0;
}

#if CONFIG_BT_SCAN_BLOCKLIST
int bt_scan_blocklist_device_add(const bt_addr_le_t *addr)
{
	int err = 0;
	char addr_str[BT_ADDR_LE_STR_LEN];

	if (!addr) {
		return -EINVAL;
	}

	bt_addr_le_to_str(addr, addr_str, sizeof(addr_str));

	k_mutex_lock(&scan_mutex, K_FOREVER);

	/* Check if the device is already on the blocklist. */
	for (size_t i = 0; i < ARRAY_SIZE(bt_scan.blocklist.addr); i++) {
		if (bt_addr_le_cmp(&bt_scan.blocklist.addr[i], addr) == 0) {
			LOG_DBG("Device %s is already on the blocklist", addr_str);

			goto out;
		}
	}

	if (bt_scan.blocklist.count >= ARRAY_SIZE(bt_scan.blocklist.addr)) {
		LOG_ERR("No place for the new device");
		err = -ENOMEM;
	} else {
		bt_addr_le_copy(&bt_scan.blocklist.addr[bt_scan.blocklist.count], addr);
		bt_scan.blocklist.count++;
		LOG_INF("Device %s added to the scanning blocklist", addr_str);
	}

out:
	k_mutex_unlock(&scan_mutex);

	return err;
}

void bt_scan_blocklist_clear(void)
{
	k_mutex_lock(&scan_mutex, K_FOREVER);
	memset(&bt_scan.blocklist, 0, sizeof(bt_scan.blocklist));
	k_mutex_unlock(&scan_mutex);
}
#endif /* CONFIG_BT_SCAN_BLOCKLIST */

#if CONFIG_BT_SCAN_CONN_ATTEMPTS_FILTER
void bt_scan_conn_attempts_filter_clear(void)
{
	k_mutex_lock(&scan_mutex, K_FOREVER);
	memset(&bt_scan.attempts_filter, 0, sizeof(bt_scan.attempts_filter));
	k_mutex_unlock(&scan_mutex);
}
#endif /* CONFIG_BT_SCAN_CONN_ATTEMPTS_FILTER */

#if CONFIG_BT_CENTRAL
void bt_scan_update_connect_if_match(bool connect_if_match)
{
	bt_scan.connect_if_match = connect_if_match;
}
#endif /* CONFIG_BT_CENTRAL */
