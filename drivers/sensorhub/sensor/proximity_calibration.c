/*
 *  Copyright (C) 2020, Samsung Electronics Co. Ltd. All Rights Reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 */

#include "../sensormanager/shub_sensor.h"
#include "../sensormanager/shub_sensor_manager.h"
#include "../sensor/proximity.h"

#include <linux/slab.h>

void proximity_calibration_off(void)
{
	shub_infof("");
	disable_sensor(SENSOR_TYPE_PROXIMITY_CALIBRATION, NULL, 0);
}

void report_event_proximity_calibration(void)
{
	struct proximity_data *data = get_sensor(SENSOR_TYPE_PROXIMITY_CALIBRATION)->data;
	struct proximity_chipset_funcs *chipset_funcs = get_sensor(SENSOR_TYPE_PROXIMITY)->chipset_funcs;
	struct prox_cal_event *sensor_value =
	    (struct prox_cal_event *)(get_sensor_event(SENSOR_TYPE_PROXIMITY_CALIBRATION)->value);

	data->prox_threshold[0] = sensor_value->prox_cal[0];
	data->prox_threshold[1] = sensor_value->prox_cal[1];
	shub_infof("prox thresh %u %u", data->prox_threshold[0], data->prox_threshold[1]);

	proximity_calibration_off();

	if (chipset_funcs->pre_report_event_proximity)
		chipset_funcs->pre_report_event_proximity();
}

int init_proximity_calibration(bool en)
{
	struct shub_sensor *sensor = get_sensor(SENSOR_TYPE_PROXIMITY_CALIBRATION);

	if (!sensor)
		return 0;

	if (en) {
		strcpy(sensor->name, "proximity_calibration");
		sensor->hal_sensor = false;

		sensor->receive_event_size = 4;
		sensor->report_event_size = 0;
		sensor->event_buffer.value = kzalloc(sizeof(struct prox_cal_event), GFP_KERNEL);
		if (!sensor->event_buffer.value)
			goto err_no_mem;

		sensor->funcs = kzalloc(sizeof(struct sensor_funcs), GFP_KERNEL);
		if (!sensor->funcs)
			goto err_no_mem;

		sensor->data = get_sensor(SENSOR_TYPE_PROXIMITY)->data;
		sensor->funcs->report_event = report_event_proximity_calibration;
	} else {
		kfree(sensor->event_buffer.value);
		sensor->event_buffer.value = NULL;

		kfree(sensor->funcs);
		sensor->funcs = NULL;
	}

	return 0;

err_no_mem:
	kfree(sensor->event_buffer.value);
	sensor->event_buffer.value = NULL;

	kfree(sensor->funcs);
	sensor->funcs = NULL;

	return -ENOMEM;
}
