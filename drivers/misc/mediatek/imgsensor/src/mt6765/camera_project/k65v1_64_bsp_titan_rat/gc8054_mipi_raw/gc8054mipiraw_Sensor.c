// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2020 MediaTek Inc.
 */

#include <linux/videodev2.h>
#include <linux/i2c.h>
#include <linux/platform_device.h>
#include <linux/delay.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/atomic.h>
#include <linux/types.h>

#include "kd_camera_typedef.h"
#include "kd_imgsensor.h"
#include "kd_imgsensor_define.h"
#include "kd_imgsensor_errcode.h"
//#include "imgsensor_common.h"

#include "gc8054mipiraw_Sensor.h"

/************************** Modify Following Strings for Debug **************************/
#define PFX "GC8054_camera_sensor"
#define LOG_1 LOG_INF("GC8054MIPI, 4LANE\n")
/****************************   Modify end    *******************************************/
#define GC8054_DEBUG
#if defined(GC8054_DEBUG)
#define LOG_INF(format, args...)    pr_info(PFX "[%s] " format, __func__, ##args)
#else
#define LOG_INF(format, args...)
#endif

#ifndef VENDOR_EDIT
#define VENDOR_EDIT
#endif

static DEFINE_SPINLOCK(imgsensor_drv_lock);

static kal_uint32 Dgain_ratio = 256;

static struct imgsensor_info_struct imgsensor_info = {
	.sensor_id = GC8054_SENSOR_ID,    /*record sensor id defined in Kd_imgsensor.h*/
	.checksum_value = 0xcde448ca,         /*checksum value for Camera Auto Test*/

	.pre = {
		.pclk = 403000000,
		.linelength = 5248,
		.framelength = 2532,
		.startx = 0,
		.starty = 0,
		.grabwindow_width = 3264,
		.grabwindow_height = 2448,
		.mipi_data_lp2hs_settle_dc = 85,
		.mipi_pixel_rate = 268640000,
		.max_framerate = 300,
	},
	.cap = {
		.pclk = 403000000,
		.linelength = 5248,
		.framelength = 2532,
		.startx = 0,
		.starty = 0,
		.grabwindow_width = 3264,
		.grabwindow_height = 2448,
		.mipi_data_lp2hs_settle_dc = 85,
		.mipi_pixel_rate = 268640000,
		.max_framerate = 300,
	},
	.normal_video = {
		.pclk = 403000000,
		.linelength = 5248,
		.framelength = 2532,
		.startx = 0,
		.starty = 0,
		.grabwindow_width = 3264,
		.grabwindow_height = 1836,
		.mipi_data_lp2hs_settle_dc = 85,
		.mipi_pixel_rate = 268640000,
		.max_framerate = 300,
	},
	.hs_video = {
		.pclk = 179400000,
		.linelength = 2936,
		.framelength = 508,
		.startx = 0,
		.starty = 0,
		.grabwindow_width = 576,
		.grabwindow_height = 432,
		.mipi_data_lp2hs_settle_dc = 85,
		.mipi_pixel_rate = 89700000,
		.max_framerate = 1200,
	},
	.slim_video = {
		.pclk = 179400000,
		.linelength = 2936,
		.framelength = 508,
		.startx = 0,
		.starty = 0,
		.grabwindow_width = 576,
		.grabwindow_height = 432,
		.mipi_data_lp2hs_settle_dc = 85,
		.mipi_pixel_rate = 89700000,
		.max_framerate = 1200,
	},
	.custom1 = {
		.pclk = 179400000,
		.linelength = 2936,
		.framelength = 508,
		.startx = 0,
		.starty = 0,
		.grabwindow_width = 576,
		.grabwindow_height = 432,
		.mipi_data_lp2hs_settle_dc = 85,
		.mipi_pixel_rate = 89700000,
		.max_framerate = 1200,
	},
	.margin = 16,
	/*sensor framelength & shutter margin*/
	.min_shutter = 4,                                       /*min shutter*/
	.max_frame_length = 0x3fff,
	/*max framelength by sensor register's limitation*/     /*5fps*/
	.ae_shut_delay_frame = 0,
	/*shutter delay frame for AE cycle, 2 frame with ispGain_delay-shut_delay=2-0=2*/
	.ae_sensor_gain_delay_frame = 0,
	/*sensor gain delay frame for AE cycle, 2 frame with ispGain_delay-sensor_gain_delay=2-0=2*/
	 /*isp gain delay frame for AE cycle*/
	.ae_ispGain_delay_frame = 2,
	.ihdr_support = 0,                                      /*1 support; 0 not support*/
	.ihdr_le_firstline = 0,                                 /*1 le first ; 0, se first*/
	.sensor_mode_num = 6,                                   /*support sensor mode num*/

	.cap_delay_frame = 2,                                   /*enter capture delay frame num*/
	.pre_delay_frame = 2,                                   /*enter preview delay frame num*/
	.video_delay_frame = 2,                                 /*enter video delay frame num*/
	/*enter high speed video  delay frame num*/
	.hs_video_delay_frame = 2,
	.slim_video_delay_frame = 2,                            /*enter slim video delay frame num*/
	.custom1_delay_frame = 2,                               /*enter custom1 delay frame num*/
	.frame_time_delay_frame = 2,                            /*enter custom1 delay frame num*/

	.isp_driving_current = ISP_DRIVING_4MA,                 /*mclk driving current*/
	.sensor_interface_type = SENSOR_INTERFACE_TYPE_MIPI,    /*sensor_interface_type*/
	/*0,MIPI_OPHY_NCSI2;  1,MIPI_OPHY_CSI2*/
	.mipi_sensor_type = MIPI_OPHY_NCSI2,
	.mipi_settle_delay_mode = MIPI_SETTLEDELAY_AUTO,
	/*0,MIPI_SETTLEDELAY_AUTO; 1,MIPI_SETTLEDELAY_MANNUAL*/

	.sensor_output_dataformat = SENSOR_OUTPUT_FORMAT_RAW_Gr,
	/*sensor output first pixel color*/

	.mclk = 26,
	/*mclk value, suggest 24 or 26 for 24Mhz or 26Mhz*/
	.mipi_lane_num = SENSOR_MIPI_4_LANE,                    /*mipi lane num*/
	.i2c_addr_table = {0x62, 0xff},
	/*record sensor support all write id addr, only supprt 4must end with 0xff*/
};

static struct imgsensor_struct imgsensor = {
	.mirror = IMAGE_NORMAL,       /*mirrorflip information*/
	.sensor_mode = IMGSENSOR_MODE_INIT,
	/*IMGSENSOR_MODE enum value, record current sensor mode,*/
	/*such as: INIT, Preview, Capture, Video,High Speed Video, Slim Video*/
	.shutter = 0x258,             /*current shutter*/
	.gain = 0x40,                 /*current gain*/
	.dummy_pixel = 0,             /*current dummypixel*/
	.dummy_line = 0,              /*current dummyline*/
	/* full size current fps*/
	/* 24fps for PIP, 30fps for Normal or ZSD*/
	.current_fps = 300,
	.autoflicker_en = KAL_FALSE,
	/* auto flicker enable: KAL_FALSE for disable auto flicker*/
	/* KAL_TRUE for enable auto flicker*/
	.test_pattern = KAL_FALSE,
	/*test pattern mode or not KAL_FALSE for in test pattern mode, KAL_TRUE for normal output*/
	.current_scenario_id = MSDK_SCENARIO_ID_CAMERA_PREVIEW, /*current scenario id*/
	.ihdr_en = 0,                 /*sensor need support LE, SE with HDR feature*/
	.i2c_write_id = 0x62,         /*record current sensor's i2c write id*/
};

/* Sensor output window information */
static struct SENSOR_WINSIZE_INFO_STRUCT imgsensor_winsize_info[6] = {
	{ 3280, 2460,    0,    0, 3280, 2460, 3280, 2460,
		 8,    6, 3264, 2448,    0,    0, 3264, 2448 }, /*preview*/
	{ 3280, 2460,    0,    0, 3280, 2460, 3280, 2460,
		 8,    6, 3264, 2448,    0,    0, 3264, 2448 }, /*capture*/
	{ 3280, 2460,    0,    0, 3280, 2460, 3280, 2460,
		 8,  312, 3264, 1836,    0,    0, 3264, 1836 }, /*video*/
	{ 2608, 1960,    0,    0, 2608, 1960, 1304,  980,
	   363,   26,  576,  432,    0,    0,  576,  432 }, /*hs video*/
	{ 2608, 1960,    0,    0, 2608, 1960, 1304,  980,
	   363,   26,  576,  432,    0,    0,  576,  432 }, /*sl video*/
	{ 2608, 1960,    0,    0, 2608, 1960, 1304,  980,
	   363,   26,  576,  432,    0,    0,  576,  432 } /*custom1*/
};

//static struct gc8054_otp gc8054_otp_data = { 0 };
static kal_uint16 read_cmos_sensor(kal_uint16 addr)
{
	kal_uint16 get_byte = 0;
	char pusendcmd[2] = {(char)(addr >> 8), (char)(addr & 0xFF) };

	iReadRegI2C(pusendcmd, 2, (u8 *)&get_byte, 1, imgsensor.i2c_write_id);
	return get_byte;
}


static void write_cmos_sensor(kal_uint16 addr, kal_uint8 para)
{
	char pusendcmd[3] = {
		(char)(addr >> 8), (char)(addr & 0xFF), (char)(para & 0xFF)};

	iWriteRegI2C(pusendcmd, 3, imgsensor.i2c_write_id);
}

static void set_dummy(void)
{
	kal_uint32 frame_length = imgsensor.frame_length >> 2;

	frame_length = frame_length << 2;
	write_cmos_sensor(0x0340, (frame_length >> 8) & 0x3f);
	write_cmos_sensor(0x0341, frame_length & 0xff);
	LOG_INF("Exit! framelength = %d\n", frame_length);
}

static kal_uint32 return_sensor_id(void)
{
	kal_uint32 rtn_id = 0, i = 0;
	kal_uint32 idg[8] = {
		0x8054, 0x5045, 0x5055, 0x5065,
		0x5075, 0x5085, 0x5095, 0x50a5
	};
	rtn_id = (read_cmos_sensor(0x03f0) << 8) | read_cmos_sensor(0x03f1);
	LOG_INF("Sensor ID = 0x%x\n", rtn_id);
	for (i = 0; i < 8; i++) {
		if (rtn_id == idg[i])
			return 0x8054;
	}
	return 0;
}

static void set_max_framerate(UINT16 framerate, kal_bool min_framelength_en)
{
	kal_uint32 frame_length = imgsensor.frame_length;

	frame_length = imgsensor.pclk / framerate * 10 / imgsensor.line_length;

	spin_lock(&imgsensor_drv_lock);
	imgsensor.frame_length = (frame_length > imgsensor.min_frame_length)
		? frame_length : imgsensor.min_frame_length;
	imgsensor.dummy_line = imgsensor.frame_length - imgsensor.min_frame_length;
	if (imgsensor.frame_length > imgsensor_info.max_frame_length) {
		imgsensor.frame_length = imgsensor_info.max_frame_length;
		imgsensor.dummy_line = imgsensor.frame_length - imgsensor.min_frame_length;
	}
	LOG_INF("framelength = %d\n", imgsensor.frame_length);
	if (min_framelength_en)
		imgsensor.min_frame_length = imgsensor.frame_length;
	spin_unlock(&imgsensor_drv_lock);
	set_dummy();
}

/*************************************************************************
 * FUNCTION
 *    set_shutter
 *
 * DESCRIPTION
 *    This function set e-shutter of sensor to change exposure time.
 *
 * PARAMETERS
 *    iShutter : exposured lines
 *
 * RETURNS
 *    None
 *
 * GLOBALS AFFECTED
 *
 *************************************************************************/
static void set_shutter(kal_uint16 shutter)
{
	unsigned long flags;
	kal_uint16 realtime_fps = 0, cal_shutter = 0;

	spin_lock_irqsave(&imgsensor_drv_lock, flags);
	imgsensor.shutter = shutter;
	spin_unlock_irqrestore(&imgsensor_drv_lock, flags);

	/*if shutter bigger than frame_length, should extend frame length first*/
	spin_lock(&imgsensor_drv_lock);
	if (shutter > imgsensor.min_frame_length - imgsensor_info.margin)
		imgsensor.frame_length = shutter + imgsensor_info.margin;
	else
		imgsensor.frame_length = imgsensor.min_frame_length;

	if (imgsensor.frame_length > imgsensor_info.max_frame_length)
		imgsensor.frame_length = imgsensor_info.max_frame_length;

	spin_unlock(&imgsensor_drv_lock);
	shutter = (shutter < imgsensor_info.min_shutter) ? imgsensor_info.min_shutter : shutter;
	shutter = (shutter > (imgsensor_info.max_frame_length - imgsensor_info.margin)) ?
		(imgsensor_info.max_frame_length - imgsensor_info.margin) : shutter;

	realtime_fps = imgsensor.pclk / imgsensor.line_length * 10 / imgsensor.frame_length;

	if (imgsensor.autoflicker_en) {
		if (realtime_fps >= 297 && realtime_fps <= 305)
			set_max_framerate(296, 0);
		else if (realtime_fps >= 147 && realtime_fps <= 150)
			set_max_framerate(146, 0);
		else
			set_max_framerate(realtime_fps, 0);
	} else {
		set_max_framerate(realtime_fps, 0);
	}

	cal_shutter = shutter >> 2;
	cal_shutter = cal_shutter << 2;
	Dgain_ratio = 256 * shutter / cal_shutter;

	write_cmos_sensor(0x0202, (cal_shutter >> 8) & 0x3F);
	write_cmos_sensor(0x0203, cal_shutter & 0xFF);

	LOG_INF("Exit! shutter = %d, framelength = %d\n", shutter, imgsensor.frame_length);
	LOG_INF("Exit! cal_shutter = %d, ", cal_shutter);
}

static void set_shutter_frame_length(kal_uint16 shutter, kal_uint16 frame_length)
{
	unsigned long flags;
	kal_uint16 realtime_fps = 0, cal_shutter = 0;
	kal_int32 dummy_line = 0;

	spin_lock_irqsave(&imgsensor_drv_lock, flags);
	imgsensor.shutter = shutter;
	spin_unlock_irqrestore(&imgsensor_drv_lock, flags);

	/*if shutter bigger than frame_length, should extend frame length first*/
	spin_lock(&imgsensor_drv_lock);
	if (frame_length > 1)
		dummy_line = frame_length - imgsensor.frame_length;
	imgsensor.frame_length = imgsensor.frame_length + dummy_line;

	if (shutter > imgsensor.frame_length - imgsensor_info.margin)
		imgsensor.frame_length = shutter + imgsensor_info.margin;

	if (imgsensor.frame_length > imgsensor_info.max_frame_length)
		imgsensor.frame_length = imgsensor_info.max_frame_length;

	spin_unlock(&imgsensor_drv_lock);
	shutter = (shutter < imgsensor_info.min_shutter) ? imgsensor_info.min_shutter : shutter;
	shutter = (shutter > (imgsensor_info.max_frame_length - imgsensor_info.margin)) ?
		(imgsensor_info.max_frame_length - imgsensor_info.margin) : shutter;

	realtime_fps = imgsensor.pclk / imgsensor.line_length * 10 / imgsensor.frame_length;

	if (imgsensor.autoflicker_en) {
		if (realtime_fps >= 297 && realtime_fps <= 305)
			set_max_framerate(296, 0);
		else if (realtime_fps >= 147 && realtime_fps <= 150)
			set_max_framerate(146, 0);
		else
			set_max_framerate(realtime_fps, 0);
	} else
		set_max_framerate(realtime_fps, 0);

	cal_shutter = shutter >> 2;
	cal_shutter = cal_shutter << 2;
	Dgain_ratio = 256 * shutter / cal_shutter;

	write_cmos_sensor(0x0202, (cal_shutter >> 8) & 0x3F);
	write_cmos_sensor(0x0203, cal_shutter & 0xFF);

	LOG_INF("Exit! shutter = %d, framelength = %d\n", shutter, imgsensor.frame_length);
	LOG_INF("Exit! cal_shutter = %d, ", cal_shutter);
}

static kal_uint16 gain2reg(const kal_uint16 gain)
{
	kal_uint16 reg_gain = gain << 2;

	if (reg_gain < SENSOR_BASE_GAIN)
		reg_gain = SENSOR_BASE_GAIN;
	else if (reg_gain > SENSOR_MAX_GAIN)
		reg_gain = SENSOR_MAX_GAIN;

	return (kal_uint16)reg_gain;
}

/*************************************************************************
 * FUNCTION
 *    set_gain
 *
 * DESCRIPTION
 *    This function is to set global gain to sensor.
 *
 * PARAMETERS
 *    iGain : sensor global gain(base: 0x40)
 *
 * RETURNS
 *    the actually gain set to sensor.
 *
 * GLOBALS AFFECTED
 *
 *************************************************************************/
static kal_uint16 set_gain(kal_uint16 gain)
{
	kal_uint16 reg_gain;
	kal_uint32 temp_gain;
	kal_int16 gain_index;
	kal_uint16 GC8054_AGC_Param[MAX_GAIN_INDEX][2] = {
		{  256,  0 },
		{  302,  1 },
		{  358,  2 },
		{  425,  3 },
		{  502,  8 },
		{  599,  9 },
		{  717, 10 },
		{  845, 11 },
		{ 998,  12 },
		{ 1203, 13 },
		{ 1434, 14 },
		{ 1710, 15 },
		{ 1997, 16 },
		{ 2355, 17 },
		{ 2816, 18 },
		{ 3318, 19 },
		{ 3994, 20 },
	};

	reg_gain = gain2reg(gain);

	for (gain_index = E_GAIN_INDEX - 1; gain_index >= 0; gain_index--) {
		if (reg_gain >= GC8054_AGC_Param[gain_index][0])
			break;
	}

	//write_cmos_sensor(0xfe, 0x00);
	//write_cmos_sensor(0xb6, GC8054_AGC_Param[gain_index][1]);
	temp_gain = reg_gain * Dgain_ratio / GC8054_AGC_Param[gain_index][0];
	//write_cmos_sensor(0xb1, (temp_gain >> 8) & 0x0f);
	//write_cmos_sensor(0xb2, temp_gain & 0xfc);
	LOG_INF("Exit! GC8054_AGC_Param[gain_index][1] = 0x%x, temp_gain = 0x%x, reg_gain = %d\n",
		GC8054_AGC_Param[gain_index][1], temp_gain, reg_gain);

	return reg_gain;
}

static void ihdr_write_shutter_gain(kal_uint16 le, kal_uint16 se, kal_uint16 gain)
{
	LOG_INF("le: 0x%x, se: 0x%x, gain: 0x%x\n", le, se, gain);
}

/*************************************************************************
 * FUNCTION
 *    night_mode
 *
 * DESCRIPTION
 *    This function night mode of sensor.
 *
 * PARAMETERS
 *    bEnable: KAL_TRUE -> enable night mode, otherwise, disable night mode
 *
 * RETURNS
 *    None
 *
 * GLOBALS AFFECTED
 *
 *************************************************************************/
static void night_mode(kal_bool enable)
{
	/* No Need to implement this function */
}

static kal_uint32 streaming_control(kal_bool enable)
{
	LOG_INF("streaming_enable(0=Sw Standby,1=streaming): %d\n", enable);
	if (enable) {
		write_cmos_sensor(0x0102, 0x09);
		mDELAY(10);
	} else {
		write_cmos_sensor(0x0102, 0x00);
		mDELAY(10);
	}
	return ERROR_NONE;
}

static void sensor_init(void)
{
	pr_info("GC8054_sensor_init\n");
	write_cmos_sensor(0x031c, 0x60);
	write_cmos_sensor(0x0320, 0xbb);
	write_cmos_sensor(0x0337, 0x06);
	write_cmos_sensor(0x0335, 0x51);
	write_cmos_sensor(0x0336, 0x9b);
	write_cmos_sensor(0x031a, 0x00);
	write_cmos_sensor(0x0321, 0x10);
	write_cmos_sensor(0x0327, 0x06);
	write_cmos_sensor(0x0325, 0x41);
	write_cmos_sensor(0x0326, 0x5d);
	write_cmos_sensor(0x0314, 0x01);
	write_cmos_sensor(0x0315, 0xe9);
	write_cmos_sensor(0x0317, 0x00);
	write_cmos_sensor(0x0115, 0x30);
	write_cmos_sensor(0x0180, 0x67);
	write_cmos_sensor(0x0334, 0x40);
	write_cmos_sensor(0x0324, 0x44);
	write_cmos_sensor(0x031c, 0x00);
	write_cmos_sensor(0x031c, 0x9f);
	write_cmos_sensor(0x0288, 0x03);
	write_cmos_sensor(0x0084, 0x30);
	write_cmos_sensor(0x0265, 0x00);
	write_cmos_sensor(0x04e0, 0x01);
	write_cmos_sensor(0x0100, 0x01);
	write_cmos_sensor(0x0101, 0x00);
	write_cmos_sensor(0x0342, 0x05);
	write_cmos_sensor(0x0343, 0x20);
	write_cmos_sensor(0x0344, 0x00);
	write_cmos_sensor(0x0345, 0x06);
	write_cmos_sensor(0x0346, 0x00);
	write_cmos_sensor(0x0347, 0x04);
	write_cmos_sensor(0x0348, 0x0c);
	write_cmos_sensor(0x0349, 0xd0);
	write_cmos_sensor(0x034a, 0x09);
	write_cmos_sensor(0x034b, 0x9c);
	write_cmos_sensor(0x0257, 0x06);
	write_cmos_sensor(0x0290, 0x00);
	write_cmos_sensor(0x0291, 0x00);
	write_cmos_sensor(0x0292, 0x28);
	write_cmos_sensor(0x0295, 0x10);
	write_cmos_sensor(0x0213, 0x12);
	write_cmos_sensor(0x02a9, 0x18);
	write_cmos_sensor(0x0221, 0x22);
	write_cmos_sensor(0x028b, 0x18);
	write_cmos_sensor(0x028c, 0x18);
	write_cmos_sensor(0x0229, 0x64);
	write_cmos_sensor(0x024b, 0x16);
	write_cmos_sensor(0x0255, 0x21);
	write_cmos_sensor(0x0280, 0x38);
	write_cmos_sensor(0x0500, 0x18);
	write_cmos_sensor(0x0501, 0xd0);
	write_cmos_sensor(0x0502, 0x15);
	write_cmos_sensor(0x0211, 0x02);
	write_cmos_sensor(0x0216, 0x06);
	write_cmos_sensor(0x0219, 0x08);
	write_cmos_sensor(0x021a, 0x04);
	write_cmos_sensor(0x021f, 0x10);
	write_cmos_sensor(0x0224, 0x00);
	write_cmos_sensor(0x0234, 0x00);
	write_cmos_sensor(0x0220, 0x15);
	write_cmos_sensor(0x024a, 0x02);
	write_cmos_sensor(0x0281, 0x30);
	write_cmos_sensor(0x0282, 0x13);
	write_cmos_sensor(0x028d, 0x92);
	write_cmos_sensor(0x028f, 0x01);
	write_cmos_sensor(0x0390, 0x6f);
	write_cmos_sensor(0x0392, 0x5c);
	write_cmos_sensor(0x0394, 0x20);
	write_cmos_sensor(0x039a, 0x90);
	write_cmos_sensor(0x0506, 0x19);
	write_cmos_sensor(0x0514, 0x00);
	write_cmos_sensor(0x0515, 0x1c);
	write_cmos_sensor(0x031c, 0x80);
	write_cmos_sensor(0x03fe, 0x10);
	write_cmos_sensor(0x03fe, 0x00);
	write_cmos_sensor(0x031c, 0x9f);
	write_cmos_sensor(0x03fe, 0x00);
	write_cmos_sensor(0x03fe, 0x00);
	write_cmos_sensor(0x03fe, 0x00);
	write_cmos_sensor(0x03fe, 0x00);
	write_cmos_sensor(0x031c, 0x80);
	write_cmos_sensor(0x03fe, 0x10);
	write_cmos_sensor(0x03fe, 0x00);
	write_cmos_sensor(0x031c, 0x9f);
	write_cmos_sensor(0x0360, 0x01);
	write_cmos_sensor(0x0360, 0x00);
	write_cmos_sensor(0x0317, 0x08);
	write_cmos_sensor(0x0a67, 0x80);
	write_cmos_sensor(0x0313, 0x00);
	write_cmos_sensor(0x0a54, 0x04);
	write_cmos_sensor(0x0a65, 0x05);
	write_cmos_sensor(0x0a68, 0x11);
	write_cmos_sensor(0x0a59, 0x00);
	write_cmos_sensor(0x00be, 0x00);
	write_cmos_sensor(0x00a9, 0x01);
	write_cmos_sensor(0x00d7, 0xd0);
	write_cmos_sensor(0x00d8, 0x0c);
	write_cmos_sensor(0x009c, 0x09);
	write_cmos_sensor(0x009d, 0x9c);
	write_cmos_sensor(0x009e, 0x0c);
	write_cmos_sensor(0x009f, 0xd0);
	write_cmos_sensor(0x0a82, 0x00);
	write_cmos_sensor(0x0a83, 0x88);
	write_cmos_sensor(0x0a84, 0x10);
	write_cmos_sensor(0x0a85, 0x10);
	write_cmos_sensor(0x0a88, 0x0a);
	write_cmos_sensor(0x0a89, 0x0d);
	write_cmos_sensor(0x0a8a, 0x20);
	write_cmos_sensor(0x0a71, 0x52);
	write_cmos_sensor(0x0a72, 0x12);
	write_cmos_sensor(0x0a73, 0x60);
	write_cmos_sensor(0x0a75, 0x41);
	write_cmos_sensor(0x0a70, 0x07);
	write_cmos_sensor(0x0313, 0x80);
	write_cmos_sensor(0x0080, 0xd0);
	write_cmos_sensor(0x0087, 0x51);
	write_cmos_sensor(0x0089, 0x03);
	write_cmos_sensor(0x0096, 0x82);
	write_cmos_sensor(0x0040, 0x22);
	write_cmos_sensor(0x0041, 0x20);
	write_cmos_sensor(0x0043, 0x05);
	write_cmos_sensor(0x0044, 0x00);
	write_cmos_sensor(0x0046, 0x08);
	write_cmos_sensor(0x0048, 0x01);
	write_cmos_sensor(0x0049, 0xf0);
	write_cmos_sensor(0x004a, 0x0f);
	write_cmos_sensor(0x004c, 0x0f);
	write_cmos_sensor(0x004d, 0x00);
	write_cmos_sensor(0x0414, 0x80);
	write_cmos_sensor(0x0415, 0x80);
	write_cmos_sensor(0x0416, 0x80);
	write_cmos_sensor(0x0417, 0x80);
	write_cmos_sensor(0x009a, 0x40);
	write_cmos_sensor(0x00c0, 0x80);
	write_cmos_sensor(0x00c1, 0x80);
	write_cmos_sensor(0x00c2, 0x02);
	write_cmos_sensor(0x0470, 0x04);
	write_cmos_sensor(0x0471, 0x1c);
	write_cmos_sensor(0x0472, 0x14);
	write_cmos_sensor(0x0473, 0x12);
	write_cmos_sensor(0x0474, 0x1a);
	write_cmos_sensor(0x0475, 0x1a);
	write_cmos_sensor(0x0476, 0x18);
	write_cmos_sensor(0x0477, 0x16);
	write_cmos_sensor(0x0480, 0x03);
	write_cmos_sensor(0x0481, 0x03);
	write_cmos_sensor(0x0482, 0x03);
	write_cmos_sensor(0x0483, 0x03);
	write_cmos_sensor(0x0484, 0x04);
	write_cmos_sensor(0x0485, 0x04);
	write_cmos_sensor(0x0486, 0x04);
	write_cmos_sensor(0x0487, 0x04);
	write_cmos_sensor(0x0478, 0x04);
	write_cmos_sensor(0x0479, 0x10);
	write_cmos_sensor(0x047a, 0x26);
	write_cmos_sensor(0x047b, 0x38);
	write_cmos_sensor(0x047c, 0x10);
	write_cmos_sensor(0x047d, 0x20);
	write_cmos_sensor(0x047e, 0x30);
	write_cmos_sensor(0x047f, 0x60);
	write_cmos_sensor(0x0488, 0x04);
	write_cmos_sensor(0x0489, 0x04);
	write_cmos_sensor(0x048a, 0x04);
	write_cmos_sensor(0x048b, 0x04);
	write_cmos_sensor(0x048c, 0x03);
	write_cmos_sensor(0x048d, 0x03);
	write_cmos_sensor(0x048e, 0x03);
	write_cmos_sensor(0x048f, 0x03);
}

static void preview_setting(void)
{
	pr_info("GC8054 preview - E!\n");
	write_cmos_sensor(0x031c, 0x60);
	write_cmos_sensor(0x0320, 0xbb);
	write_cmos_sensor(0x0337, 0x06);
	write_cmos_sensor(0x0335, 0x51);
	write_cmos_sensor(0x0336, 0x9b);
	write_cmos_sensor(0x031a, 0x00);
	write_cmos_sensor(0x0321, 0x10);
	write_cmos_sensor(0x0327, 0x06);
	write_cmos_sensor(0x0325, 0x41);
	write_cmos_sensor(0x0326, 0x5d);
	write_cmos_sensor(0x0314, 0x01);
	write_cmos_sensor(0x0315, 0xe9);
	write_cmos_sensor(0x0317, 0x00);
	write_cmos_sensor(0x0115, 0x30);
	write_cmos_sensor(0x0180, 0x67);
	write_cmos_sensor(0x0334, 0x40);
	write_cmos_sensor(0x0324, 0x44);
	write_cmos_sensor(0x031c, 0x00);
	write_cmos_sensor(0x031c, 0x9f);
	write_cmos_sensor(0x0202, 0x09);
	write_cmos_sensor(0x0203, 0x00);
	write_cmos_sensor(0x0340, 0x09);
	write_cmos_sensor(0x0341, 0xe4);
	write_cmos_sensor(0x0342, 0x05);
	write_cmos_sensor(0x0343, 0x20);
	write_cmos_sensor(0x0344, 0x00);
	write_cmos_sensor(0x0345, 0x06);
	write_cmos_sensor(0x0346, 0x00);
	write_cmos_sensor(0x0347, 0x04);
	write_cmos_sensor(0x0348, 0x0c);
	write_cmos_sensor(0x0349, 0xd0);
	write_cmos_sensor(0x034a, 0x09);
	write_cmos_sensor(0x034b, 0x9c);
	write_cmos_sensor(0x0291, 0x00);
	write_cmos_sensor(0x0292, 0x28);
	write_cmos_sensor(0x0213, 0x12);
	write_cmos_sensor(0x02a9, 0x18);
	write_cmos_sensor(0x0221, 0x22);
	write_cmos_sensor(0x028b, 0x18);
	write_cmos_sensor(0x028c, 0x18);
	write_cmos_sensor(0x0229, 0x64);
	write_cmos_sensor(0x024b, 0x16);
	write_cmos_sensor(0x0255, 0x21);
	write_cmos_sensor(0x0280, 0x38);
	write_cmos_sensor(0x021f, 0x10);
	write_cmos_sensor(0x0224, 0x00);
	write_cmos_sensor(0x0234, 0x00);
	write_cmos_sensor(0x024a, 0x02);
	write_cmos_sensor(0x0282, 0x13);
	write_cmos_sensor(0x028d, 0x92);
	write_cmos_sensor(0x039a, 0x90);
	write_cmos_sensor(0x031c, 0x80);
	write_cmos_sensor(0x03fe, 0x10);
	write_cmos_sensor(0x03fe, 0x00);
	write_cmos_sensor(0x031c, 0x9f);
	write_cmos_sensor(0x03fe, 0x00);
	write_cmos_sensor(0x03fe, 0x00);
	write_cmos_sensor(0x03fe, 0x00);
	write_cmos_sensor(0x03fe, 0x00);
	write_cmos_sensor(0x031c, 0x80);
	write_cmos_sensor(0x03fe, 0x10);
	write_cmos_sensor(0x03fe, 0x00);
	write_cmos_sensor(0x031c, 0x9f);
	write_cmos_sensor(0x00d3, 0x00);
	write_cmos_sensor(0x00d4, 0x00);
	write_cmos_sensor(0x00d5, 0x00);
	write_cmos_sensor(0x00d6, 0x00);
	write_cmos_sensor(0x05a0, 0x83);
	write_cmos_sensor(0x05a3, 0x06);
	write_cmos_sensor(0x05a4, 0x04);
	write_cmos_sensor(0x0597, 0x27);
	write_cmos_sensor(0x059a, 0x00);
	write_cmos_sensor(0x059b, 0x00);
	write_cmos_sensor(0x059c, 0x01);
	write_cmos_sensor(0x05ab, 0x09);
	write_cmos_sensor(0x05ae, 0x00);
	write_cmos_sensor(0x05af, 0x00);
	write_cmos_sensor(0x05ac, 0x00);
	write_cmos_sensor(0x05ad, 0x01);
	write_cmos_sensor(0x05b1, 0x03);
	write_cmos_sensor(0x05b1, 0x04);
	write_cmos_sensor(0x05b1, 0x05);
	write_cmos_sensor(0x05b1, 0x0c);
	write_cmos_sensor(0x05b1, 0x1c);
	write_cmos_sensor(0x05b1, 0x05);
	write_cmos_sensor(0x05b1, 0x12);
	write_cmos_sensor(0x05b1, 0x05);
	write_cmos_sensor(0x05b1, 0x00);
	write_cmos_sensor(0x05b1, 0x05);
	write_cmos_sensor(0x05b1, 0x06);
	write_cmos_sensor(0x05b1, 0x05);
	write_cmos_sensor(0x05b1, 0x14);
	write_cmos_sensor(0x05b1, 0x18);
	write_cmos_sensor(0x05b1, 0x18);
	write_cmos_sensor(0x05b1, 0x19);
	write_cmos_sensor(0x05b1, 0x40);
	write_cmos_sensor(0x05b1, 0x14);
	write_cmos_sensor(0x05b1, 0x38);
	write_cmos_sensor(0x05b1, 0x29);
	write_cmos_sensor(0x05b1, 0x40);
	write_cmos_sensor(0x05b1, 0x08);
	write_cmos_sensor(0x05b1, 0x38);
	write_cmos_sensor(0x05b1, 0x29);
	write_cmos_sensor(0x05b1, 0x40);
	write_cmos_sensor(0x05b1, 0x08);
	write_cmos_sensor(0x05b1, 0x38);
	write_cmos_sensor(0x05b1, 0x29);
	write_cmos_sensor(0x05b1, 0x00);
	write_cmos_sensor(0x05b1, 0x08);
	write_cmos_sensor(0x05b1, 0x68);
	write_cmos_sensor(0x05b1, 0x41);
	write_cmos_sensor(0x05b1, 0x00);
	write_cmos_sensor(0x05b1, 0x08);
	write_cmos_sensor(0x05b1, 0x88);
	write_cmos_sensor(0x05b1, 0x51);
	write_cmos_sensor(0x05b1, 0x00);
	write_cmos_sensor(0x05b1, 0x00);
	write_cmos_sensor(0x05b1, 0x00);
	write_cmos_sensor(0x05b1, 0x01);
	write_cmos_sensor(0x05b1, 0x00);
	write_cmos_sensor(0x05b1, 0x01);
	write_cmos_sensor(0x05b1, 0x00);
	write_cmos_sensor(0x05b1, 0x00);
	write_cmos_sensor(0x05b1, 0x00);
	write_cmos_sensor(0x05b1, 0x01);
	write_cmos_sensor(0x05b1, 0x94);
	write_cmos_sensor(0x05b1, 0x03);
	write_cmos_sensor(0x05b1, 0x01);
	write_cmos_sensor(0x05b1, 0x02);
	write_cmos_sensor(0x05b1, 0x00);
	write_cmos_sensor(0x05b1, 0x00);
	write_cmos_sensor(0x05b1, 0x02);
	write_cmos_sensor(0x05b1, 0x02);
	write_cmos_sensor(0x05b1, 0xd9);
	write_cmos_sensor(0x05b1, 0x00);
	write_cmos_sensor(0x05b1, 0x03);
	write_cmos_sensor(0x05b1, 0x03);
	write_cmos_sensor(0x05b1, 0xf8);
	write_cmos_sensor(0x05b1, 0x00);
	write_cmos_sensor(0x05b1, 0x04);
	write_cmos_sensor(0x05b1, 0x05);
	write_cmos_sensor(0x05b1, 0x9e);
	write_cmos_sensor(0x05b1, 0x00);
	write_cmos_sensor(0x05b1, 0x05);
	write_cmos_sensor(0x05b1, 0x07);
	write_cmos_sensor(0x05b1, 0xf0);
	write_cmos_sensor(0x05b1, 0x00);
	write_cmos_sensor(0x05b1, 0x0c);
	write_cmos_sensor(0x05b1, 0x0b);
	write_cmos_sensor(0x05b1, 0x3d);
	write_cmos_sensor(0x05b1, 0x00);
	write_cmos_sensor(0x05b1, 0x0d);
	write_cmos_sensor(0x05b1, 0x0f);
	write_cmos_sensor(0x05b1, 0xc6);
	write_cmos_sensor(0x05b1, 0x09);
	write_cmos_sensor(0x05b1, 0x6d);
	write_cmos_sensor(0x05ac, 0x01);
	write_cmos_sensor(0x029f, 0xc4);
	write_cmos_sensor(0x05a0, 0xc3);
	write_cmos_sensor(0x02b0, 0x70);
	write_cmos_sensor(0x0206, 0xc0);
	write_cmos_sensor(0x02b3, 0x00);
	write_cmos_sensor(0x02b4, 0x00);
	write_cmos_sensor(0x0204, 0x04);
	write_cmos_sensor(0x0205, 0x00);
	write_cmos_sensor(0x020e, 0x04);
	write_cmos_sensor(0x020f, 0x00);
	write_cmos_sensor(0x0099, 0x00);
	write_cmos_sensor(0x0351, 0x00);
	write_cmos_sensor(0x0352, 0x06);
	write_cmos_sensor(0x0353, 0x00);
	write_cmos_sensor(0x0354, 0x08);
	write_cmos_sensor(0x034c, 0x0c);
	write_cmos_sensor(0x034d, 0xc0);
	write_cmos_sensor(0x034e, 0x09);
	write_cmos_sensor(0x034f, 0x90);
	write_cmos_sensor(0x0108, 0x08);
	write_cmos_sensor(0x0112, 0x0a);
	write_cmos_sensor(0x0113, 0x0a);
	write_cmos_sensor(0x0114, 0x03);
	write_cmos_sensor(0x0181, 0xf0);
	write_cmos_sensor(0x0185, 0x01);
	write_cmos_sensor(0x0188, 0x00);
	write_cmos_sensor(0x0121, 0x05);
	write_cmos_sensor(0x0122, 0x06);
	write_cmos_sensor(0x0123, 0x16);
	write_cmos_sensor(0x0124, 0x01);
	write_cmos_sensor(0x0125, 0x0b);
	write_cmos_sensor(0x0126, 0x08);
	write_cmos_sensor(0x0129, 0x06);
	write_cmos_sensor(0x012a, 0x08);
	write_cmos_sensor(0x012b, 0x08);
	write_cmos_sensor(0x0a70, 0x11);
	write_cmos_sensor(0x0313, 0x80);
	write_cmos_sensor(0x0aff, 0x10);
	write_cmos_sensor(0x0aff, 0x10);
	write_cmos_sensor(0x0aff, 0x10);
	write_cmos_sensor(0x0aff, 0x10);
	write_cmos_sensor(0x0aff, 0x10);
	write_cmos_sensor(0x0aff, 0x10);
	write_cmos_sensor(0x0aff, 0x10);
	write_cmos_sensor(0x0aff, 0x10);
	write_cmos_sensor(0x0a70, 0x00);
	write_cmos_sensor(0x00be, 0x01);
	write_cmos_sensor(0x0317, 0x00);
	write_cmos_sensor(0x0a67, 0x00);
	write_cmos_sensor(0x0084, 0x10);
}

static void capture_setting(kal_uint16 currefps)
{
	pr_info("GC8054 capture - E!\n");
	write_cmos_sensor(0x031c, 0x60);
	write_cmos_sensor(0x0320, 0xbb);
	write_cmos_sensor(0x0337, 0x06);
	write_cmos_sensor(0x0335, 0x51);
	write_cmos_sensor(0x0336, 0x9b);
	write_cmos_sensor(0x031a, 0x00);
	write_cmos_sensor(0x0321, 0x10);
	write_cmos_sensor(0x0327, 0x06);
	write_cmos_sensor(0x0325, 0x41);
	write_cmos_sensor(0x0326, 0x5d);
	write_cmos_sensor(0x0314, 0x01);
	write_cmos_sensor(0x0315, 0xe9);
	write_cmos_sensor(0x0317, 0x00);
	write_cmos_sensor(0x0115, 0x30);
	write_cmos_sensor(0x0180, 0x67);
	write_cmos_sensor(0x0334, 0x40);
	write_cmos_sensor(0x0324, 0x44);
	write_cmos_sensor(0x031c, 0x00);
	write_cmos_sensor(0x031c, 0x9f);
	write_cmos_sensor(0x0202, 0x09);
	write_cmos_sensor(0x0203, 0x00);
	write_cmos_sensor(0x0340, 0x09);
	write_cmos_sensor(0x0341, 0xe4);
	write_cmos_sensor(0x0342, 0x05);
	write_cmos_sensor(0x0343, 0x20);
	write_cmos_sensor(0x0344, 0x00);
	write_cmos_sensor(0x0345, 0x06);
	write_cmos_sensor(0x0346, 0x00);
	write_cmos_sensor(0x0347, 0x04);
	write_cmos_sensor(0x0348, 0x0c);
	write_cmos_sensor(0x0349, 0xd0);
	write_cmos_sensor(0x034a, 0x09);
	write_cmos_sensor(0x034b, 0x9c);
	write_cmos_sensor(0x0291, 0x00);
	write_cmos_sensor(0x0292, 0x28);
	write_cmos_sensor(0x0213, 0x12);
	write_cmos_sensor(0x02a9, 0x18);
	write_cmos_sensor(0x0221, 0x22);
	write_cmos_sensor(0x028b, 0x18);
	write_cmos_sensor(0x028c, 0x18);
	write_cmos_sensor(0x0229, 0x64);
	write_cmos_sensor(0x024b, 0x16);
	write_cmos_sensor(0x0255, 0x21);
	write_cmos_sensor(0x0280, 0x38);
	write_cmos_sensor(0x021f, 0x10);
	write_cmos_sensor(0x0224, 0x00);
	write_cmos_sensor(0x0234, 0x00);
	write_cmos_sensor(0x024a, 0x02);
	write_cmos_sensor(0x0282, 0x13);
	write_cmos_sensor(0x028d, 0x92);
	write_cmos_sensor(0x039a, 0x90);
	write_cmos_sensor(0x031c, 0x80);
	write_cmos_sensor(0x03fe, 0x10);
	write_cmos_sensor(0x03fe, 0x00);
	write_cmos_sensor(0x031c, 0x9f);
	write_cmos_sensor(0x03fe, 0x00);
	write_cmos_sensor(0x03fe, 0x00);
	write_cmos_sensor(0x03fe, 0x00);
	write_cmos_sensor(0x03fe, 0x00);
	write_cmos_sensor(0x031c, 0x80);
	write_cmos_sensor(0x03fe, 0x10);
	write_cmos_sensor(0x03fe, 0x00);
	write_cmos_sensor(0x031c, 0x9f);
	write_cmos_sensor(0x00d3, 0x00);
	write_cmos_sensor(0x00d4, 0x00);
	write_cmos_sensor(0x00d5, 0x00);
	write_cmos_sensor(0x00d6, 0x00);
	write_cmos_sensor(0x05a0, 0x83);
	write_cmos_sensor(0x05a3, 0x06);
	write_cmos_sensor(0x05a4, 0x04);
	write_cmos_sensor(0x0597, 0x27);
	write_cmos_sensor(0x059a, 0x00);
	write_cmos_sensor(0x059b, 0x00);
	write_cmos_sensor(0x059c, 0x01);
	write_cmos_sensor(0x05ab, 0x09);
	write_cmos_sensor(0x05ae, 0x00);
	write_cmos_sensor(0x05af, 0x00);
	write_cmos_sensor(0x05ac, 0x00);
	write_cmos_sensor(0x05ad, 0x01);
	write_cmos_sensor(0x05b1, 0x03);
	write_cmos_sensor(0x05b1, 0x04);
	write_cmos_sensor(0x05b1, 0x05);
	write_cmos_sensor(0x05b1, 0x0c);
	write_cmos_sensor(0x05b1, 0x1c);
	write_cmos_sensor(0x05b1, 0x05);
	write_cmos_sensor(0x05b1, 0x12);
	write_cmos_sensor(0x05b1, 0x05);
	write_cmos_sensor(0x05b1, 0x00);
	write_cmos_sensor(0x05b1, 0x05);
	write_cmos_sensor(0x05b1, 0x06);
	write_cmos_sensor(0x05b1, 0x05);
	write_cmos_sensor(0x05b1, 0x14);
	write_cmos_sensor(0x05b1, 0x18);
	write_cmos_sensor(0x05b1, 0x18);
	write_cmos_sensor(0x05b1, 0x19);
	write_cmos_sensor(0x05b1, 0x40);
	write_cmos_sensor(0x05b1, 0x14);
	write_cmos_sensor(0x05b1, 0x38);
	write_cmos_sensor(0x05b1, 0x29);
	write_cmos_sensor(0x05b1, 0x40);
	write_cmos_sensor(0x05b1, 0x08);
	write_cmos_sensor(0x05b1, 0x38);
	write_cmos_sensor(0x05b1, 0x29);
	write_cmos_sensor(0x05b1, 0x40);
	write_cmos_sensor(0x05b1, 0x08);
	write_cmos_sensor(0x05b1, 0x38);
	write_cmos_sensor(0x05b1, 0x29);
	write_cmos_sensor(0x05b1, 0x00);
	write_cmos_sensor(0x05b1, 0x08);
	write_cmos_sensor(0x05b1, 0x68);
	write_cmos_sensor(0x05b1, 0x41);
	write_cmos_sensor(0x05b1, 0x00);
	write_cmos_sensor(0x05b1, 0x08);
	write_cmos_sensor(0x05b1, 0x88);
	write_cmos_sensor(0x05b1, 0x51);
	write_cmos_sensor(0x05b1, 0x00);
	write_cmos_sensor(0x05b1, 0x00);
	write_cmos_sensor(0x05b1, 0x00);
	write_cmos_sensor(0x05b1, 0x01);
	write_cmos_sensor(0x05b1, 0x00);
	write_cmos_sensor(0x05b1, 0x01);
	write_cmos_sensor(0x05b1, 0x00);
	write_cmos_sensor(0x05b1, 0x00);
	write_cmos_sensor(0x05b1, 0x00);
	write_cmos_sensor(0x05b1, 0x01);
	write_cmos_sensor(0x05b1, 0x94);
	write_cmos_sensor(0x05b1, 0x03);
	write_cmos_sensor(0x05b1, 0x01);
	write_cmos_sensor(0x05b1, 0x02);
	write_cmos_sensor(0x05b1, 0x00);
	write_cmos_sensor(0x05b1, 0x00);
	write_cmos_sensor(0x05b1, 0x02);
	write_cmos_sensor(0x05b1, 0x02);
	write_cmos_sensor(0x05b1, 0xd9);
	write_cmos_sensor(0x05b1, 0x00);
	write_cmos_sensor(0x05b1, 0x03);
	write_cmos_sensor(0x05b1, 0x03);
	write_cmos_sensor(0x05b1, 0xf8);
	write_cmos_sensor(0x05b1, 0x00);
	write_cmos_sensor(0x05b1, 0x04);
	write_cmos_sensor(0x05b1, 0x05);
	write_cmos_sensor(0x05b1, 0x9e);
	write_cmos_sensor(0x05b1, 0x00);
	write_cmos_sensor(0x05b1, 0x05);
	write_cmos_sensor(0x05b1, 0x07);
	write_cmos_sensor(0x05b1, 0xf0);
	write_cmos_sensor(0x05b1, 0x00);
	write_cmos_sensor(0x05b1, 0x0c);
	write_cmos_sensor(0x05b1, 0x0b);
	write_cmos_sensor(0x05b1, 0x3d);
	write_cmos_sensor(0x05b1, 0x00);
	write_cmos_sensor(0x05b1, 0x0d);
	write_cmos_sensor(0x05b1, 0x0f);
	write_cmos_sensor(0x05b1, 0xc6);
	write_cmos_sensor(0x05b1, 0x09);
	write_cmos_sensor(0x05b1, 0x6d);
	write_cmos_sensor(0x05ac, 0x01);
	write_cmos_sensor(0x029f, 0xc4);
	write_cmos_sensor(0x05a0, 0xc3);
	write_cmos_sensor(0x02b0, 0x70);
	write_cmos_sensor(0x0206, 0xc0);
	write_cmos_sensor(0x02b3, 0x00);
	write_cmos_sensor(0x02b4, 0x00);
	write_cmos_sensor(0x0204, 0x04);
	write_cmos_sensor(0x0205, 0x00);
	write_cmos_sensor(0x020e, 0x04);
	write_cmos_sensor(0x020f, 0x00);
	write_cmos_sensor(0x0099, 0x00);
	write_cmos_sensor(0x0351, 0x00);
	write_cmos_sensor(0x0352, 0x06);
	write_cmos_sensor(0x0353, 0x00);
	write_cmos_sensor(0x0354, 0x08);
	write_cmos_sensor(0x034c, 0x0c);
	write_cmos_sensor(0x034d, 0xc0);
	write_cmos_sensor(0x034e, 0x09);
	write_cmos_sensor(0x034f, 0x90);
	write_cmos_sensor(0x0108, 0x08);
	write_cmos_sensor(0x0112, 0x0a);
	write_cmos_sensor(0x0113, 0x0a);
	write_cmos_sensor(0x0114, 0x03);
	write_cmos_sensor(0x0181, 0xf0);
	write_cmos_sensor(0x0185, 0x01);
	write_cmos_sensor(0x0188, 0x00);
	write_cmos_sensor(0x0121, 0x05);
	write_cmos_sensor(0x0122, 0x06);
	write_cmos_sensor(0x0123, 0x16);
	write_cmos_sensor(0x0124, 0x01);
	write_cmos_sensor(0x0125, 0x0b);
	write_cmos_sensor(0x0126, 0x08);
	write_cmos_sensor(0x0129, 0x06);
	write_cmos_sensor(0x012a, 0x08);
	write_cmos_sensor(0x012b, 0x08);
	write_cmos_sensor(0x0a70, 0x11);
	write_cmos_sensor(0x0313, 0x80);
	write_cmos_sensor(0x0aff, 0x10);
	write_cmos_sensor(0x0aff, 0x10);
	write_cmos_sensor(0x0aff, 0x10);
	write_cmos_sensor(0x0aff, 0x10);
	write_cmos_sensor(0x0aff, 0x10);
	write_cmos_sensor(0x0aff, 0x10);
	write_cmos_sensor(0x0aff, 0x10);
	write_cmos_sensor(0x0aff, 0x10);
	write_cmos_sensor(0x0a70, 0x00);
	write_cmos_sensor(0x00be, 0x01);
	write_cmos_sensor(0x0317, 0x00);
	write_cmos_sensor(0x0a67, 0x00);
	write_cmos_sensor(0x0084, 0x10);
}

static void normal_video_setting(kal_uint16 currefps)
{
	LOG_INF("E! currefps: %d\n", currefps);
	write_cmos_sensor(0x031c, 0x60);
	write_cmos_sensor(0x0320, 0xbb);
	write_cmos_sensor(0x0337, 0x06);
	write_cmos_sensor(0x0335, 0x51);
	write_cmos_sensor(0x0336, 0x9b);
	write_cmos_sensor(0x031a, 0x00);
	write_cmos_sensor(0x0321, 0x10);
	write_cmos_sensor(0x0327, 0x06);
	write_cmos_sensor(0x0325, 0x41);
	write_cmos_sensor(0x0326, 0x5d);
	write_cmos_sensor(0x0314, 0x01);
	write_cmos_sensor(0x0315, 0xe9);
	write_cmos_sensor(0x0317, 0x00);
	write_cmos_sensor(0x0115, 0x30);
	write_cmos_sensor(0x0180, 0x67);
	write_cmos_sensor(0x0334, 0x40);
	write_cmos_sensor(0x0324, 0x44);
	write_cmos_sensor(0x031c, 0x00);
	write_cmos_sensor(0x031c, 0x9f);
	write_cmos_sensor(0x0202, 0x09);
	write_cmos_sensor(0x0203, 0x00);
	write_cmos_sensor(0x0340, 0x09);
	write_cmos_sensor(0x0341, 0xe4);
	write_cmos_sensor(0x0342, 0x05);
	write_cmos_sensor(0x0343, 0x20);
	write_cmos_sensor(0x0344, 0x00);
	write_cmos_sensor(0x0345, 0x06);
	write_cmos_sensor(0x0346, 0x01);
	write_cmos_sensor(0x0347, 0x36);
	write_cmos_sensor(0x0348, 0x0c);
	write_cmos_sensor(0x0349, 0xd0);
	write_cmos_sensor(0x034a, 0x07);
	write_cmos_sensor(0x034b, 0x38);
	write_cmos_sensor(0x0291, 0x02);
	write_cmos_sensor(0x0292, 0x8c);
	write_cmos_sensor(0x0213, 0x12);
	write_cmos_sensor(0x02a9, 0x18);
	write_cmos_sensor(0x0221, 0x22);
	write_cmos_sensor(0x028b, 0x18);
	write_cmos_sensor(0x028c, 0x18);
	write_cmos_sensor(0x0229, 0x64);
	write_cmos_sensor(0x024b, 0x16);
	write_cmos_sensor(0x0255, 0x21);
	write_cmos_sensor(0x0280, 0x38);
	write_cmos_sensor(0x021f, 0x10);
	write_cmos_sensor(0x0224, 0x00);
	write_cmos_sensor(0x0234, 0x00);
	write_cmos_sensor(0x024a, 0x02);
	write_cmos_sensor(0x0282, 0x13);
	write_cmos_sensor(0x028d, 0x92);
	write_cmos_sensor(0x039a, 0x90);
	write_cmos_sensor(0x031c, 0x80);
	write_cmos_sensor(0x03fe, 0x10);
	write_cmos_sensor(0x03fe, 0x00);
	write_cmos_sensor(0x031c, 0x9f);
	write_cmos_sensor(0x03fe, 0x00);
	write_cmos_sensor(0x03fe, 0x00);
	write_cmos_sensor(0x03fe, 0x00);
	write_cmos_sensor(0x03fe, 0x00);
	write_cmos_sensor(0x031c, 0x80);
	write_cmos_sensor(0x03fe, 0x10);
	write_cmos_sensor(0x03fe, 0x00);
	write_cmos_sensor(0x031c, 0x9f);
	write_cmos_sensor(0x00d3, 0x32);
	write_cmos_sensor(0x00d4, 0x01);
	write_cmos_sensor(0x00d5, 0x00);
	write_cmos_sensor(0x00d6, 0x00);
	write_cmos_sensor(0x05a0, 0x83);
	write_cmos_sensor(0x05a3, 0x06);
	write_cmos_sensor(0x05a4, 0x04);
	write_cmos_sensor(0x0597, 0x27);
	write_cmos_sensor(0x059a, 0x00);
	write_cmos_sensor(0x059b, 0x00);
	write_cmos_sensor(0x059c, 0x01);
	write_cmos_sensor(0x05ab, 0x09);
	write_cmos_sensor(0x05ae, 0x00);
	write_cmos_sensor(0x05af, 0x00);
	write_cmos_sensor(0x05ac, 0x00);
	write_cmos_sensor(0x05ad, 0x01);
	write_cmos_sensor(0x05b1, 0x03);
	write_cmos_sensor(0x05b1, 0x04);
	write_cmos_sensor(0x05b1, 0x05);
	write_cmos_sensor(0x05b1, 0x0c);
	write_cmos_sensor(0x05b1, 0x1c);
	write_cmos_sensor(0x05b1, 0x05);
	write_cmos_sensor(0x05b1, 0x12);
	write_cmos_sensor(0x05b1, 0x05);
	write_cmos_sensor(0x05b1, 0x00);
	write_cmos_sensor(0x05b1, 0x05);
	write_cmos_sensor(0x05b1, 0x06);
	write_cmos_sensor(0x05b1, 0x05);
	write_cmos_sensor(0x05b1, 0x14);
	write_cmos_sensor(0x05b1, 0x18);
	write_cmos_sensor(0x05b1, 0x18);
	write_cmos_sensor(0x05b1, 0x19);
	write_cmos_sensor(0x05b1, 0x40);
	write_cmos_sensor(0x05b1, 0x14);
	write_cmos_sensor(0x05b1, 0x38);
	write_cmos_sensor(0x05b1, 0x29);
	write_cmos_sensor(0x05b1, 0x40);
	write_cmos_sensor(0x05b1, 0x08);
	write_cmos_sensor(0x05b1, 0x38);
	write_cmos_sensor(0x05b1, 0x29);
	write_cmos_sensor(0x05b1, 0x40);
	write_cmos_sensor(0x05b1, 0x08);
	write_cmos_sensor(0x05b1, 0x38);
	write_cmos_sensor(0x05b1, 0x29);
	write_cmos_sensor(0x05b1, 0x00);
	write_cmos_sensor(0x05b1, 0x08);
	write_cmos_sensor(0x05b1, 0x68);
	write_cmos_sensor(0x05b1, 0x41);
	write_cmos_sensor(0x05b1, 0x00);
	write_cmos_sensor(0x05b1, 0x08);
	write_cmos_sensor(0x05b1, 0x88);
	write_cmos_sensor(0x05b1, 0x51);
	write_cmos_sensor(0x05b1, 0x00);
	write_cmos_sensor(0x05b1, 0x00);
	write_cmos_sensor(0x05b1, 0x00);
	write_cmos_sensor(0x05b1, 0x01);
	write_cmos_sensor(0x05b1, 0x00);
	write_cmos_sensor(0x05b1, 0x01);
	write_cmos_sensor(0x05b1, 0x00);
	write_cmos_sensor(0x05b1, 0x00);
	write_cmos_sensor(0x05b1, 0x00);
	write_cmos_sensor(0x05b1, 0x01);
	write_cmos_sensor(0x05b1, 0x94);
	write_cmos_sensor(0x05b1, 0x03);
	write_cmos_sensor(0x05b1, 0x01);
	write_cmos_sensor(0x05b1, 0x02);
	write_cmos_sensor(0x05b1, 0x00);
	write_cmos_sensor(0x05b1, 0x00);
	write_cmos_sensor(0x05b1, 0x02);
	write_cmos_sensor(0x05b1, 0x02);
	write_cmos_sensor(0x05b1, 0xd9);
	write_cmos_sensor(0x05b1, 0x00);
	write_cmos_sensor(0x05b1, 0x03);
	write_cmos_sensor(0x05b1, 0x03);
	write_cmos_sensor(0x05b1, 0xf8);
	write_cmos_sensor(0x05b1, 0x00);
	write_cmos_sensor(0x05b1, 0x04);
	write_cmos_sensor(0x05b1, 0x05);
	write_cmos_sensor(0x05b1, 0x9e);
	write_cmos_sensor(0x05b1, 0x00);
	write_cmos_sensor(0x05b1, 0x05);
	write_cmos_sensor(0x05b1, 0x07);
	write_cmos_sensor(0x05b1, 0xf0);
	write_cmos_sensor(0x05b1, 0x00);
	write_cmos_sensor(0x05b1, 0x0c);
	write_cmos_sensor(0x05b1, 0x0b);
	write_cmos_sensor(0x05b1, 0x3d);
	write_cmos_sensor(0x05b1, 0x00);
	write_cmos_sensor(0x05b1, 0x0d);
	write_cmos_sensor(0x05b1, 0x0f);
	write_cmos_sensor(0x05b1, 0xc6);
	write_cmos_sensor(0x05b1, 0x09);
	write_cmos_sensor(0x05b1, 0x6d);
	write_cmos_sensor(0x05ac, 0x01);
	write_cmos_sensor(0x029f, 0xc4);
	write_cmos_sensor(0x05a0, 0xc3);
	write_cmos_sensor(0x02b0, 0x70);
	write_cmos_sensor(0x0206, 0xc0);
	write_cmos_sensor(0x02b3, 0x00);
	write_cmos_sensor(0x02b4, 0x00);
	write_cmos_sensor(0x0204, 0x04);
	write_cmos_sensor(0x0205, 0x00);
	write_cmos_sensor(0x020e, 0x04);
	write_cmos_sensor(0x020f, 0x00);
	write_cmos_sensor(0x0099, 0x00);
	write_cmos_sensor(0x0351, 0x00);
	write_cmos_sensor(0x0352, 0x06);
	write_cmos_sensor(0x0353, 0x00);
	write_cmos_sensor(0x0354, 0x08);
	write_cmos_sensor(0x034c, 0x0c);
	write_cmos_sensor(0x034d, 0xc0);
	write_cmos_sensor(0x034e, 0x07);
	write_cmos_sensor(0x034f, 0x2c);
	write_cmos_sensor(0x0108, 0x08);
	write_cmos_sensor(0x0112, 0x0a);
	write_cmos_sensor(0x0113, 0x0a);
	write_cmos_sensor(0x0114, 0x03);
	write_cmos_sensor(0x0181, 0xf0);
	write_cmos_sensor(0x0185, 0x01);
	write_cmos_sensor(0x0188, 0x00);
	write_cmos_sensor(0x0121, 0x05);
	write_cmos_sensor(0x0122, 0x06);
	write_cmos_sensor(0x0123, 0x16);
	write_cmos_sensor(0x0124, 0x01);
	write_cmos_sensor(0x0125, 0x0b);
	write_cmos_sensor(0x0126, 0x08);
	write_cmos_sensor(0x0129, 0x06);
	write_cmos_sensor(0x012a, 0x08);
	write_cmos_sensor(0x012b, 0x08);
	write_cmos_sensor(0x0a70, 0x11);
	write_cmos_sensor(0x0313, 0x80);
	write_cmos_sensor(0x0aff, 0x10);
	write_cmos_sensor(0x0aff, 0x10);
	write_cmos_sensor(0x0aff, 0x10);
	write_cmos_sensor(0x0aff, 0x10);
	write_cmos_sensor(0x0aff, 0x10);
	write_cmos_sensor(0x0aff, 0x10);
	write_cmos_sensor(0x0aff, 0x10);
	write_cmos_sensor(0x0aff, 0x10);
	write_cmos_sensor(0x0a70, 0x00);
	write_cmos_sensor(0x00be, 0x01);
	write_cmos_sensor(0x0317, 0x00);
	write_cmos_sensor(0x0a67, 0x00);
	write_cmos_sensor(0x0084, 0x10);
}

static void hs_video_setting(void)
{
	LOG_INF("E\n");
}

static void slim_video_setting(void)
{
	LOG_INF("E\n");
}

static void custom1_setting(void)
{
	LOG_INF("E\n");
}

static kal_uint32 set_test_pattern_mode(kal_bool enable)
{
	LOG_INF("enable: %d\n", enable);

	spin_lock(&imgsensor_drv_lock);
	imgsensor.test_pattern = enable;
	spin_unlock(&imgsensor_drv_lock);
	return ERROR_NONE;
}

/*************************************************************************
 * FUNCTION
 *    get_imgsensor_id
 *
 * DESCRIPTION
 *    This function get the sensor ID
 *
 * PARAMETERS
 *    *sensorID : return the sensor ID
 *
 * RETURNS
 *    None
 *
 * GLOBALS AFFECTED
 *
 *************************************************************************/
static kal_uint32 get_imgsensor_id(UINT32 *sensor_id)
{
	kal_uint8 i = 0;
	kal_uint8 retry = 2;

	while (imgsensor_info.i2c_addr_table[i] != 0xff) {
		spin_lock(&imgsensor_drv_lock);
		imgsensor.i2c_write_id = imgsensor_info.i2c_addr_table[i];
		spin_unlock(&imgsensor_drv_lock);
		do {
			*sensor_id = return_sensor_id();
			if (*sensor_id == imgsensor_info.sensor_id) {
				LOG_INF("i2c write id: 0x%x, sensor id: 0x%x\n",
				imgsensor.i2c_write_id, *sensor_id);
				return ERROR_NONE;
			}
			LOG_INF("Read sensor id fail, write id: 0x%x, id: 0x%x\n",
				 imgsensor.i2c_write_id, *sensor_id);
			retry--;
		} while (retry > 0);
		i++;
		retry = 2;
	}

	if (*sensor_id != imgsensor_info.sensor_id) {
		/*if Sensor ID is not correct, Must set *sensor_id to 0xFFFFFFFF*/
		*sensor_id = 0xFFFFFFFF;
		return ERROR_SENSOR_CONNECT_FAIL;
	}

	return ERROR_NONE;
}

/*************************************************************************
 * FUNCTION
 *    open
 *
 * DESCRIPTION
 *    This function initialize the registers of CMOS sensor
 *
 * PARAMETERS
 *    None
 *
 * RETURNS
 *    None
 *
 * GLOBALS AFFECTED
 *
 *************************************************************************/
static kal_uint32 open(void)
{
	kal_uint8 i = 0;
	kal_uint8 retry = 2;
	kal_uint32 sensor_id = 0;

	LOG_1;

	while (imgsensor_info.i2c_addr_table[i] != 0xff) {
		spin_lock(&imgsensor_drv_lock);
		imgsensor.i2c_write_id = imgsensor_info.i2c_addr_table[i];
		spin_unlock(&imgsensor_drv_lock);
		do {
			sensor_id = return_sensor_id();
			if (sensor_id == imgsensor_info.sensor_id) {
				LOG_INF("i2c write id: 0x%x, sensor id: 0x%x\n",
					imgsensor.i2c_write_id, sensor_id);
				break;
			}
			LOG_INF("Read sensor id fail, write id: 0x%x, id: 0x%x\n",
				imgsensor.i2c_write_id, sensor_id);
			retry--;
		} while (retry > 0);
		i++;
		if (sensor_id == imgsensor_info.sensor_id)
			break;
		retry = 2;
	}
	if (imgsensor_info.sensor_id != sensor_id)
		return ERROR_SENSOR_CONNECT_FAIL;
	/* initail sequence write in  */
	sensor_init();

	//gc8054_otp_function();

	spin_lock(&imgsensor_drv_lock);

	imgsensor.autoflicker_en = KAL_FALSE;
	imgsensor.sensor_mode = IMGSENSOR_MODE_INIT;
	imgsensor.pclk = imgsensor_info.pre.pclk;
	imgsensor.frame_length = imgsensor_info.pre.framelength;
	imgsensor.line_length = imgsensor_info.pre.linelength;
	imgsensor.min_frame_length = imgsensor_info.pre.framelength;
	imgsensor.dummy_pixel = 0;
	imgsensor.dummy_line = 0;
	imgsensor.ihdr_en = 0;
	imgsensor.test_pattern = KAL_FALSE;
	imgsensor.current_fps = imgsensor_info.pre.max_framerate;
	spin_unlock(&imgsensor_drv_lock);
	return ERROR_NONE;
}

/*
 ************************************************************************
 * FUNCTION
 *    close
 *
 * DESCRIPTION
 *
 *
 * PARAMETERS
 *    None
 *
 * RETURNS
 *    None
 *
 * GLOBALS AFFECTED
 *
 *************************************************************************/
static kal_uint32 close(void)
{
	LOG_INF("E\n");
	/* No Need to implement this function */
	streaming_control(KAL_FALSE);
	return ERROR_NONE;
}

/*************************************************************************
 * FUNCTION
 * preview
 *
 * DESCRIPTION
 *    This function start the sensor preview.
 *
 * PARAMETERS
 *    *image_window : address pointer of pixel numbers in one period of HSYNC
 *  *sensor_config_data : address pointer of line numbers in one period of VSYNC
 *
 * RETURNS
 *    None
 *
 * GLOBALS AFFECTED
 *
 *************************************************************************/
static kal_uint32 preview(MSDK_SENSOR_EXPOSURE_WINDOW_STRUCT *image_window,
	MSDK_SENSOR_CONFIG_STRUCT *sensor_config_data)
{
	LOG_INF("E\n");

	spin_lock(&imgsensor_drv_lock);
	imgsensor.sensor_mode = IMGSENSOR_MODE_PREVIEW;
	imgsensor.pclk = imgsensor_info.pre.pclk;
	/* imgsensor.video_mode = KAL_FALSE; */
	imgsensor.line_length = imgsensor_info.pre.linelength;
	imgsensor.frame_length = imgsensor_info.pre.framelength;
	imgsensor.min_frame_length = imgsensor_info.pre.framelength;
	imgsensor.autoflicker_en = KAL_FALSE;
	spin_unlock(&imgsensor_drv_lock);
	preview_setting();

	/* set_mirror_flip(sensor_config_data->SensorImageMirror); */
	return ERROR_NONE;
}

/* ************************************************************************
 * FUNCTION
 *    capture
 *
 * DESCRIPTION
 *    This function setup the CMOS sensor in capture MY_OUTPUT mode
 *
 * PARAMETERS
 *
 * RETURNS
 *    None
 *
 * GLOBALS AFFECTED
 *
 *************************************************************************/
static kal_uint32 capture(MSDK_SENSOR_EXPOSURE_WINDOW_STRUCT *image_window,
	MSDK_SENSOR_CONFIG_STRUCT *sensor_config_data)
{
	LOG_INF("E\n");

	spin_lock(&imgsensor_drv_lock);
	imgsensor.sensor_mode = IMGSENSOR_MODE_CAPTURE;
	imgsensor.pclk = imgsensor_info.cap.pclk;
	imgsensor.line_length = imgsensor_info.cap.linelength;
	imgsensor.frame_length = imgsensor_info.cap.framelength;
	imgsensor.min_frame_length = imgsensor_info.cap.framelength;
	imgsensor.autoflicker_en = KAL_FALSE;
	spin_unlock(&imgsensor_drv_lock);
	capture_setting(imgsensor.current_fps);
	return ERROR_NONE;
}

static kal_uint32 normal_video(MSDK_SENSOR_EXPOSURE_WINDOW_STRUCT *image_window,
	MSDK_SENSOR_CONFIG_STRUCT *sensor_config_data)
{
	LOG_INF("E\n");

	spin_lock(&imgsensor_drv_lock);
	imgsensor.sensor_mode = IMGSENSOR_MODE_VIDEO;
	imgsensor.pclk = imgsensor_info.normal_video.pclk;
	imgsensor.line_length = imgsensor_info.normal_video.linelength;
	imgsensor.frame_length = imgsensor_info.normal_video.framelength;
	imgsensor.min_frame_length = imgsensor_info.normal_video.framelength;
	/* imgsensor.current_fps = 300; */
	imgsensor.autoflicker_en = KAL_FALSE;
	spin_unlock(&imgsensor_drv_lock);

	normal_video_setting(imgsensor.current_fps);
	/* set_mirror_flip(sensor_config_data->SensorImageMirror); */
	return ERROR_NONE;
}

static kal_uint32 hs_video(MSDK_SENSOR_EXPOSURE_WINDOW_STRUCT *image_window,
	MSDK_SENSOR_CONFIG_STRUCT *sensor_config_data)
{
	LOG_INF("E\n");

	spin_lock(&imgsensor_drv_lock);
	imgsensor.sensor_mode = IMGSENSOR_MODE_HIGH_SPEED_VIDEO;
	imgsensor.pclk = imgsensor_info.hs_video.pclk;
	/* imgsensor.video_mode = KAL_TRUE; */
	imgsensor.line_length = imgsensor_info.hs_video.linelength;
	imgsensor.frame_length = imgsensor_info.hs_video.framelength;
	imgsensor.min_frame_length = imgsensor_info.hs_video.framelength;
	imgsensor.dummy_line = 0;
	imgsensor.dummy_pixel = 0;
	imgsensor.autoflicker_en = KAL_FALSE;
	spin_unlock(&imgsensor_drv_lock);
	hs_video_setting();
	return ERROR_NONE;
}

static kal_uint32 slim_video(MSDK_SENSOR_EXPOSURE_WINDOW_STRUCT *image_window,
	MSDK_SENSOR_CONFIG_STRUCT *sensor_config_data)
{
	LOG_INF("E\n");

	spin_lock(&imgsensor_drv_lock);
	imgsensor.sensor_mode = IMGSENSOR_MODE_SLIM_VIDEO;
	imgsensor.pclk = imgsensor_info.slim_video.pclk;
	imgsensor.line_length = imgsensor_info.slim_video.linelength;
	imgsensor.frame_length = imgsensor_info.slim_video.framelength;
	imgsensor.min_frame_length = imgsensor_info.slim_video.framelength;
	imgsensor.dummy_line = 0;
	imgsensor.dummy_pixel = 0;
	imgsensor.autoflicker_en = KAL_FALSE;
	spin_unlock(&imgsensor_drv_lock);
	slim_video_setting();
	return ERROR_NONE;
}

static kal_uint32 custom1(MSDK_SENSOR_EXPOSURE_WINDOW_STRUCT *image_window,
	MSDK_SENSOR_CONFIG_STRUCT *sensor_config_data)
{
	LOG_INF("custom1_setting E\n");

	spin_lock(&imgsensor_drv_lock);
	imgsensor.sensor_mode = IMGSENSOR_MODE_CUSTOM1;
	imgsensor.pclk = imgsensor_info.custom1.pclk;
	imgsensor.line_length = imgsensor_info.custom1.linelength;
	imgsensor.frame_length = imgsensor_info.custom1.framelength;
	imgsensor.min_frame_length = imgsensor_info.custom1.framelength;
	spin_unlock(&imgsensor_drv_lock);
	custom1_setting();
	return ERROR_NONE;
}

static kal_uint32 get_resolution(MSDK_SENSOR_RESOLUTION_INFO_STRUCT *sensor_resolution)
{
	LOG_INF("E\n");
	sensor_resolution->SensorFullWidth =
		imgsensor_info.cap.grabwindow_width;
	sensor_resolution->SensorFullHeight =
		imgsensor_info.cap.grabwindow_height;

	sensor_resolution->SensorPreviewWidth =
		imgsensor_info.pre.grabwindow_width;
	sensor_resolution->SensorPreviewHeight =
		imgsensor_info.pre.grabwindow_height;

	sensor_resolution->SensorVideoWidth =
		imgsensor_info.normal_video.grabwindow_width;
	sensor_resolution->SensorVideoHeight =
		imgsensor_info.normal_video.grabwindow_height;

	sensor_resolution->SensorHighSpeedVideoWidth =
		imgsensor_info.hs_video.grabwindow_width;
	sensor_resolution->SensorHighSpeedVideoHeight =
		imgsensor_info.hs_video.grabwindow_height;

	sensor_resolution->SensorSlimVideoWidth =
		imgsensor_info.slim_video.grabwindow_width;
	sensor_resolution->SensorSlimVideoHeight =
		imgsensor_info.slim_video.grabwindow_height;

	sensor_resolution->SensorCustom1Width =
		imgsensor_info.custom1.grabwindow_width;
	sensor_resolution->SensorCustom1Height =
		imgsensor_info.custom1.grabwindow_height;
	return ERROR_NONE;
}

static kal_uint32 get_info(enum MSDK_SCENARIO_ID_ENUM scenario_id,
			   MSDK_SENSOR_INFO_STRUCT *sensor_info,
			   MSDK_SENSOR_CONFIG_STRUCT *sensor_config_data)
{
	LOG_INF("scenario_id = %d\n", scenario_id);

	sensor_info->SensorClockPolarity = SENSOR_CLOCK_POLARITY_LOW;
	sensor_info->SensorClockFallingPolarity = SENSOR_CLOCK_POLARITY_LOW;/*not use*/
	sensor_info->SensorHsyncPolarity = SENSOR_CLOCK_POLARITY_LOW;/*inverse with datasheet*/
	sensor_info->SensorVsyncPolarity = SENSOR_CLOCK_POLARITY_LOW;
	sensor_info->SensorInterruptDelayLines = 4;/*not use*/
	sensor_info->SensorResetActiveHigh = FALSE;/*not use*/
	sensor_info->SensorResetDelayCount = 5;/*not use*/

	sensor_info->SensroInterfaceType = imgsensor_info.sensor_interface_type;
	sensor_info->MIPIsensorType = imgsensor_info.mipi_sensor_type;
	sensor_info->SettleDelayMode = imgsensor_info.mipi_settle_delay_mode;
	sensor_info->SensorOutputDataFormat = imgsensor_info.sensor_output_dataformat;

	sensor_info->CaptureDelayFrame = imgsensor_info.cap_delay_frame;
	sensor_info->PreviewDelayFrame = imgsensor_info.pre_delay_frame;
	sensor_info->VideoDelayFrame = imgsensor_info.video_delay_frame;
	sensor_info->HighSpeedVideoDelayFrame = imgsensor_info.hs_video_delay_frame;
	sensor_info->SlimVideoDelayFrame = imgsensor_info.slim_video_delay_frame;
	sensor_info->Custom1DelayFrame = imgsensor_info.custom1_delay_frame;

	sensor_info->SensorMasterClockSwitch = 0;/*not use*/
	sensor_info->SensorDrivingCurrent = imgsensor_info.isp_driving_current;

	sensor_info->AEShutDelayFrame = imgsensor_info.ae_shut_delay_frame;
	/*The frame of setting shutter default 0 for TG int*/
	sensor_info->AESensorGainDelayFrame = imgsensor_info.ae_sensor_gain_delay_frame;
	/*The frame of setting sensor gain*/
	sensor_info->AEISPGainDelayFrame = imgsensor_info.ae_ispGain_delay_frame;
	sensor_info->IHDR_Support = imgsensor_info.ihdr_support;
	sensor_info->IHDR_LE_FirstLine = imgsensor_info.ihdr_le_firstline;
	sensor_info->SensorModeNum = imgsensor_info.sensor_mode_num;

	sensor_info->SensorMIPILaneNumber = imgsensor_info.mipi_lane_num;
	sensor_info->SensorClockFreq = imgsensor_info.mclk;
	sensor_info->SensorClockDividCount = 3;/*not use*/
	sensor_info->SensorClockRisingCount = 0;
	sensor_info->SensorClockFallingCount = 2;/*not use*/
	sensor_info->SensorPixelClockCount = 3;/*not use*/
	sensor_info->SensorDataLatchCount = 2;/*not use*/

	sensor_info->MIPIDataLowPwr2HighSpeedTermDelayCount = 0;
	sensor_info->MIPICLKLowPwr2HighSpeedTermDelayCount = 0;
	sensor_info->SensorWidthSampling = 0;/*0 is default 1x*/
	sensor_info->SensorHightSampling = 0;/*0 is default 1x*/
	sensor_info->SensorPacketECCOrder = 1;

	sensor_info->FrameTimeDelayFrame = imgsensor_info.frame_time_delay_frame;

	switch (scenario_id) {
	case MSDK_SCENARIO_ID_CAMERA_PREVIEW:
		sensor_info->SensorGrabStartX = imgsensor_info.pre.startx;
		sensor_info->SensorGrabStartY = imgsensor_info.pre.starty;
		sensor_info->MIPIDataLowPwr2HighSpeedSettleDelayCount =
			imgsensor_info.pre.mipi_data_lp2hs_settle_dc;
		break;
	case MSDK_SCENARIO_ID_CAMERA_CAPTURE_JPEG:
		sensor_info->SensorGrabStartX = imgsensor_info.cap.startx;
		sensor_info->SensorGrabStartY = imgsensor_info.cap.starty;
		sensor_info->MIPIDataLowPwr2HighSpeedSettleDelayCount =
			imgsensor_info.cap.mipi_data_lp2hs_settle_dc;
		break;
	case MSDK_SCENARIO_ID_VIDEO_PREVIEW:
		sensor_info->SensorGrabStartX = imgsensor_info.normal_video.startx;
		sensor_info->SensorGrabStartY = imgsensor_info.normal_video.starty;
		sensor_info->MIPIDataLowPwr2HighSpeedSettleDelayCount =
			imgsensor_info.normal_video.mipi_data_lp2hs_settle_dc;
		break;
	case MSDK_SCENARIO_ID_HIGH_SPEED_VIDEO:
		sensor_info->SensorGrabStartX = imgsensor_info.hs_video.startx;
		sensor_info->SensorGrabStartY = imgsensor_info.hs_video.starty;
		sensor_info->MIPIDataLowPwr2HighSpeedSettleDelayCount =
			imgsensor_info.hs_video.mipi_data_lp2hs_settle_dc;
		break;
	case MSDK_SCENARIO_ID_SLIM_VIDEO:
		sensor_info->SensorGrabStartX = imgsensor_info.slim_video.startx;
		sensor_info->SensorGrabStartY = imgsensor_info.slim_video.starty;
		sensor_info->MIPIDataLowPwr2HighSpeedSettleDelayCount =
			imgsensor_info.slim_video.mipi_data_lp2hs_settle_dc;
		break;
	case MSDK_SCENARIO_ID_CUSTOM1:
		sensor_info->SensorGrabStartX = imgsensor_info.custom1.startx;
		sensor_info->SensorGrabStartY = imgsensor_info.custom1.starty;
		sensor_info->MIPIDataLowPwr2HighSpeedSettleDelayCount =
			imgsensor_info.custom1.mipi_data_lp2hs_settle_dc;
		break;
	default:
		sensor_info->SensorGrabStartX = imgsensor_info.pre.startx;
		sensor_info->SensorGrabStartY = imgsensor_info.pre.starty;
		sensor_info->MIPIDataLowPwr2HighSpeedSettleDelayCount =
			imgsensor_info.pre.mipi_data_lp2hs_settle_dc;
		break;
	}

	return ERROR_NONE;
}

static kal_uint32 control(enum MSDK_SCENARIO_ID_ENUM scenario_id,
	MSDK_SENSOR_EXPOSURE_WINDOW_STRUCT *image_window,
	MSDK_SENSOR_CONFIG_STRUCT *sensor_config_data)
{
	LOG_INF("scenario_id = %d\n", scenario_id);
	spin_lock(&imgsensor_drv_lock);
	imgsensor.current_scenario_id = scenario_id;
	spin_unlock(&imgsensor_drv_lock);
	switch (scenario_id) {
	case MSDK_SCENARIO_ID_CAMERA_PREVIEW:
		preview(image_window, sensor_config_data);
		break;
	case MSDK_SCENARIO_ID_CAMERA_CAPTURE_JPEG:
		capture(image_window, sensor_config_data);
		break;
	case MSDK_SCENARIO_ID_VIDEO_PREVIEW:
		normal_video(image_window, sensor_config_data);
		break;
	case MSDK_SCENARIO_ID_HIGH_SPEED_VIDEO:
		hs_video(image_window, sensor_config_data);
		break;
	case MSDK_SCENARIO_ID_SLIM_VIDEO:
		slim_video(image_window, sensor_config_data);
		break;
	case MSDK_SCENARIO_ID_CUSTOM1:
		custom1(image_window, sensor_config_data);
		break;
	default:
		LOG_INF("Error ScenarioId setting");
		preview(image_window, sensor_config_data);
		return ERROR_INVALID_SCENARIO_ID;
	}
	return ERROR_NONE;
}

static kal_uint32 set_video_mode(UINT16 framerate)
{
	/* This Function not used after ROME */
	LOG_INF("framerate = %d\n ", framerate);
	/* SetVideoMode Function should fix framerate */
	if (framerate == 0) /* Dynamic frame rate */
		return ERROR_NONE;
	spin_lock(&imgsensor_drv_lock);
	if ((framerate == 300) && (imgsensor.autoflicker_en == KAL_TRUE))
		imgsensor.current_fps = 296;
	else if ((framerate == 150) && (imgsensor.autoflicker_en == KAL_TRUE))
		imgsensor.current_fps = 146;
	else
		imgsensor.current_fps = framerate;
	spin_unlock(&imgsensor_drv_lock);
	set_max_framerate(imgsensor.current_fps, 1);

	return ERROR_NONE;
}

static kal_uint32 set_auto_flicker_mode(kal_bool enable, UINT16 framerate)
{
	LOG_INF("enable = %d, framerate = %d\n", enable, framerate);
	spin_lock(&imgsensor_drv_lock);
	if (enable) {/* enable auto flicker */
		imgsensor.autoflicker_en = KAL_TRUE;
	} else {        /* Cancel Auto flick */
		imgsensor.autoflicker_en = KAL_FALSE;
	}
	spin_unlock(&imgsensor_drv_lock);
	return ERROR_NONE;
}

static kal_uint32 set_max_framerate_by_scenario
	(enum MSDK_SCENARIO_ID_ENUM scenario_id, MUINT32 framerate)
{
	kal_uint32 frame_length;

	LOG_INF("scenario_id = %d, framerate = %d\n", scenario_id, framerate);

	switch (scenario_id) {
	case MSDK_SCENARIO_ID_CAMERA_PREVIEW:
		frame_length = imgsensor_info.pre.pclk /
			framerate * 10 / imgsensor_info.pre.linelength;
		spin_lock(&imgsensor_drv_lock);
		imgsensor.dummy_line =
			(frame_length > imgsensor_info.pre.framelength) ?
			(frame_length - imgsensor_info.pre.framelength) : 0;
		imgsensor.frame_length =
			imgsensor_info.pre.framelength + imgsensor.dummy_line;
		imgsensor.min_frame_length = imgsensor.frame_length;
		spin_unlock(&imgsensor_drv_lock);
		if (imgsensor.frame_length > imgsensor.shutter)
			set_dummy();
		break;
	case MSDK_SCENARIO_ID_VIDEO_PREVIEW:
		if (framerate == 0)
			return ERROR_NONE;
		frame_length =
			imgsensor_info.normal_video.pclk / framerate *
			10 / imgsensor_info.normal_video.linelength;
		spin_lock(&imgsensor_drv_lock);
		imgsensor.dummy_line =
			(frame_length > imgsensor_info.normal_video.framelength) ?
			(frame_length - imgsensor_info.normal_video.framelength) : 0;
		imgsensor.frame_length =
			imgsensor_info.normal_video.framelength + imgsensor.dummy_line;
		imgsensor.min_frame_length = imgsensor.frame_length;
		spin_unlock(&imgsensor_drv_lock);
		if (imgsensor.frame_length > imgsensor.shutter)
			set_dummy();
		break;
	case MSDK_SCENARIO_ID_CAMERA_CAPTURE_JPEG:
		if (imgsensor.current_fps != imgsensor_info.cap.max_framerate) {
			LOG_INF("Warning: current_fps %d fps is not support",
				framerate);
			LOG_INF("So use cap's setting: %d fps!\n",
				imgsensor_info.cap.max_framerate / 10);
		}
		frame_length = imgsensor_info.cap.pclk /
			framerate * 10 / imgsensor_info.cap.linelength;
		spin_lock(&imgsensor_drv_lock);
		imgsensor.dummy_line =
			(frame_length > imgsensor_info.cap.framelength) ?
			(frame_length - imgsensor_info.cap.framelength) : 0;
		imgsensor.frame_length =
			imgsensor_info.cap.framelength + imgsensor.dummy_line;
		imgsensor.min_frame_length = imgsensor.frame_length;
		spin_unlock(&imgsensor_drv_lock);
		if (imgsensor.frame_length > imgsensor.shutter)
			set_dummy();
		break;
	case MSDK_SCENARIO_ID_HIGH_SPEED_VIDEO:
		frame_length = imgsensor_info.hs_video.pclk /
			framerate * 10 / imgsensor_info.hs_video.linelength;
		spin_lock(&imgsensor_drv_lock);
		imgsensor.dummy_line =
			(frame_length > imgsensor_info.hs_video.framelength) ?
			(frame_length - imgsensor_info.hs_video.framelength) : 0;
		imgsensor.frame_length =
			imgsensor_info.hs_video.framelength + imgsensor.dummy_line;
		imgsensor.min_frame_length = imgsensor.frame_length;
		spin_unlock(&imgsensor_drv_lock);
		if (imgsensor.frame_length > imgsensor.shutter)
			set_dummy();
		break;
	case MSDK_SCENARIO_ID_SLIM_VIDEO:
		frame_length = imgsensor_info.slim_video.pclk /
			framerate * 10 / imgsensor_info.slim_video.linelength;
		spin_lock(&imgsensor_drv_lock);
		imgsensor.dummy_line =
			(frame_length > imgsensor_info.slim_video.framelength) ?
			(frame_length - imgsensor_info.slim_video.framelength) : 0;
		imgsensor.frame_length =
			imgsensor_info.slim_video.framelength + imgsensor.dummy_line;
		imgsensor.min_frame_length = imgsensor.frame_length;
		spin_unlock(&imgsensor_drv_lock);
		if (imgsensor.frame_length > imgsensor.shutter)
			set_dummy();
		break;
	case MSDK_SCENARIO_ID_CUSTOM1:
		frame_length = imgsensor_info.custom1.pclk /
			framerate * 10 / imgsensor_info.custom1.linelength;
		spin_lock(&imgsensor_drv_lock);
		imgsensor.dummy_line =
			(frame_length > imgsensor_info.custom1.framelength) ?
			(frame_length - imgsensor_info.custom1.framelength) : 0;
		imgsensor.frame_length =
			imgsensor_info.custom1.framelength + imgsensor.dummy_line;
		imgsensor.min_frame_length = imgsensor.frame_length;
		spin_unlock(&imgsensor_drv_lock);
		if (imgsensor.frame_length > imgsensor.shutter)
			set_dummy();
		break;
	default:  /*coding with  preview scenario by default*/
		frame_length = imgsensor_info.pre.pclk /
			framerate * 10 / imgsensor_info.pre.linelength;
		spin_lock(&imgsensor_drv_lock);
		imgsensor.dummy_line =
			(frame_length > imgsensor_info.pre.framelength) ?
			(frame_length - imgsensor_info.pre.framelength) : 0;
		imgsensor.frame_length =
			imgsensor_info.pre.framelength + imgsensor.dummy_line;
		imgsensor.min_frame_length = imgsensor.frame_length;
		spin_unlock(&imgsensor_drv_lock);
		if (imgsensor.frame_length > imgsensor.shutter)
			set_dummy();
		LOG_INF("error scenario_id = %d, we use preview scenario\n", scenario_id);
		break;
	}
	return ERROR_NONE;
}

static kal_uint32 get_default_framerate_by_scenario
	(enum MSDK_SCENARIO_ID_ENUM scenario_id, MUINT32 *framerate)
{
	LOG_INF("scenario_id = %d\n", scenario_id);

	switch (scenario_id) {
	case MSDK_SCENARIO_ID_CAMERA_PREVIEW:
		*framerate = imgsensor_info.pre.max_framerate;
		break;
	case MSDK_SCENARIO_ID_VIDEO_PREVIEW:
		*framerate = imgsensor_info.normal_video.max_framerate;
		break;
	case MSDK_SCENARIO_ID_CAMERA_CAPTURE_JPEG:
		*framerate = imgsensor_info.cap.max_framerate;
		break;
	case MSDK_SCENARIO_ID_HIGH_SPEED_VIDEO:
		*framerate = imgsensor_info.hs_video.max_framerate;
		break;
	case MSDK_SCENARIO_ID_SLIM_VIDEO:
		*framerate = imgsensor_info.slim_video.max_framerate;
		break;
	case MSDK_SCENARIO_ID_CUSTOM1:
		*framerate = imgsensor_info.custom1.max_framerate;
		break;
	default:
		break;
	}

	return ERROR_NONE;
}

static kal_uint32 feature_control(MSDK_SENSOR_FEATURE_ENUM feature_id,
	UINT8 *feature_para, UINT32 *feature_para_len)
{
	UINT16 *feature_return_para_16 = (UINT16 *)feature_para;
	UINT16 *feature_data_16 = (UINT16 *)feature_para;
	UINT32 *feature_return_para_32 = (UINT32 *)feature_para;
	UINT32 *feature_data_32 = (UINT32 *)feature_para;
	unsigned long long *feature_data = (unsigned long long *) feature_para;
	/* unsigned long long *feature_return_para=(unsigned long long *) feature_para; */

	struct SENSOR_WINSIZE_INFO_STRUCT *wininfo;
	MSDK_SENSOR_REG_INFO_STRUCT *sensor_reg_data = (MSDK_SENSOR_REG_INFO_STRUCT *)feature_para;

	LOG_INF("feature_id = %d\n", feature_id);
	switch (feature_id) {
	case SENSOR_FEATURE_GET_PIXEL_CLOCK_FREQ_BY_SCENARIO:
		switch (*feature_data) {
		case MSDK_SCENARIO_ID_CAMERA_CAPTURE_JPEG:
			*(MUINT32 *)(uintptr_t)(*(feature_data + 1))
				= imgsensor_info.cap.pclk;
			break;
		case MSDK_SCENARIO_ID_VIDEO_PREVIEW:
			*(MUINT32 *)(uintptr_t)(*(feature_data + 1))
				= imgsensor_info.normal_video.pclk;
			break;
		case MSDK_SCENARIO_ID_HIGH_SPEED_VIDEO:
			*(MUINT32 *)(uintptr_t)(*(feature_data + 1))
				= imgsensor_info.hs_video.pclk;
			break;
		case MSDK_SCENARIO_ID_CUSTOM1:
			*(MUINT32 *)(uintptr_t)(*(feature_data + 1))
				= imgsensor_info.custom1.pclk;
			break;
		case MSDK_SCENARIO_ID_SLIM_VIDEO:
			*(MUINT32 *)(uintptr_t)(*(feature_data + 1))
				= imgsensor_info.slim_video.pclk;
			break;
		case MSDK_SCENARIO_ID_CAMERA_PREVIEW:
		default:
			*(MUINT32 *)(uintptr_t)(*(feature_data + 1))
				= imgsensor_info.pre.pclk;
			break;
		}
		break;
	case SENSOR_FEATURE_GET_PERIOD_BY_SCENARIO:
		switch (*feature_data) {
		case MSDK_SCENARIO_ID_CAMERA_CAPTURE_JPEG:
			*(MUINT32 *)(uintptr_t)(*(feature_data + 1))
				= (imgsensor_info.cap.framelength << 16)
					+ imgsensor_info.cap.linelength;
			break;
		case MSDK_SCENARIO_ID_VIDEO_PREVIEW:
			*(MUINT32 *)(uintptr_t)(*(feature_data + 1))
				= (imgsensor_info.normal_video.framelength << 16)
					+ imgsensor_info.normal_video.linelength;
			break;
		case MSDK_SCENARIO_ID_HIGH_SPEED_VIDEO:
			*(MUINT32 *)(uintptr_t)(*(feature_data + 1))
				= (imgsensor_info.hs_video.framelength << 16)
					+ imgsensor_info.hs_video.linelength;
			break;
		case MSDK_SCENARIO_ID_SLIM_VIDEO:
			*(MUINT32 *)(uintptr_t)(*(feature_data + 1))
				= (imgsensor_info.slim_video.framelength << 16)
					+ imgsensor_info.slim_video.linelength;
			break;
		case MSDK_SCENARIO_ID_CUSTOM1:
			*(MUINT32 *)(uintptr_t)(*(feature_data + 1))
				= (imgsensor_info.custom1.framelength << 16)
					+ imgsensor_info.custom1.linelength;
			break;
		case MSDK_SCENARIO_ID_CAMERA_PREVIEW:
		default:
			*(MUINT32 *)(uintptr_t)(*(feature_data + 1))
				= (imgsensor_info.pre.framelength << 16)
					+ imgsensor_info.pre.linelength;
			break;
		}
		break;
	case SENSOR_FEATURE_GET_PERIOD:
		*feature_return_para_16++ = imgsensor.line_length;
		*feature_return_para_16 = imgsensor.frame_length;
		*feature_para_len = 4;
		break;
	case SENSOR_FEATURE_GET_PIXEL_CLOCK_FREQ:
		*feature_return_para_32 = imgsensor.pclk;
		*feature_para_len = 4;
		break;

	case SENSOR_FEATURE_GET_MIPI_PIXEL_RATE:
		{
			kal_uint32 rate;

			switch (*feature_data) {
			case MSDK_SCENARIO_ID_CAMERA_CAPTURE_JPEG:
				rate = imgsensor_info.cap.mipi_pixel_rate;
				break;
			case MSDK_SCENARIO_ID_VIDEO_PREVIEW:
				rate = imgsensor_info.normal_video.mipi_pixel_rate;
				break;
			case MSDK_SCENARIO_ID_HIGH_SPEED_VIDEO:
				rate = imgsensor_info.hs_video.mipi_pixel_rate;
				break;
			case MSDK_SCENARIO_ID_SLIM_VIDEO:
				rate = imgsensor_info.slim_video.mipi_pixel_rate;
				break;
			case MSDK_SCENARIO_ID_CUSTOM1:
				rate = imgsensor_info.custom1.mipi_pixel_rate;
				break;
			case MSDK_SCENARIO_ID_CAMERA_PREVIEW:
			default:
				rate = imgsensor_info.pre.mipi_pixel_rate;
				break;
			}
			*(MUINT32 *)(uintptr_t)(*(feature_data + 1)) = rate;
		}
		break;
	case SENSOR_FEATURE_SET_STREAMING_SUSPEND:
		LOG_INF("SENSOR_FEATURE_SET_STREAMING_SUSPEND\n");
		streaming_control(KAL_FALSE);
		break;
	case SENSOR_FEATURE_SET_STREAMING_RESUME:
		LOG_INF("SENSOR_FEATURE_SET_STREAMING_RESUME, shutter:%llu\n", *feature_data);
		if (*feature_data != 0)
			set_shutter(*feature_data);
		streaming_control(KAL_TRUE);
		break;
	case SENSOR_FEATURE_SET_ESHUTTER:
		set_shutter(*feature_data);
		break;
	case SENSOR_FEATURE_SET_NIGHTMODE:
		night_mode((BOOL)*feature_data);
		break;
	case SENSOR_FEATURE_SET_GAIN:
		set_gain((UINT16)*feature_data);
		break;
	case SENSOR_FEATURE_SET_FLASHLIGHT:
		break;
	case SENSOR_FEATURE_SET_ISP_MASTER_CLOCK_FREQ:
		break;
	case SENSOR_FEATURE_SET_SHUTTER_FRAME_TIME:
		set_shutter_frame_length((UINT16) (*feature_data), (UINT16) (*(feature_data + 1)));
		break;
	case SENSOR_FEATURE_SET_REGISTER:
		write_cmos_sensor(sensor_reg_data->RegAddr, sensor_reg_data->RegData);
		break;
	case SENSOR_FEATURE_GET_REGISTER:
		sensor_reg_data->RegData = read_cmos_sensor(sensor_reg_data->RegAddr);
		LOG_INF("adb_i2c_read 0x%x = 0x%x\n",
			sensor_reg_data->RegAddr, sensor_reg_data->RegData);
		break;
	case SENSOR_FEATURE_GET_LENS_DRIVER_ID:
		/* get the lens driver ID from EEPROM or just return LENS_DRIVER_ID_DO_NOT_CARE */
		/* if EEPROM does not exist in camera module. */
		*feature_return_para_32 = LENS_DRIVER_ID_DO_NOT_CARE;
		*feature_para_len = 4;
		break;
	case SENSOR_FEATURE_SET_VIDEO_MODE:
		set_video_mode(*feature_data);
		break;
	case SENSOR_FEATURE_CHECK_SENSOR_ID:
		get_imgsensor_id(feature_return_para_32);
		break;
	case SENSOR_FEATURE_SET_AUTO_FLICKER_MODE:
		set_auto_flicker_mode((BOOL)*feature_data_16, *(feature_data_16 + 1));
		break;
	case SENSOR_FEATURE_SET_MAX_FRAME_RATE_BY_SCENARIO:
		 set_max_framerate_by_scenario(
				(enum MSDK_SCENARIO_ID_ENUM)*feature_data,
				*(feature_data+1));
		break;
	case SENSOR_FEATURE_GET_DEFAULT_FRAME_RATE_BY_SCENARIO:
		get_default_framerate_by_scenario((enum MSDK_SCENARIO_ID_ENUM)*(feature_data),
			(MUINT32 *)(uintptr_t)(*(feature_data + 1)));
		break;
	case SENSOR_FEATURE_SET_TEST_PATTERN:
		set_test_pattern_mode((BOOL)*feature_data);
		break;
	case SENSOR_FEATURE_GET_TEST_PATTERN_CHECKSUM_VALUE: /*for factory mode auto testing */
		*feature_return_para_32 = imgsensor_info.checksum_value;
		*feature_para_len = 4;
		break;
	case SENSOR_FEATURE_SET_FRAMERATE:
		LOG_INF("current fps :%d\n", (UINT32)*feature_data);
		spin_lock(&imgsensor_drv_lock);
		imgsensor.current_fps = *feature_data;
		spin_unlock(&imgsensor_drv_lock);
		break;
	case SENSOR_FEATURE_SET_HDR:
		LOG_INF("ihdr enable :%d\n", (BOOL)*feature_data);
		spin_lock(&imgsensor_drv_lock);
		imgsensor.ihdr_en = (BOOL)*feature_data;
		spin_unlock(&imgsensor_drv_lock);
		break;
	case SENSOR_FEATURE_GET_CROP_INFO:
		LOG_INF("SENSOR_FEATURE_GET_CROP_INFO scenarioId:%d\n",
			(UINT32)*feature_data);
		wininfo =
			(struct SENSOR_WINSIZE_INFO_STRUCT *)(uintptr_t)(*(feature_data+1));
		switch (*feature_data_32) {
		case MSDK_SCENARIO_ID_CAMERA_CAPTURE_JPEG:
			memcpy((void *)wininfo, (void *)&imgsensor_winsize_info[1],
				sizeof(struct SENSOR_WINSIZE_INFO_STRUCT));
			break;
		case MSDK_SCENARIO_ID_VIDEO_PREVIEW:
			memcpy((void *)wininfo, (void *)&imgsensor_winsize_info[2],
				sizeof(struct SENSOR_WINSIZE_INFO_STRUCT));
			break;
		case MSDK_SCENARIO_ID_HIGH_SPEED_VIDEO:
			memcpy((void *)wininfo, (void *)&imgsensor_winsize_info[3],
				sizeof(struct SENSOR_WINSIZE_INFO_STRUCT));
			break;
		case MSDK_SCENARIO_ID_SLIM_VIDEO:
			memcpy((void *)wininfo, (void *)&imgsensor_winsize_info[4],
				sizeof(struct SENSOR_WINSIZE_INFO_STRUCT));
			break;
		case MSDK_SCENARIO_ID_CUSTOM1:
			memcpy((void *)wininfo, (void *)&imgsensor_winsize_info[5],
				sizeof(struct SENSOR_WINSIZE_INFO_STRUCT));
			break;
		case MSDK_SCENARIO_ID_CAMERA_PREVIEW:
		default:
			memcpy((void *)wininfo, (void *)&imgsensor_winsize_info[0],
				sizeof(struct SENSOR_WINSIZE_INFO_STRUCT));
			break;
		}
		break;
	case SENSOR_FEATURE_SET_IHDR_SHUTTER_GAIN:
		LOG_INF("SENSOR_SET_SENSOR_IHDR LE=%d, SE=%d, Gain=%d\n",
			(UINT16)*feature_data, (UINT16)*(feature_data + 1),
				(UINT16)*(feature_data + 2));
		ihdr_write_shutter_gain
			((UINT16)*feature_data, (UINT16)*(feature_data + 1),
				(UINT16)*(feature_data + 2));
		break;
	case SENSOR_FEATURE_GET_AWB_REQ_BY_SCENARIO:
		*(MUINT32 *)(uintptr_t)(*(feature_data + 1)) = 0;
		break;
	default:
		break;
	}

	return ERROR_NONE;
}

static struct SENSOR_FUNCTION_STRUCT sensor_func = {
	open,
	get_info,
	get_resolution,
	feature_control,
	control,
	close
};
UINT32 GC8054_MIPI_RAW_SensorInit(struct SENSOR_FUNCTION_STRUCT **pfFunc)
{
	/* To Do : Check Sensor status here */
	if (pfFunc != NULL)
		*pfFunc = &sensor_func;
	return ERROR_NONE;
}
