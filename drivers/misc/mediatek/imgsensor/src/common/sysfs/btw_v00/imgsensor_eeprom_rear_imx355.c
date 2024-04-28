#include "imgsensor_eeprom_rear_imx355.h"

#define REAR_IMX355_MAX_CAL_SIZE               (0x08AF + 0x1)

#define REAR_IMX355_HEADER_CHECKSUM_LEN        (0x00FB - 0x0000 + 0x1)
#define REAR_IMX355_AWB_CHECKSUM_LEN           (0x028B - 0x0270 + 0x1)
#define REAR_IMX355_LSC_CHECKSUM_LEN           (0x068B - 0x0290 + 0x1)		
#define REAR_IMX355_OEM_CHECKSUM_LEN           (0x026B - 0x01F0 + 0x1)

#define REAR_IMX355_CONVERTED_MAX_CAL_SIZE     (0x0BFF + 0x1)
#define REAR_IMX355_CONVERTED_AWB_CHECKSUM_LEN (0x027B - 0x0270 + 0x1)
#define REAR_IMX355_CONVERTED_LSC_CHECKSUM_LEN (0x09DB - 0x0280 + 0x1)

const struct rom_converted_cal_addr rear_imx355_converted_cal_addr = {
	.rom_awb_cal_data_start_addr            = 0x0270,
	.rom_awb_checksum_addr                  = 0x027C,
	.rom_awb_checksum_len                   = (REAR_IMX355_CONVERTED_AWB_CHECKSUM_LEN),
	.rom_shading_cal_data_start_addr        = 0x0280,
	.rom_shading_checksum_addr              = 0x09DC,
	.rom_shading_checksum_len               = (REAR_IMX355_CONVERTED_LSC_CHECKSUM_LEN),
};

const struct rom_sac_cal_addr rear_imx355_sac_addr = {
	.rom_mode_addr = 0x0224,
	.rom_time_addr = 0x0225,
};

const struct imgsensor_vendor_rom_addr rear_imx355_cal_addr = {
	/* Set '-1' if not used */
	.camera_module_es_version               = 'A',
	.cal_map_es_version                     = '1',
	.rom_max_cal_size                       = REAR_IMX355_MAX_CAL_SIZE,
	.rom_header_cal_data_start_addr         = 0x00,
	.rom_header_main_module_info_start_addr = 0x56,
	.rom_header_cal_map_ver_start_addr      = 0x90,
	.rom_header_project_name_start_addr     = 0x98,
	.rom_header_module_id_addr              = 0xAE,
	.rom_header_main_sensor_id_addr         = 0xB8,

	.rom_header_sub_module_info_start_addr  = -1,
	.rom_header_sub_sensor_id_addr          = -1,

	.rom_header_main_header_start_addr      = -1,
	.rom_header_main_header_end_addr        = -1,
	.rom_header_main_oem_start_addr         = 0x18,
	.rom_header_main_oem_end_addr           = 0x1C,
	.rom_header_main_awb_start_addr         = 0x20,
	.rom_header_main_awb_end_addr           = 0x24,
	.rom_header_main_shading_start_addr     = 0x28,
	.rom_header_main_shading_end_addr       = 0x2C,
	.rom_header_main_sensor_cal_start_addr  = -1,
	.rom_header_main_sensor_cal_end_addr    = -1,
	.rom_header_dual_cal_start_addr         = -1,
	.rom_header_dual_cal_end_addr           = -1,
	.rom_header_pdaf_cal_start_addr         = -1,
	.rom_header_pdaf_cal_end_addr           = -1,
	.rom_header_ois_cal_start_addr          = -1,
	.rom_header_ois_cal_end_addr            = -1,

	.rom_header_sub_oem_start_addr          = -1,
	.rom_header_sub_oem_end_addr            = -1,
	.rom_header_sub_awb_start_addr          = -1,
	.rom_header_sub_awb_end_addr            = -1,
	.rom_header_sub_shading_start_addr      = -1,
	.rom_header_sub_shading_end_addr        = -1,

	.rom_header_main_mtf_data_addr          = 0x01A8,
	.rom_header_sub_mtf_data_addr           = -1,

	.rom_header_checksum_addr               = 0x00FC,
	.rom_header_checksum_len                = REAR_IMX355_HEADER_CHECKSUM_LEN,

	.rom_oem_af_inf_position_addr           = 0x01FC,
	.rom_oem_af_macro_position_addr         = 0x0208,
	.rom_oem_module_info_start_addr         = -1,
	.rom_oem_checksum_addr                  = 0x026C,
	.rom_oem_checksum_len                   = REAR_IMX355_OEM_CHECKSUM_LEN,

	.rom_module_cal_data_start_addr         = -1,
	.rom_module_module_info_start_addr      = -1,
	.rom_module_checksum_addr               = -1,
	.rom_module_checksum_len                = -1,

	.rom_awb_cal_data_start_addr            = 0x0270,
	.rom_awb_module_info_start_addr         = -1,
	.rom_awb_checksum_addr                  = 0x028C,
	.rom_awb_checksum_len                   = REAR_IMX355_AWB_CHECKSUM_LEN,

	.rom_shading_cal_data_start_addr        = 0x0290,
	.rom_shading_module_info_start_addr     = -1,
	.rom_shading_checksum_addr              = 0x068C,
	.rom_shading_checksum_len               = REAR_IMX355_LSC_CHECKSUM_LEN,

	.rom_sensor_cal_module_info_start_addr  = -1,
	.rom_sensor_cal_checksum_addr           = -1,
	.rom_sensor_cal_checksum_len            = -1,

	.rom_dual_module_info_start_addr        = -1,
	.rom_dual_checksum_addr                 = -1,
	.rom_dual_checksum_len                  = -1,

	.rom_pdaf_module_info_start_addr        = -1,
	.rom_pdaf_checksum_addr                 = -1,
	.rom_pdaf_checksum_len                  = -1,
	.rom_ois_checksum_addr                  = -1,
	.rom_ois_checksum_len                   = -1,

	.rom_sub_oem_af_inf_position_addr       = -1,
	.rom_sub_oem_af_macro_position_addr     = -1,
	.rom_sub_oem_module_info_start_addr     = -1,
	.rom_sub_oem_checksum_addr              = -1,
	.rom_sub_oem_checksum_len               = -1,

	.rom_sub_awb_module_info_start_addr     = -1,
	.rom_sub_awb_checksum_addr              = -1,
	.rom_sub_awb_checksum_len               = -1,

	.rom_sub_shading_module_info_start_addr = -1,
	.rom_sub_shading_checksum_addr          = -1,
	.rom_sub_shading_checksum_len           = -1,

	.rom_dual_cal_data2_start_addr          = -1,
	.rom_dual_cal_data2_size                = -1,
	.rom_dual_tilt_x_addr                   = -1,
	.rom_dual_tilt_y_addr                   = -1,
	.rom_dual_tilt_z_addr                   = -1,
	.rom_dual_tilt_sx_addr                  = -1,
	.rom_dual_tilt_sy_addr                  = -1,
	.rom_dual_tilt_range_addr               = -1,
	.rom_dual_tilt_max_err_addr             = -1,
	.rom_dual_tilt_avg_err_addr             = -1,
	.rom_dual_tilt_dll_version_addr         = -1,
	.rom_dual_tilt_dll_modelID_addr         = -1,
	.rom_dual_tilt_dll_modelID_size         = -1,
	.rom_dual_shift_x_addr                  = -1,
	.rom_dual_shift_y_addr                  = -1,


	.crosstalk_cal_addr                     = NULL,
	.sac_cal_addr                           = &rear_imx355_sac_addr,
	.extend_cal_addr                        = NULL,

	.converted_cal_addr                     = &rear_imx355_converted_cal_addr,
	.rom_converted_max_cal_size             = REAR_IMX355_CONVERTED_MAX_CAL_SIZE,

	.sensor_maker                           = "SONY",
	.sensor_name                            = "IMX355",
	.sub_sensor_maker                       = NULL,
	.sub_sensor_name                        = NULL,

	.bayerformat                            = -1,
};
