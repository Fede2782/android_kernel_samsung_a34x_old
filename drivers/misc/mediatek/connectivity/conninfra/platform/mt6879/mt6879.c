// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2021 MediaTek Inc.
 */

#define pr_fmt(fmt) KBUILD_MODNAME "@(%s:%d) " fmt, __func__, __LINE__

#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/math64.h>
#include <linux/of.h>
#include <linux/types.h>
#include <mtk_clkbuf_ctl.h>
#include <linux/pm_runtime.h>

#include <connectivity_build_in_adapter.h>

#include "osal.h"
#include "conninfra.h"
#include "conninfra_conf.h"
#include "consys_hw.h"
#include "consys_reg_mng.h"
#include "consys_reg_util.h"

#include "mt6879.h"
#include "mt6879_pos.h"
#include "mt6879_consys_reg.h"
#include "mt6879_consys_reg_offset.h"
#include "mt6879_connsyslog.h"
#include "clock_mng.h"
#include "coredump_mng.h"

/*******************************************************************************
*                         C O M P I L E R   F L A G S
********************************************************************************
*/

/*******************************************************************************
*                                 M A C R O S
********************************************************************************
*/
#define PLATFORM_SOC_CHIP 0x6879

/*******************************************************************************
*                    E X T E R N A L   R E F E R E N C E S
********************************************************************************
*/

/*******************************************************************************
*                              C O N S T A N T S
********************************************************************************
*/

/*******************************************************************************
*                             D A T A   T Y P E S
********************************************************************************
*/

/*******************************************************************************
*                  F U N C T I O N   D E C L A R A T I O N S
********************************************************************************
*/
static int consys_clk_get_from_dts_mt6879(struct platform_device *pdev);
static int consys_clock_buffer_ctrl_mt6879(unsigned int enable);
static unsigned int consys_soc_chipid_get_mt6879(void);
static void consys_clock_fail_dump_mt6879(void);
static unsigned int consys_get_hw_ver_mt6879(void);
static int consys_thermal_query_mt6879(void);
/* Power state relative */
static int consys_enable_power_dump_mt6879(void);
static int consys_reset_power_state_mt6879(void);
static int consys_power_state_dump_mt6879(void);

static unsigned long long consys_soc_timestamp_get_mt6879(void);

static unsigned int consys_adie_detection_mt6879(void);
static void consys_set_mcu_control_mt6879(int type, bool onoff);
/*******************************************************************************
*                            P U B L I C   D A T A
********************************************************************************
*/

struct consys_hw_ops_struct g_consys_hw_ops_mt6879 = {
	/* load from dts */
	/* TODO: mtcmos should move to a independent module */
	.consys_plt_clk_get_from_dts = consys_clk_get_from_dts_mt6879,

	/* clock */
	.consys_plt_clock_buffer_ctrl = consys_clock_buffer_ctrl_mt6879,
	.consys_plt_co_clock_type = consys_co_clock_type_mt6879,

	/* POS */
	.consys_plt_conninfra_on_power_ctrl = consys_conninfra_on_power_ctrl_mt6879,
	.consys_plt_set_if_pinmux = consys_set_if_pinmux_mt6879,

	.consys_plt_polling_consys_chipid = consys_polling_chipid_mt6879,
	.consys_plt_d_die_cfg = connsys_d_die_cfg_mt6879,
	.consys_plt_spi_master_cfg = connsys_spi_master_cfg_mt6879,
	.consys_plt_a_die_cfg = connsys_a_die_cfg_mt6879,
	.consys_plt_afe_wbg_cal = connsys_afe_wbg_cal_mt6879,
	.consys_plt_subsys_pll_initial = connsys_subsys_pll_initial_mt6879,
	.consys_plt_low_power_setting = connsys_low_power_setting_mt6879,
	.consys_plt_soc_chipid_get = consys_soc_chipid_get_mt6879,
	.consys_plt_conninfra_wakeup = consys_conninfra_wakeup_mt6879,
	.consys_plt_conninfra_sleep = consys_conninfra_sleep_mt6879,
	.consys_plt_is_rc_mode_enable = consys_is_rc_mode_enable_mt6879,

	/* debug */
	.consys_plt_clock_fail_dump = consys_clock_fail_dump_mt6879,
	.consys_plt_get_hw_ver = consys_get_hw_ver_mt6879,

	.consys_plt_spi_read = consys_spi_read_mt6879,
	.consys_plt_spi_write = consys_spi_write_mt6879,
	.consys_plt_spi_update_bits = consys_spi_update_bits_mt6879,
	.consys_plt_spi_clock_switch = consys_spi_clock_switch_mt6879,
	.consys_plt_subsys_status_update = consys_subsys_status_update_mt6879,

	.consys_plt_thermal_query = consys_thermal_query_mt6879,
	.consys_plt_enable_power_dump = consys_enable_power_dump_mt6879,
	.consys_plt_reset_power_state = consys_power_state_dump_mt6879,
	.consys_plt_power_state = consys_power_state_dump_mt6879,
	.consys_plt_soc_timestamp_get = consys_soc_timestamp_get_mt6879,
	.consys_plt_adie_detection = consys_adie_detection_mt6879,
	.consys_plt_set_mcu_control = consys_set_mcu_control_mt6879,
};

extern struct consys_hw_ops_struct g_consys_hw_ops_mt6879;
extern struct consys_reg_mng_ops g_dev_consys_reg_ops_mt6879;
extern struct consys_platform_emi_ops g_consys_platform_emi_ops_mt6879;
extern struct consys_platform_pmic_ops g_consys_platform_pmic_ops_mt6879;
extern struct consys_platform_coredump_ops g_consys_platform_coredump_ops_mt6879;

const struct conninfra_plat_data mt6879_plat_data = {
	.chip_id = PLATFORM_SOC_CHIP,
	.consys_hw_version = CONN_HW_VER,
	.hw_ops = &g_consys_hw_ops_mt6879,
	.reg_ops = &g_dev_consys_reg_ops_mt6879,
	.platform_emi_ops = &g_consys_platform_emi_ops_mt6879,
	.platform_pmic_ops = &g_consys_platform_pmic_ops_mt6879,
	.platform_coredump_ops = &g_consys_platform_coredump_ops_mt6879,
	.connsyslog_config = &g_connsyslog_config,
};

static struct consys_plat_thermal_data_mt6879 g_consys_plat_therm_data;

int consys_co_clock_type_mt6879(void)
{
	const struct conninfra_conf *conf;

	struct regmap *map = consys_clock_mng_get_regmap();
	int value;

	/* Default solution */
	conf = conninfra_conf_get_cfg();
	if (NULL == conf) {
		pr_err("[%s] Get conf fail", __func__);
		return -1;
	}
	pr_info("[%s] conf->tcxo_gpio=%d conn_hw_env.tcxo_support=%d",
		__func__, conf->tcxo_gpio, conn_hw_env.tcxo_support);
	/* TODO: for co-clock mode, there are two case: 26M and 52M. Need something to distinguish it. */
	if (conf->tcxo_gpio != 0 || conn_hw_env.tcxo_support)
		return CONNSYS_CLOCK_SCHEMATIC_26M_EXTCXO;

	if (!map)
		pr_err("%s, failed to get regmap.\n", __func__);
	else {
		regmap_read(map, DCXO_DIGCLK_ELR, &value);
		if (value & 0x1)
			return CONNSYS_CLOCK_SCHEMATIC_52M_COTMS;
	}
	return CONNSYS_CLOCK_SCHEMATIC_26M_COTMS;
}

int consys_clk_get_from_dts_mt6879(struct platform_device *pdev)
{
	pm_runtime_enable(&pdev->dev);
	dev_pm_syscore_device(&pdev->dev, true);

	return 0;
}

int consys_platform_spm_conn_ctrl_mt6879(unsigned int enable)
{
	int ret = 0;
	struct platform_device *pdev = get_consys_device();

		if (!pdev) {
				pr_info("get_consys_device fail.\n");
				return -1;
		}

	if (enable) {
		ret = pm_runtime_get_sync(&(pdev->dev));
		if (ret)
			pr_info("pm_runtime_get_sync() fail(%d)\n", ret);
		else
			pr_info("pm_runtime_get_sync() CONSYS ok\n");

		ret = device_init_wakeup(&(pdev->dev), true);
		if (ret)
			pr_info("device_init_wakeup(true) fail.\n");
		else
			pr_info("device_init_wakeup(true) CONSYS ok\n");
	} else {
		ret = device_init_wakeup(&(pdev->dev), false);
		if (ret)
			pr_info("device_init_wakeup(false) fail.\n");
		else
			pr_info("device_init_wakeup(false) CONSYS ok\n");

		ret = pm_runtime_put_sync(&(pdev->dev));
		if (ret)
			pr_info("pm_runtime_put_sync() fail.\n");
		else
			pr_info("pm_runtime_put_sync() CONSYS ok\n");
	}
	return ret;
}

int consys_clock_buffer_ctrl_mt6879(unsigned int enable)
{
	/* This function call didn't work now.
	 * clock buffer is HW controlled, not SW controlled.
	 * Keep this function call to update status.
	 */
#if (!COMMON_KERNEL_CLK_SUPPORT)
	if (enable)
		KERNEL_clk_buf_ctrl(CLK_BUF_CONN, true);	/*open XO_WCN*/
	else
		KERNEL_clk_buf_ctrl(CLK_BUF_CONN, false);	/*close XO_WCN*/
#endif
	return 0;
}

unsigned int consys_soc_chipid_get_mt6879(void)
{
	return PLATFORM_SOC_CHIP;
}

void consys_clock_fail_dump_mt6879(void)
{
#if defined(KERNEL_clk_buf_show_status_info)
	KERNEL_clk_buf_show_status_info();
#endif
}

int consys_enable_power_dump_mt6879(void)
{
	/* Return success because sleep count dump is enable on POS */
	return 0;
}

int consys_reset_power_state_mt6879(void)
{
	/* Clear data and disable stop */
	/* I. Clear
	 * i.	Conn_infra:	0x1806_0384[15]
	 * ii.	Wf:			0x1806_0384[9]
	 * iii.	Bt:			0x1806_0384[10]
	 * iv.	Gps:		0x1806_0384[8]
	 */
	CONSYS_REG_WRITE_HW_ENTRY(
		CONN_HOST_CSR_TOP_HOST_CONN_INFRA_SLP_CNT_SLP_STOP_HOST_CR_CONN_INFRA_SLEEP_CNT_CLR,
		0x1);
	udelay(150);
	CONSYS_REG_WRITE_HW_ENTRY(
		CONN_HOST_CSR_TOP_HOST_CONN_INFRA_SLP_CNT_SLP_STOP_HOST_CR_CONN_INFRA_SLEEP_CNT_CLR,
		0x0);

	CONSYS_REG_WRITE_HW_ENTRY(
		CONN_HOST_CSR_TOP_HOST_CONN_INFRA_SLP_CNT_SLP_STOP_HOST_CR_WF_SLEEP_CNT_CLR,
		0x1);
	udelay(150);
	CONSYS_REG_WRITE_HW_ENTRY(
		CONN_HOST_CSR_TOP_HOST_CONN_INFRA_SLP_CNT_SLP_STOP_HOST_CR_WF_SLEEP_CNT_CLR,
		0x0);

	CONSYS_REG_WRITE_HW_ENTRY(
		CONN_HOST_CSR_TOP_HOST_CONN_INFRA_SLP_CNT_SLP_STOP_HOST_CR_BT_SLEEP_CNT_CLR,
		0x1);
	udelay(150);
	CONSYS_REG_WRITE_HW_ENTRY(
		CONN_HOST_CSR_TOP_HOST_CONN_INFRA_SLP_CNT_SLP_STOP_HOST_CR_BT_SLEEP_CNT_CLR,
		0x0);


	CONSYS_REG_WRITE_HW_ENTRY(
		CONN_HOST_CSR_TOP_HOST_CONN_INFRA_SLP_CNT_SLP_STOP_HOST_CR_GPS_SLEEP_CNT_CLR,
		0x1);
	udelay(150);
	CONSYS_REG_WRITE_HW_ENTRY(
		CONN_HOST_CSR_TOP_HOST_CONN_INFRA_SLP_CNT_SLP_STOP_HOST_CR_GPS_SLEEP_CNT_CLR,
		0x0);
	/* II. Stop
	 * i.	Conn_infra:	0x1806_0384[7]
	 * ii.	Wf:			0x1806_0384[1]
	 * iii.	Bt:			0x1806_0384[2]
	 * iv.	Gps:		0x1806_0384[0]
	 */
	CONSYS_REG_WRITE_HW_ENTRY(
		CONN_HOST_CSR_TOP_HOST_CONN_INFRA_SLP_CNT_SLP_STOP_HOST_CR_CONN_INFRA_SLEEP_CNT_STOP,
		0x0);
	CONSYS_REG_WRITE_HW_ENTRY(
		CONN_HOST_CSR_TOP_HOST_CONN_INFRA_SLP_CNT_SLP_STOP_HOST_CR_WF_SLEEP_CNT_STOP,		
		0x0);
	CONSYS_REG_WRITE_HW_ENTRY(
		CONN_HOST_CSR_TOP_HOST_CONN_INFRA_SLP_CNT_SLP_STOP_HOST_CR_BT_SLEEP_CNT_STOP,
		0x0);
	CONSYS_REG_WRITE_HW_ENTRY(
		CONN_HOST_CSR_TOP_HOST_CONN_INFRA_SLP_CNT_SLP_STOP_HOST_CR_GPS_SLEEP_CNT_STOP,
		0x0);
	return 0;
}

static inline void __sleep_count_trigger_read(void)
{
	CONSYS_REG_WRITE_HW_ENTRY(
		CONN_HOST_CSR_TOP_HOST_CONN_INFRA_SLP_CNT_CTL_HOST_SLP_COUNTER_RD_TRIGGER, 0x1);
	udelay(150);
	CONSYS_REG_WRITE_HW_ENTRY(
		CONN_HOST_CSR_TOP_HOST_CONN_INFRA_SLP_CNT_CTL_HOST_SLP_COUNTER_RD_TRIGGER, 0x0);

}

static void consys_power_state(void)
{
#if 0
	unsigned int i, str_len;
	unsigned int buf_len = 0;
	unsigned int r;
	const char* osc_str[] = {
		  "fm ", "gps ", "bgf ", "wf ", "ap2conn ", "conn_thm ", "conn_pta ", "conn_infra_bus "};
	char buf[256] = {'\0'};

	CONSYS_REG_WRITE_HW_ENTRY(CONN_HOST_CSR_TOP_CONN_INFRA_CFG_DBG_SEL_CONN_INFRA_CFG_DBG_SEL,
								  0x0);
	r = CONSYS_REG_READ(CONN_HOST_CSR_TOP_DBG_DUMMY_2_ADDR);

	for (i = 0; i < 8; i++) {
		str_len = strlen(osc_str[i]);
		if ((r & (0x1 << (18 + i))) > 0 && (buf_len + str_len < 256)) {
			strncat(buf, osc_str[i], str_len);
			buf_len += str_len;
		}
	}
	pr_info("[%s] [0x%x] %s", __func__, r, buf);
#endif
}

int consys_power_state_dump_mt6879(void)
{
	static u64 round = 0;
	static u64 t_conninfra_sleep_cnt = 0, t_conninfra_sleep_time = 0;
	static u64 t_wf_sleep_cnt = 0, t_wf_sleep_time = 0;
	static u64 t_bt_sleep_cnt = 0, t_bt_sleep_time = 0;
	static u64 t_gps_sleep_cnt = 0, t_gps_sleep_time = 0;
	unsigned int conninfra_sleep_cnt, conninfra_sleep_time;
	unsigned int wf_sleep_cnt, wf_sleep_time;
	unsigned int bt_sleep_cnt, bt_sleep_time;
	unsigned int gps_sleep_cnt, gps_sleep_time;

	/* Sleep count */
	/* 1. Setup read select: 0x1806_0380[3:1]
	 * 	3'h0: conn_infra sleep counter
	 * 	3'h1: wfsys sleep counter
	 * 	3'h2: bgfsys sleep counter
	 * 	3'h3: gpssys sleep counter
	 * 2. Dump time and count
	 * 	a. Timer: 0x1806_0388
	 * 	b. Count: 0x1806_038C
	 */
	CONSYS_REG_WRITE_HW_ENTRY(
		CONN_HOST_CSR_TOP_HOST_CONN_INFRA_SLP_CNT_CTL_HOST_SLP_COUNTER_SEL,
		0x0);
	__sleep_count_trigger_read();
	conninfra_sleep_time = CONSYS_REG_READ(
		CONN_HOST_CSR_TOP_HOST_CONN_INFRA_SLP_TIMER_ADDR);
	conninfra_sleep_cnt = CONSYS_REG_READ(
		CONN_HOST_CSR_TOP_HOST_CONN_INFRA_SLP_COUNTER_ADDR);
	t_conninfra_sleep_time += conninfra_sleep_time;
	t_conninfra_sleep_cnt += conninfra_sleep_cnt;


	CONSYS_REG_WRITE_HW_ENTRY(
		CONN_HOST_CSR_TOP_HOST_CONN_INFRA_SLP_CNT_CTL_HOST_SLP_COUNTER_SEL,
		0x1);
	__sleep_count_trigger_read();
	wf_sleep_time = CONSYS_REG_READ(
		CONN_HOST_CSR_TOP_HOST_CONN_INFRA_SLP_TIMER_ADDR);
	wf_sleep_cnt = CONSYS_REG_READ(
		CONN_HOST_CSR_TOP_HOST_CONN_INFRA_SLP_COUNTER_ADDR);
	t_wf_sleep_time += wf_sleep_time;
	t_wf_sleep_cnt += wf_sleep_cnt;

	CONSYS_REG_WRITE_HW_ENTRY(
		CONN_HOST_CSR_TOP_HOST_CONN_INFRA_SLP_CNT_CTL_HOST_SLP_COUNTER_SEL,
		0x2);
	__sleep_count_trigger_read();
	bt_sleep_time = CONSYS_REG_READ(
		CONN_HOST_CSR_TOP_HOST_CONN_INFRA_SLP_TIMER_ADDR);
	bt_sleep_cnt = CONSYS_REG_READ(
		CONN_HOST_CSR_TOP_HOST_CONN_INFRA_SLP_COUNTER_ADDR);
	t_bt_sleep_time += bt_sleep_time;
	t_bt_sleep_cnt += bt_sleep_cnt;

	CONSYS_REG_WRITE_HW_ENTRY(
		CONN_HOST_CSR_TOP_HOST_CONN_INFRA_SLP_CNT_CTL_HOST_SLP_COUNTER_SEL,
		0x3);
	__sleep_count_trigger_read();
	gps_sleep_time = CONSYS_REG_READ(
		CONN_HOST_CSR_TOP_HOST_CONN_INFRA_SLP_TIMER_ADDR);
	gps_sleep_cnt = CONSYS_REG_READ(
		CONN_HOST_CSR_TOP_HOST_CONN_INFRA_SLP_COUNTER_ADDR);
	t_gps_sleep_time += gps_sleep_time;
	t_gps_sleep_cnt += gps_sleep_cnt;

	pr_info("[consys_power_state][round:%llu]conninfra:%u,%u;wf:%u,%u;bt:%u,%u;gps:%u,%u;",
		round,
		conninfra_sleep_time, conninfra_sleep_cnt,
		wf_sleep_time, wf_sleep_cnt,
		bt_sleep_time, bt_sleep_cnt,
		gps_sleep_time, gps_sleep_cnt);
	pr_info("[consys_power_state][total]conninfra:%llu,%llu;wf:%llu,%llu;bt:%llu,%llu;gps:%llu,%llu;",
		t_conninfra_sleep_time, t_conninfra_sleep_cnt,
		t_wf_sleep_time, t_wf_sleep_cnt,
		t_bt_sleep_time, t_bt_sleep_cnt,
		t_gps_sleep_time, t_gps_sleep_cnt);

	/* Power state */
	consys_power_state();
	round++;

	/* reset after sleep time is accumulated. */
	consys_reset_power_state_mt6879();

	return 0;
}

unsigned int consys_get_hw_ver_mt6879(void)
{
	return CONN_HW_VER;
}

void update_thermal_data_mt6879(struct consys_plat_thermal_data_mt6879* input)
{
	memcpy(&g_consys_plat_therm_data, input, sizeof(struct consys_plat_thermal_data_mt6879));
}

static int calculate_thermal_temperature(int y)
{
	struct consys_plat_thermal_data_mt6879 *data = &g_consys_plat_therm_data;
	int t;
	int const_offset = 30;

	/* temperature = (y-b)*slope + (offset) */
	/* Postpone division to avoid getting wrong slope becasue of integer division */
	t = (y - (data->thermal_b == 0 ? 0x38 : data->thermal_b)) *
			(data->slop_molecule + 1866) / 1000 + const_offset;

	pr_info("y=[%d] b=[%d] constOffset=[%d] [%d] [%d] => t=[%d]\n",
			y, data->thermal_b, const_offset, data->slop_molecule, data->offset,
			t);

	return t;
}

int consys_thermal_query_mt6879(void)
{
#define THERMAL_DUMP_NUM		11
#define LOG_TMP_BUF_SZ			256
#define TEMP_SIZE				13
#define CONN_GPT2_CTRL_BASE		0x18007000
#define CONN_GPT2_CTRL_AP_EN	0x38

	void __iomem *addr = NULL;
	int cal_val, res = 0;
	/* Base: 0x1800_2000, CONN_TOP_THERM_CTL */
	const unsigned int thermal_dump_crs[THERMAL_DUMP_NUM] = {
		0x00, 0x04, 0x08, 0x0c,
		0x10, 0x14, 0x18, 0x1c,
		0x20, 0x24, 0x28,
	};
	char tmp[TEMP_SIZE] = {'\0'};
	char tmp_buf[LOG_TMP_BUF_SZ] = {'\0'};
	unsigned int i;
	unsigned int efuse0, efuse1, efuse2, efuse3;

	addr = ioremap(CONN_GPT2_CTRL_BASE, 0x100);
	if (addr == NULL) {
		pr_err("GPT2_CTRL_BASE remap fail");
		return -1;
	}

	connsys_adie_top_ck_en_ctl_mt6879(true);

	/* Hold Semaphore, TODO: may not need this, because
		thermal cr seperate for different  */
	if (consys_sema_acquire_timeout_mt6879(CONN_SEMA_THERMAL_INDEX, CONN_SEMA_TIMEOUT) == CONN_SEMA_GET_FAIL) {
		pr_err("[THERM QRY] Require semaphore fail\n");
		connsys_adie_top_ck_en_ctl_mt6879(false);
		iounmap(addr);
		return -1;
	}

	/* therm cal en */
	CONSYS_SET_BIT(CONN_THERM_CTL_THERMEN3_ADDR, (0x1 << 19));
	/* GPT2 En */
	CONSYS_REG_WRITE(addr + CONN_GPT2_CTRL_AP_EN, 0x1);

	/* thermal trigger */
	CONSYS_SET_BIT(CONN_THERM_CTL_THERMEN3_ADDR, (0x1 << 18));
	udelay(500);
	/* get thermal value */
	cal_val = CONSYS_REG_READ(CONN_THERM_CTL_THERMEN3_ADDR);
	cal_val = (cal_val >> 8) & 0x7f;

	/* thermal debug dump */
	efuse0 = CONSYS_REG_READ(CONN_INFRA_SYSRAM_SW_CR_A_DIE_EFUSE_DATA_0);
	efuse1 = CONSYS_REG_READ(CONN_INFRA_SYSRAM_SW_CR_A_DIE_EFUSE_DATA_1);
	efuse2 = CONSYS_REG_READ(CONN_INFRA_SYSRAM_SW_CR_A_DIE_EFUSE_DATA_2);
	efuse3 = CONSYS_REG_READ(CONN_INFRA_SYSRAM_SW_CR_A_DIE_EFUSE_DATA_3);
	for (i = 0; i < THERMAL_DUMP_NUM; i++) {
		if (snprintf(
			tmp, TEMP_SIZE, "[0x%08x]",
			CONSYS_REG_READ(CONN_REG_CONN_THERM_CTL_ADDR + thermal_dump_crs[i])) >= 0)
			strncat(tmp_buf, tmp, strlen(tmp));
	}
	pr_info("[%s] efuse:[0x%08x][0x%08x][0x%08x][0x%08x] thermal dump: %s",
		__func__, efuse0, efuse1, efuse2, efuse3, tmp_buf);

	res = calculate_thermal_temperature(cal_val);

	/* GPT2 disable */
	CONSYS_REG_WRITE(addr + CONN_GPT2_CTRL_AP_EN, 0);

	/* disable */
	CONSYS_CLR_BIT(CONN_THERM_CTL_THERMEN3_ADDR, (0x1 << 19));

	consys_sema_release_mt6879(CONN_SEMA_THERMAL_INDEX);
	connsys_adie_top_ck_en_ctl_mt6879(false);

	iounmap(addr);

	return res;
}

static unsigned long long consys_soc_timestamp_get_mt6879(void)
{
#define TICK_PER_MS	(13000)
	void __iomem *addr = NULL;
	u32 tick_h = 0, tick_l = 0, tmp_h = 0;
	u64 timestamp = 0;

	/* 0x1c01_1000	sys_timer@13M (VLPSYS)
	 * - 0x0008	CNTCV_L	32	System counter count value low
	 * - 0x000C	CNTCV_H	32	System counter count value high
	 */
	addr = ioremap(0x1c011000, 0x10);
	if (addr) {
		do {
			tick_h = CONSYS_REG_READ(addr + 0x000c);
			tick_l = CONSYS_REG_READ(addr + 0x0008);
			tmp_h = CONSYS_REG_READ(addr + 0x000c);
		} while (tick_h != tmp_h);
		iounmap(addr);
	} else {
		pr_info("[%s] remap fail", __func__);
		return 0;
	}

	timestamp = ((((u64)tick_h << 32) & 0xFFFFFFFF00000000) | ((u64)tick_l & 0x00000000FFFFFFFF));
	do_div(timestamp, TICK_PER_MS);

	return timestamp;
}

static unsigned int consys_adie_detection_mt6879(void)
{
	return ADIE_6637;
}

unsigned int consys_get_adie_chipid_mt6879(void)
{
	return ADIE_6637;
}

static void consys_set_mcu_control_mt6879(int type, bool onoff)
{
	pr_info("[%s] Set mcu control type=[%d] onoff=[%d]\n", __func__, type, onoff);

	if (onoff) // Turn on
		CONSYS_SET_BIT(CONN_INFRA_SYSRAM_SW_CR_MCU_LOG_CONTROL, (0x1 << type));
	else // Turn off
		CONSYS_CLR_BIT(CONN_INFRA_SYSRAM_SW_CR_MCU_LOG_CONTROL, (0x1 << type));
}
