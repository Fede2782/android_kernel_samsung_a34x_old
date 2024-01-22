#include <linux/delay.h>
#include <linux/fs.h>
#include <linux/uaccess.h>

#include <linux/i2c.h>

#include <linux/of.h>
#include <linux/of_gpio.h>
#include <linux/vmalloc.h>
#include <linux/ctype.h>
#include <linux/crc32.h>

#include <linux/byteorder/generic.h>

#include <linux/syscalls.h>
#include <linux/file.h>
#include <linux/regulator/consumer.h>
#include <linux/firmware.h>

#include "cam_ois_mcu_fw.h"
#include "cam_ois_define.h"
#include "cam_ois_i2c.h"
#include "cam_ois_aois_if.h"
#include "cam_ois_power.h"
#include "cam_ois_common.h"

/* Flash memory page(or sector) structure */
struct sysboot_page_type memory_pages[] = {
	{2048, 32},
	{   0,  0}
};

struct sysboot_map_type memory_map = {
	0x08000000, /* flash memory starting address */
	0x1FFF0000, /* system memory starting address */
	0x1FFF7800, /* option byte starting address */
	(struct sysboot_page_type *)memory_pages,
};

uint8_t sysboot_checksum(uint8_t *src, uint32_t len)
{
	uint8_t csum = *src++;

	if (len)
		while (--len)
			csum ^= *src++;
	else
		csum = 0; /* error (no length param) */

	return csum;
}

int sysboot_connect(struct mcu_info *mcu_info, struct i2c_client *client)
{
	int ret = 0;

	LOG_INF(" - E");
	return ret;
}

int sysboot_disconnect(struct mcu_info *mcu_info)
{
	int ret = 0;

	LOG_INF(" - E");
	return ret;
}

int sysboot_i2c_sync(struct i2c_client *client, uint8_t *cmd)
{
	int ret = 0;

	LOG_INF("E");
	/* set it and wait for it to be so */
	ret = cam_ois_i2c_master_send(client, cmd, 1);
	LOG_INF("i2c client addr 0x%x ", client->addr);
	if (ret >= 0)
		LOG_ERR("success connect to target mcu ");
	else
		LOG_ERR("failed connect to target mcu ");
	return ret;
}

static int sysboot_i2c_wait_ack(struct i2c_client *client, unsigned long timeout)
{
	int ret = 0;
	uint32_t retry = 3;
	unsigned char resp = 0;
	unsigned long end = jiffies + timeout;

	while (retry--) {
		ret = cam_ois_i2c_master_recv(client, &resp, 1);
		if (ret >= 0 && resp == BOOT_I2C_RESP_ACK) {
			LOG_INF("[mcu] wait ack success. resp: 0x%x\n", resp);
			return 0;
		}

		LOG_ERR("[mcu] failed resp is 0x%x ,ret is %d\n", resp, ret);
		if (time_after(jiffies, end)) {
			LOG_INF("[mcu] timeout.\n");
			ret = -ETIMEDOUT;
			break;
		}
		usleep_range(BOOT_I2C_INTER_PKT_BACK_INTVL * 1000,
			BOOT_I2C_INTER_PKT_BACK_INTVL * 1000 + 1000);

	}
	return -1;
}

static int sysboot_i2c_get_info(struct mcu_info *mcu_info, struct i2c_client *client,
	uint8_t *cmd, uint32_t cmd_size, uint32_t data_size)
{
	uint8_t recv[BOOT_I2C_RESP_GET_ID_LEN] = {0, };
	int ret = 0;
	int retry = 0;

	LOG_INF("info 0 0x%x 0x%x", cmd[0], cmd[1]);
	for (retry = 0; retry < BOOT_I2C_SYNC_RETRY_COUNT; ++retry) {
		/* transmit command */
		ret = cam_ois_i2c_master_send(client, cmd, cmd_size);
		if (ret < 0) {
			LOG_ERR("info 1 send data fail ret = %d", ret);
			msleep(BOOT_I2C_SYNC_RETRY_INTVL);
			continue;
		}
		usleep_range(1100, 1500);
		/* wait for ACK response */
		ret = sysboot_i2c_wait_ack(client, BOOT_I2C_WAIT_RESP_TMOUT);
		if (ret < 0) {
			LOG_ERR("info 2 wait ack fail ret = %d", ret);
			msleep(BOOT_I2C_SYNC_RETRY_INTVL);
			continue;
		}
		usleep_range(100, 500);
		/* receive payload */
		ret = cam_ois_i2c_master_recv(client, recv, data_size);
		if (ret < 0) {
			LOG_ERR("info 3 receive payload fail ret = %d", ret);
			msleep(BOOT_I2C_SYNC_RETRY_INTVL);
			continue;
		}

		usleep_range(1100, 1500);
		/* wait for ACK response */
		ret = sysboot_i2c_wait_ack(client, BOOT_I2C_WAIT_RESP_TMOUT);
		if (ret < 0) {
			LOG_ERR("info 4 wait ack fail ret = %d", ret);
			msleep(BOOT_I2C_SYNC_RETRY_INTVL);
			continue;
		}
		usleep_range(100, 500);

		if (cmd[0] == BOOT_I2C_CMD_GET_ID) {
			memcpy((void *)&(mcu_info->id), &recv[1], recv[0] + 1);
			mcu_info->id = NTOHS(mcu_info->id);
			LOG_INF("success get info id %d", mcu_info->id);
		} else if (cmd[0] == BOOT_I2C_CMD_GET_VER) {
			memcpy((void *)&(mcu_info->ver), recv, 1);
			LOG_INF("success get info version %d", mcu_info->ver);
		}

		return 0;
	}

	return ret + cmd[0];
}

static int cam_ois_mcu_chip_command(struct mcu_info *mcu_info, struct i2c_client *client, int command)
{
	/* build command */
	uint8_t cmd[BOOT_I2C_REQ_CMD_LEN] = {0, };
	int ret = 0;

	LOG_INF("[mcu] command %d\n", command);

	/* execute the command */
	switch (command) {
	case BOOT_I2C_CMD_GET:
		cmd[0] = 0x00;
		break;

	case BOOT_I2C_CMD_GET_VER:
		cmd[0] = 0x01;
		cmd[1] = ~cmd[0];
		ret = sysboot_i2c_get_info(mcu_info, client, cmd, 2, 1);
		break;

	case BOOT_I2C_CMD_GET_ID:
		cmd[0] = 0x02;
		cmd[1] = ~cmd[0];
		ret = sysboot_i2c_get_info(mcu_info, client, cmd, 2, 3);
		break;

	case BOOT_I2C_CMD_READ:
		cmd[0] = 0x11;
		break;

	case BOOT_I2C_CMD_WRITE:
		cmd[0] = 0x31;
		break;

	case BOOT_I2C_CMD_ERASE:
		cmd[0] = 0x44;
		break;

	case BOOT_I2C_CMD_GO:
		cmd[0] = 0x21;
		break;

	case BOOT_I2C_CMD_WRITE_UNPROTECT:
		cmd[0] = 0x73;
		break;

	case BOOT_I2C_CMD_READ_UNPROTECT:
		cmd[0] = 0x92;
		break;

	case BOOT_I2C_CMD_SYNC:
		/* UNKNOWN command */
		cmd[0] = 0xFF;
		ret = sysboot_i2c_sync(client, cmd);
		break;

	default:
		break;
		return -EINVAL;
	}

	return ret;
}

int sysboot_i2c_info(struct mcu_info *mcu_info, struct i2c_client *client)
{
	int ret = 0;

	LOG_INF("E\n");
	mcu_info->ver = 0;
	mcu_info->id = 0;
	ret = cam_ois_mcu_chip_command(mcu_info, client, BOOT_I2C_CMD_GET_ID);
	ret |= cam_ois_mcu_chip_command(mcu_info, client, BOOT_I2C_CMD_GET_VER);
	if (ret)
		ret = -1;

	LOG_INF("mcu pid 0x%x(0x456), mcu version 0x%x(0x12)", mcu_info->id, mcu_info->ver);
	return ret;
}

int mcu_validation(struct mcu_info *mcu_info, struct i2c_client *client)
{
	int ret = 0;

	LOG_INF("Start target validation");
	/* Connection ------------------------------------------------------------- */
	ret = sysboot_connect(mcu_info, client);
	if (ret < 0) {
		LOG_INF("Error: Cannot connect to the target (%d) but skip", ret);
		goto validation_fail;
	}
	LOG_INF("1. Connection OK");

	ret = sysboot_i2c_info(mcu_info, client);
	if (ret < 0) {
		LOG_INF("Error: Failed to collect the target info (%d)", ret);
		goto validation_fail;
	}

	LOG_INF("2. Get target info OK Target PID: 0x%X, Bootloader version: 0x%X", mcu_info->id, mcu_info->ver);

	return 0;

validation_fail:
	sysboot_disconnect(mcu_info);
	LOG_ERR(" Failed: target disconnected");

	return -1;
}

int sysboot_i2c_read(struct i2c_client *client, uint32_t address, uint8_t *dst, size_t len)
{
	uint8_t cmd[BOOT_I2C_REQ_CMD_LEN] = {0, }; //BOOT_I2C_REQ_CMD_LEN = 2
	uint8_t startaddr[BOOT_I2C_REQ_ADDRESS_LEN] = {0, }; //BOOT_I2C_REQ_ADDRESS_LEN = 5
	uint8_t nbytes[BOOT_I2C_READ_PARAM_LEN] = {0, }; //BOOT_I2C_READ_PARAM_LEN = 2
	int ret = 0;
	int retry = 0;

	/* build command */
	cmd[0] = BOOT_I2C_CMD_READ;
	cmd[1] = ~cmd[0];

	/* build address + checksum */
	*(uint32_t *)startaddr = HTONL(address);
	startaddr[BOOT_I2C_ADDRESS_LEN] = sysboot_checksum(startaddr, BOOT_I2C_ADDRESS_LEN);

	/* build number of bytes + checksum */
	nbytes[0] = len - 1;
	nbytes[1] = ~nbytes[0];
	LOG_INF("read address 0x%x", address);

	for (retry = 0; retry < BOOT_I2C_SYNC_RETRY_COUNT; ++retry) {
		/* transmit command */
		ret = cam_ois_i2c_master_send(client, cmd, sizeof(cmd));
		if (ret < 0) {
			msleep(BOOT_I2C_SYNC_RETRY_INTVL);
			continue;
		}
		/* wait for ACK response */
		ret = sysboot_i2c_wait_ack(client, BOOT_I2C_WAIT_RESP_TMOUT);
		if (ret < 0) {
			msleep(BOOT_I2C_SYNC_RETRY_INTVL);
			continue;
		}
		/* transmit address */
		ret = cam_ois_i2c_master_send(client, startaddr, sizeof(startaddr));
		if (ret < 0) {
			msleep(BOOT_I2C_SYNC_RETRY_INTVL);
			continue;
		}
		/* wait for ACK response */
		ret = sysboot_i2c_wait_ack(client, BOOT_I2C_WAIT_RESP_TMOUT);
		if (ret < 0) {
			msleep(BOOT_I2C_SYNC_RETRY_INTVL);
			continue;
		}

		/* transmit number of bytes */
		ret = cam_ois_i2c_master_send(client, nbytes, sizeof(nbytes));
		if (ret < 0) {
			msleep(BOOT_I2C_SYNC_RETRY_INTVL);
			continue;
		}
		/* wait for ACK response */
		ret = sysboot_i2c_wait_ack(client, BOOT_I2C_WAIT_RESP_TMOUT);
		if (ret < 0) {
			msleep(BOOT_I2C_SYNC_RETRY_INTVL);
			continue;
		}

		/* receive payload */
		ret = cam_ois_i2c_master_recv(client, dst, len);
		if (ret < 0) {
			msleep(BOOT_I2C_SYNC_RETRY_INTVL);
			continue;
		}
		return 0;
	}

	return ret + BOOT_ERR_API_READ;
}

int sysboot_i2c_read_unprotect(struct i2c_client *client)
{
	uint8_t cmd[BOOT_I2C_REQ_CMD_LEN] = {0, };
	int ret = 0;
	int retry = 0;

	/* build command */
	cmd[0] = BOOT_I2C_CMD_READ_UNPROTECT;
	cmd[1] = ~cmd[0];
	LOG_INF("E");

	for (retry = 0; retry < BOOT_I2C_SYNC_RETRY_COUNT; ++retry) {
		/* transmit command */
		ret = cam_ois_i2c_master_send(client, cmd, sizeof(cmd));
		if (ret < 0) {
			msleep(BOOT_I2C_SYNC_RETRY_INTVL);
			continue;
		}
		/* wait for ACK response */
		ret = sysboot_i2c_wait_ack(client, BOOT_I2C_FULL_ERASE_TMOUT);
		if (ret < 0) {
			msleep(BOOT_I2C_SYNC_RETRY_INTVL);
			continue;
		}
		/* wait for ACK response */
		ret = sysboot_i2c_wait_ack(client, BOOT_I2C_FULL_ERASE_TMOUT);
		if (ret < 0) {
			msleep(BOOT_I2C_SYNC_RETRY_INTVL);
			continue;
		}

		return 0;
	}

	return ret + BOOT_ERR_API_READ_UNPROTECT;
}

int sysboot_i2c_write(struct i2c_client *client, uint32_t address, uint8_t *src, size_t len)
{
	uint8_t cmd[BOOT_I2C_REQ_CMD_LEN] = {0, };
	uint8_t startaddr[BOOT_I2C_REQ_ADDRESS_LEN] = {0, };
	int ret = 0;
	int retry = 0;
	char *buf = NULL;

	/* build command */
	cmd[0] = BOOT_I2C_CMD_WRITE;
	cmd[1] = ~cmd[0];

	/* build address + checksum */
	*(uint32_t *)startaddr = HTONL(address);
	startaddr[BOOT_I2C_ADDRESS_LEN] = sysboot_checksum(startaddr, BOOT_I2C_ADDRESS_LEN);

	/* build number of bytes + checksum */
	LOG_INF("mcu address = 0x%x", address);

	buf = kzalloc(len + 2, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;
	buf[0] = len - 1;
	memcpy(&buf[1], src, len);
	buf[len+1] = sysboot_checksum(buf, len + 1);

	for (retry = 0; retry < BOOT_I2C_SYNC_RETRY_COUNT; ++retry) {
		/* transmit command */
		ret = cam_ois_i2c_master_send(client, cmd, 2);
		if (ret < 0) {
			LOG_ERR("[mcu] txdata fail");
			msleep(BOOT_I2C_SYNC_RETRY_INTVL);
			continue;
		}
		/* wait for ACK response */
		ret = sysboot_i2c_wait_ack(client, BOOT_I2C_WAIT_RESP_TMOUT);
		if (ret < 0) {
			LOG_ERR("mcu_wait_ack fail after txdata");
			msleep(BOOT_I2C_SYNC_RETRY_INTVL);
			continue;
		}

		/* transmit address */
		ret = cam_ois_i2c_master_send(client, startaddr, 5);
		if (ret < 0) {
			LOG_ERR("txdata fail ");
			msleep(BOOT_I2C_SYNC_RETRY_INTVL);
			continue;
		}
		/* wait for ACK response */
		ret = sysboot_i2c_wait_ack(client, BOOT_I2C_WAIT_RESP_TMOUT);
		if (ret < 0) {
			LOG_ERR("mcu_wait_ack fail after txdata ");
			msleep(BOOT_I2C_SYNC_RETRY_INTVL);
			continue;
		}

		/* transmit number of bytes + datas */
		ret = cam_ois_i2c_master_send(client, buf, BOOT_I2C_WRITE_PARAM_LEN(len));
		if (ret < 0) {
			LOG_ERR("txdata fail ");
			msleep(BOOT_I2C_SYNC_RETRY_INTVL);
			continue;
		}
		//msleep(len);
		/* wait for ACK response */
		ret = sysboot_i2c_wait_ack(client, BOOT_I2C_WRITE_TMOUT);
		if (ret < 0) {
			LOG_ERR("mcu_wait_ack fail after txdata ");
			msleep(BOOT_I2C_SYNC_RETRY_INTVL);
			continue;
		}
		kfree(buf);

		return 0;
	}
	usleep_range(2000, 2100);
	kfree(buf);

	return ret + BOOT_ERR_API_WRITE;
}

int target_option_update(struct mcu_info *mcu_info, struct i2c_client *i2c_client)
{
	int ret = 0;
	uint32_t optionbyte = 0;
	int retry = 3;

	LOG_INF("read option byte begin ");

	for (retry = 0; retry < 3; retry++) {
		ret = sysboot_i2c_read(i2c_client, memory_map.optionbyte, (uint8_t *)&optionbyte, sizeof(optionbyte));
		if ((ret < 0) || ((optionbyte & 0xff) != 0xaa)) {
			ret = sysboot_i2c_read_unprotect(i2c_client);
			if (ret < 0)
				LOG_ERR("ois_mcu_read_unprotect failed");
			else
				LOG_INF("ois_mcu_read_unprotect ok");

			msleep(60);
			ret = sysboot_connect(mcu_info, i2c_client);
			//try connection again
			continue;
		}

		if (optionbyte & (1 << 24)) {
		/* Option byte write ---------------------------------------------------- */
			optionbyte &= ~(1 << 24);
			ret = sysboot_i2c_write(i2c_client, memory_map.optionbyte, (uint8_t *)&optionbyte,
									sizeof(optionbyte));
			if (ret < 0) {
				usleep_range(10000, 11000);
				continue;
			}
			LOG_INF("write option byte ok");
			//try connection again
		} else {
			LOG_INF("[mao]option byte is 0, return success");
			return 0;
		}
	}

	return ret;
}

int sysboot_conv_memory_map(uint32_t address, size_t len, struct sysboot_erase_param_type *erase)
{
	struct sysboot_page_type *map = memory_map.pages;
	int found = 0;
	int total_bytes = 0, total_pages = 0;
	int ix = 0;
	int unit = 0;

	LOG_INF("E");

	/* find out the matched starting page number and total page count */
	for (ix = 0; map[ix].size != 0; ++ix) {
		for (unit = 0; unit < map[ix].count; ++unit) {
			/* MATCH CASE: Starting address aligned and page number to be erased */
			if (address == memory_map.flashbase + total_bytes) {
				found++;
				erase->page = total_pages;
			}
			total_bytes += map[ix].size;
			total_pages++;
			/* MATCH CASE: End of page number to be erased */
			if ((found == 1) && (len <= total_bytes)) {
				found++;
				erase->count = total_pages - erase->page;
			}
		}
	}

	if (found < 2) {
		/* Not aligned address or too much length inputted */
		return BOOT_ERR_DEVICE_MEMORY_MAP;
	}

	if ((address == memory_map.flashbase) && (erase->count == total_pages))
		erase->page = 0xFFFF; /* mark the full erase */

	return 0;
}

int sysboot_i2c_erase(struct i2c_client *client, uint32_t address, size_t len)
{
	uint8_t cmd[BOOT_I2C_REQ_CMD_LEN] = {0, };
	struct sysboot_erase_param_type erase;
	uint8_t xmit_bytes = 0;
	int ret = 0;
	int retry = 0;
	uint8_t *xmit = NULL;

	/* build command */
	cmd[0] = BOOT_I2C_CMD_ERASE;
	cmd[1] = ~cmd[0];

	/* build erase parameter */
	ret = sysboot_conv_memory_map(address, len, &erase);
	if (ret < 0)
		return ret + BOOT_ERR_API_ERASE;

	LOG_INF("erase.page 0x%x", erase.page);

	xmit = kmalloc(1024, GFP_KERNEL | GFP_DMA);
	if (xmit == NULL) {
		LOG_ERR("out of memory");
		return ret + BOOT_ERR_API_ERASE;
	}

	memset(xmit, 0, 1024);

	for (retry = 0; retry < BOOT_I2C_SYNC_RETRY_COUNT; ++retry) {
		/* build full erase command */
		if (erase.page == 0xFFFF)
			*(uint16_t *)xmit = (uint16_t)erase.page;
		else	/* build page erase command */
			*(uint16_t *)xmit = HTONS((erase.count - 1));

		xmit_bytes = sizeof(uint16_t);
		xmit[xmit_bytes] = sysboot_checksum(xmit, xmit_bytes);
		xmit_bytes++;
		/* transmit command */
		ret = cam_ois_i2c_master_send(client, cmd, sizeof(cmd));
		if (ret < 0) {
			msleep(BOOT_I2C_SYNC_RETRY_INTVL);
			continue;
		}

		/* wait for ACK response */
		ret = sysboot_i2c_wait_ack(client, BOOT_I2C_WAIT_RESP_TMOUT);
		if (ret < 0) {
			msleep(BOOT_I2C_SYNC_RETRY_INTVL);
			continue;
		}
		/* transmit parameter */
		ret = cam_ois_i2c_master_send(client, xmit, xmit_bytes);
		if (ret < 0) {
			msleep(BOOT_I2C_SYNC_RETRY_INTVL);
			continue;
		}
		/* wait for ACK response */
		//msleep(2*32);
		ret = sysboot_i2c_wait_ack(client,
				(erase.page == 0xFFFF) ? BOOT_I2C_FULL_ERASE_TMOUT : BOOT_I2C_WAIT_RESP_TMOUT);
		if (ret < 0) {
			msleep(BOOT_I2C_SYNC_RETRY_INTVL);
			continue;
		}

		/* case of page erase */
		if (erase.page != 0xFFFF) {
			/* build page erase parameter */
			register int ix;
			register uint16_t *pbuf = (uint16_t *)xmit;

			for (ix = 0; ix < erase.count; ++ix)
				pbuf[ix] = HTONS((erase.page + ix));

			LOG_INF("erase.count %d", erase.count);
			LOG_INF("&pbuf[ix] %pK,xmit %pK", &pbuf[ix], xmit);
			xmit_bytes = 2 * erase.count;
			*((uint8_t *)&pbuf[ix]) = sysboot_checksum(xmit, xmit_bytes);
			LOG_INF("xmit_bytes %d", xmit_bytes);
			xmit_bytes++;
			/* transmit parameter */
			ret = cam_ois_i2c_master_send(client, xmit, xmit_bytes);
			if (ret < 0) {
				msleep(BOOT_I2C_SYNC_RETRY_INTVL);
				continue;
			}
			//msleep(2*32);
			/* wait for ACK response */
			ret = sysboot_i2c_wait_ack(client, BOOT_I2C_PAGE_ERASE_TMOUT(erase.count + 1));
			if (ret < 0) {
				msleep(BOOT_I2C_SYNC_RETRY_INTVL);
				continue;
			}
		}
		LOG_INF("erase finish");
		kfree(xmit);
		return 0;
	}

	kfree(xmit);
	return ret + BOOT_ERR_API_ERASE;
}

int target_empty_check_status(struct i2c_client *client)
{
	uint32_t value = 0;
	int ret = 0;

	LOG_INF("E");

	/* Read first flash memory word ------------------------------------------- */
	ret = sysboot_i2c_read(client, memory_map.flashbase, (uint8_t *)&value, sizeof(value));
	if (ret < 0) {
		LOG_ERR("Failed to read word for empty check (%d)", ret);
		goto empty_check_status_fail;
	}

	LOG_INF("Flash Word: 0x%08X", value);

	if (value == 0xFFFFFFFF)
		return 1;

	return 0;

empty_check_status_fail:
	return -1;
}

int target_read_hwver(struct i2c_client *client)
{
	int ret = 0;
	int i = 0;

	uint32_t addr[4] = {0, };
	uint8_t dst = 0;
	uint32_t address = 0;

	for (i = 0; i < 4; i++) {
		addr[i] = OIS_FW_VER_BIN_ADDR_START + i + memory_map.flashbase;
		address = addr[i];
		ret = sysboot_i2c_read(client, address, &dst, 1);

		if (ret < 0)
			LOG_ERR("read fwver addr 0x%x fail", address);
		else
			LOG_ERR("read fwver addr 0x%x dst 0x%x", address, dst);
	}
	return ret;
}

int target_read_vdrinfo(struct i2c_client *client)
{
	int ret = 0;
	int i = 0;
	uint32_t addr[4] = {0, };
	unsigned char dst[5] = "";
	uint32_t address = 0;
	uint8_t *data = NULL;

	for (i = 0; i < 4 ; i++) {
		addr[i] = 0x807C + i + memory_map.flashbase;
		address = addr[i];
		ret = sysboot_i2c_read(client, address, dst, 4);

		if (ret < 0)
			LOG_ERR("read fwver addr 0x%x fail", address);
		else
			LOG_ERR("read fwver addr 0x%x dst [0] 0x%x,[1] 0x%x,[2] 0x%x,[3] 0x%x,",
				address, dst[0], dst[1], dst[2], dst[3]);
	}
	address = memory_map.flashbase + 0x8000;

	data = kmalloc(256, GFP_KERNEL | GFP_DMA);
	if (data != NULL) {
		memset(data, 0, 256);

		ret = sysboot_i2c_read(client, address, data, 256);
		//strncpy(dst,data+0x7c,4);
		strncpy(dst, data + 124, 4);
		LOG_INF("read fwver addr 0x%x dst [0] 0x%x,[1] 0x%x,[2] 0x%x,[3] 0x%x,",
			address + 0x7C, dst[0], dst[1], dst[2], dst[3]);

		kfree(data);
	} else {
		LOG_ERR("out of memory");
	}
	return ret;
}

int target_empty_check_clear(struct mcu_info *mcu_info, struct i2c_client *client)
{
	int ret = 0;
	uint32_t optionbyte = 0;

	/* Option Byte read ------------------------------------------------------- */
	ret = sysboot_i2c_read(client, memory_map.optionbyte, (uint8_t *)&optionbyte, sizeof(optionbyte));
	if (ret < 0) {
		LOG_ERR("Option Byte read fail");
		goto empty_check_clear_fail;
	}

	LOG_INF("Option Byte read 0x%x", optionbyte);

	/* Option byte write (dummy: readed value) -------------------------------- */
	ret = sysboot_i2c_write(client, memory_map.optionbyte, (uint8_t *)&optionbyte, sizeof(optionbyte));
	if (ret < 0) {
		LOG_ERR("Option Byte write fail");
		goto empty_check_clear_fail;
	}
	LOG_INF("Option Byte write 0x%x", optionbyte);

	/* Put little delay for Target program option byte and self-reset */
	msleep(150);
	/* Option byte read for checking protection status ------------------------ */
	/* 1> Re-connect to the target */
	ret = sysboot_connect(mcu_info, client);
	if (ret) {
		LOG_ERR("Cannot connect to the target for RDP check (%d)", ret);
		goto empty_check_clear_fail;
	}

	/* 2> Read from target for status checking and recover it if needed */
	ret = sysboot_i2c_read(client, memory_map.optionbyte, (uint8_t *)&optionbyte, sizeof(optionbyte));
	if ((ret < 0) || ((optionbyte & 0x000000FF) != 0xAA)) {
		LOG_ERR("Failed to read option byte from target (%d)", ret);
		/* Tryout the RDP level to 0 */
		ret = sysboot_i2c_read_unprotect(client);
		if (ret)
			LOG_INF("Readout unprotect Not OK ... Host restart and try again");
		else
			LOG_INF("Readout unprotect OK ... Host restart and try again");

		/* Put little delay for Target erase all of pages */
		msleep(50);
		goto empty_check_clear_fail;
	}

	return 0;
empty_check_clear_fail:
	return -1;
}

uint16_t cam_ois_mcu_calcchecksum(unsigned char *data, int size)
{
	int i = 0;
	uint16_t result = 0;

	for (i = 0; i < size; i += 2)
		result = result + (0xFFFF & (((*(data + i + 1)) << 8) | (*(data + i))));

	return result;
}

static int cam_ois_mcu_read_file(struct mcu_info *mcu_info, const char *name, unsigned char **data, unsigned int *size)
{
	int ret = 0;
	const struct firmware *fw = NULL;
	struct device *dev = mcu_info->pdev;

	ret = request_firmware(&fw, name, dev);
	if (ret) {
		LOG_ERR("Failed to get firmware. name: %s, ret: %d", name, ret);
		return ret;
	}

	*data = NULL;
	*size = fw->size;

	if (*size)
		*data = vmalloc(*size);
	if (!(*data)) {
		LOG_ERR("vmalloc failed");
		ret = -EINVAL;
		goto kread_err;
	}

	memcpy(*data, fw->data, *size);
	LOG_INF("fw file %s, %d Bytes", name, *size);

kread_err:
	release_firmware(fw);
	return ret;
}

int32_t cam_ois_mcu_fw_update_wbootloader(struct mcu_info *mcu_info, struct i2c_client *client)
{
	int ret = 0;
	uint8_t sendData[OIS_FW_UPDATE_PACKET_SIZE] = "";
	uint16_t checkSum = 0;

	unsigned char *buffer = NULL;
	int i = 0;
	int empty_check_en = 0;
	int fw_size = 0;
	uint32_t address = 0;
	uint32_t wbytes = 0;
	int len = 0;
	uint32_t unit = OIS_FW_UPDATE_PACKET_SIZE;

	LOG_INF("E\n");
	cam_ois_mcu_read_file(mcu_info, OIS_MCU_FW_NAME, &buffer, &fw_size);

	msleep(55);

	/* verify checkSum */
	checkSum = cam_ois_mcu_calcchecksum(buffer, fw_size);
	LOG_INF("ois cal checksum = %u", checkSum);

	//enter system bootloader mode
	LOG_INF("need update MCU FW, enter system bootloader mode");
	// o_ctrl->io_master_info.client->addr = sysboot_i2c_slave_address >> 1;

	msleep(50);

	ret = mcu_validation(mcu_info, client);
	if (ret < 0) {
		LOG_ERR("mcu connect failed");
		goto ERROR;
	}

	//check_option_byte
	target_option_update(mcu_info, client);
	//check empty status
	empty_check_en = target_empty_check_status(client);
	//erase
	sysboot_i2c_erase(client, memory_map.flashbase, 65536 - 2048);

	address = memory_map.flashbase;
	len = fw_size;
	/* Write UserProgram Data */
	while (len > 0) {
		wbytes = (len > unit) ? unit : len;
		/* write the unit */
		LOG_ERR("write wbytes=%d  left len=%d", wbytes, len);
		for (i = 0; i < wbytes; i++)
			sendData[i] = buffer[i];

		ret = sysboot_i2c_write(client, address, sendData, wbytes);
		if (ret < 0) {
			LOG_ERR("i2c byte prog code write failed");
			break; /* fail to write */
		}
		address += wbytes;
		buffer += wbytes;
		len -= wbytes;
	}
	buffer = buffer - (address - memory_map.flashbase);
	//target_read_hwver
	target_read_hwver(client);
	//target_read_vdrinfo
	target_read_vdrinfo(client);
	if (empty_check_en > 0) {
		if (target_empty_check_clear(mcu_info, client) < 0) {
			ret = -1;
			goto ERROR;
		}
	}
	//sysboot_disconnect
	sysboot_disconnect(mcu_info);

	LOG_INF("ois fw update done");

ERROR:
	if (buffer) {
		vfree(buffer);
		buffer = NULL;
	}
	return ret;
}

int cam_ois_mcu_wait_idle(struct i2c_client *client, int retries)
{
	u8 status = 0;
	int ret = 0;

	/* check ois status if it`s idle or not */
	/* OISSTS register(0x0001) 1Byte read */
	/* 0x01 == IDLE State */
	do {
		ret = cam_ois_i2c_read_multi(client, MCU_I2C_SLAVE_W_ADDR, 0x0001, &status, 1);
		if (status == 0x01)
			break;
		if (--retries < 0) {
			if (ret < 0) {
				LOG_ERR("failed due to i2c fail");
				return -EIO;
			}
			LOG_ERR("ois status is not idle, current status %d", status);
			return -EBUSY;
		}
		usleep_range(10000, 11000);
	} while (status != 0x01);
	return 0;
}


int cam_ois_mcu_get_fw_status(struct i2c_client *client)
{
	int rc = 0;
	uint32_t i = 0;
	uint8_t status_arr[OIS_FW_STATUS_SIZE];
	uint32_t status = 0;

	rc = cam_ois_i2c_read_multi(client, MCU_I2C_SLAVE_W_ADDR, OIS_FW_STATUS_OFFSET,
		status_arr, OIS_FW_STATUS_SIZE);
	if (rc < 0) {
		LOG_ERR("i2c read fail");
		LOG_ERR("MCU NACK need update FW again");
		return -2;
	}

	for (i = 0; i < OIS_FW_STATUS_SIZE; i++)
		status |= status_arr[i] << (i * 8);

	// In case previous update failed, (like removing the battery during update)
	// Module itself set the 0x00FC ~ 0x00FF register as error status
	// So if previous fw update failed, 0x00FC ~ 0x00FF register value is '4451'
	if (status == 4451) { //previous fw update failed, 0x00FC ~ 0x00FF register value is 4451
		return -1;
	}

	return 0;
}

int32_t cam_ois_mcu_read_module_ver(struct mcu_info *mcu_info, struct i2c_client *client)
{
	int rc = 0, i = 0;
	uint8_t data[OIS_VER_SIZE + 1] = "";

	rc = cam_ois_i2c_read_multi(client, MCU_I2C_SLAVE_W_ADDR, 0x00F8,
		data, OIS_MCU_VERSION_SIZE);
	if (rc < 0)
		return -2;

	rc = cam_ois_i2c_read_multi(client, MCU_I2C_SLAVE_W_ADDR, 0x007C,
		data + OIS_MCU_VERSION_SIZE, OIS_MCU_VDRINFO_SIZE);
	if (rc < 0)
		return -2;
	//HW Ver
	mcu_info->module_ver[0] = data[3]; // Projects
	mcu_info->module_ver[1] = data[2]; // Projects
	mcu_info->module_ver[2] = data[1]; // MCU info
	mcu_info->module_ver[3] = data[0]; // Gyro
	//VDR INFO
	mcu_info->module_ver[4] = data[4]; // FW release year
	mcu_info->module_ver[5] = data[5]; // FW release month
	mcu_info->module_ver[6] = data[6]; // FW revision
	mcu_info->module_ver[7] = data[7]; // Dev or Rel

	for (i = 0; i < OIS_VER_SIZE; i++) {
		if (!isalnum(mcu_info->module_ver[i])) {
			LOG_ERR("module_ver[%d] is not alnum type (%c)", i, mcu_info->module_ver[i]);
			return -1;
		}
	}

	LOG_INF("%c%c%c%c%c%c%c%c",
		mcu_info->module_ver[0], mcu_info->module_ver[1],
		mcu_info->module_ver[2], mcu_info->module_ver[3],
		mcu_info->module_ver[4], mcu_info->module_ver[5],
		mcu_info->module_ver[6], mcu_info->module_ver[7]);

	return 0;
}

int32_t cam_ois_mcu_read_phone_ver(struct mcu_info *mcu_info)
{
	char char_ois_ver[OIS_VER_SIZE + 1] = "";
	int ret = 0, i = 0;
	unsigned int size, fw_size, pos;
	const struct firmware *fw = NULL;
	struct device *dev = mcu_info->pdev;
	unsigned char *fw_buffer = NULL;

	LOG_INF("OIS FW : %s", OIS_MCU_FW_NAME);
	ret = request_firmware(&fw, OIS_MCU_FW_NAME, dev);
	if (ret) {
		LOG_ERR("Failed to get FW %s, ret: %d", OIS_MCU_FW_NAME, ret);
		return ret;
	}
	fw_size = fw->size;

	fw_buffer = vmalloc(fw_size);
	if (!fw_buffer) {
		LOG_ERR("Fail to allocate fw buffer. size: %u", fw_size);
		ret = -ENOMEM;
		goto PHONE_VER_ERROR;
	}

	memcpy(fw_buffer, fw->data, fw_size);

	pos = OIS_MCU_VERSION_OFFSET;
	size = OIS_MCU_VERSION_SIZE;
	if ((pos + size) < fw_size)
		memcpy(char_ois_ver, fw_buffer + pos, sizeof(char) * size);
	else
		LOG_ERR("version cp error. fw size: %d, target position: %d\n", fw_size, pos + size);

	pos = OIS_MCU_VDRINFO_OFFSET;
	size = OIS_VER_SIZE - OIS_MCU_VERSION_SIZE;
	if ((pos + size) < fw_size)
		memcpy(char_ois_ver + OIS_MCU_VERSION_SIZE, fw_buffer + pos, sizeof(char) * size);
	else
		LOG_ERR("vdrinfo cp error. fw size: %d, target position: %d\n", fw_size, pos + size);

	mcu_info->phone_ver[0] = char_ois_ver[3]; // core version
	mcu_info->phone_ver[1] = char_ois_ver[2];
	mcu_info->phone_ver[2] = char_ois_ver[1]; // MCU infor
	mcu_info->phone_ver[3] = char_ois_ver[0]; // Gyro
	mcu_info->phone_ver[4] = char_ois_ver[4]; // FW release year
	mcu_info->phone_ver[5] = char_ois_ver[5]; // FW release month
	mcu_info->phone_ver[6] = char_ois_ver[6]; // FW release count
	mcu_info->phone_ver[7] = char_ois_ver[7]; // Dev or Rel

	for (i = 0; i < OIS_VER_SIZE; i++) {
		if (!isalnum(mcu_info->phone_ver[i])) {
			LOG_ERR("version char (%c) is not alnum type.", mcu_info->phone_ver[i]);
			ret = -1;
			goto PHONE_VER_ERROR;
		}
	}

	LOG_INF("%c%c%c%c%c%c%c%c",
		mcu_info->phone_ver[0], mcu_info->phone_ver[1],
		mcu_info->phone_ver[2], mcu_info->phone_ver[3],
		mcu_info->phone_ver[4], mcu_info->phone_ver[5],
		mcu_info->phone_ver[6], mcu_info->phone_ver[7]);

PHONE_VER_ERROR:
	if (fw_buffer) {
		vfree(fw_buffer);
		fw_buffer = NULL;
	}
	release_firmware(fw);

	return ret;
}

#if ENABLE_AOIS == 1
int cam_ois_mcu_fw_update(struct mcu_info *mcu_info, struct i2c_client *client)
{
	int ret = 0;
	int i = 0;

	LOG_INF("- E");

	mcu_info->is_updated = 0;
	mcu_info->no_module_ver = false;

	ret = cam_ois_set_fac_mode(FACTORY_MODE_ON);
	if (ret < 0)
		LOG_INF("FACTORY_MODE_ON fail ret:%d", ret);

	msleep(30);

	ret = cam_ois_mcu_read_module_ver(mcu_info, client);
	if (ret < 0) {
		LOG_ERR("read module version fail %d", ret);
		mcu_info->no_module_ver = true;
	}
	for (i = 0; i < OIS_VER_SIZE; i++)
		mcu_info->phone_ver[i] = mcu_info->module_ver[i];

	ret = cam_ois_set_fac_mode(FACTORY_MODE_OFF);
	if (ret < 0)
		LOG_INF("FACTORY_MODE_ON fail ret:%d", ret);

	if (mcu_info->no_module_ver == false)
		mcu_info->is_updated = 1;

	LOG_INF("- X");
	return ret;
}
#else
//from cam_ois_check_fw
int cam_ois_mcu_fw_update(struct mcu_info *mcu_info, struct i2c_client *client)
{
	int rc = 0, i = 0;
	bool is_force_update = false;
	bool is_need_retry = false;
	bool is_cal_wrong = false;
	bool is_mcu_nack = false;
	int update_retries = 3;
	bool is_fw_crack = false;
	char ois_dev_core[] = {'A', 'B', 'E', 'F', 'I', 'J', 'M', 'N'};
	char fw_ver_ng[OIS_VER_SIZE + 1] = "NG_FW2";
	char cal_ver_ng[OIS_VER_SIZE + 1] = "NG_CD2";
	int force_fw_update = 0;

	LOG_INF("E");
	mcu_info->no_module_ver = false;

FW_UPDATE_RETRY:
	is_mcu_nack = false;
	is_force_update = false;
	mcu_info->is_updated = 0;

	rc = cam_ois_mcu_power_up(mcu_info);
	if (rc < 0) {
		LOG_ERR("OIS Power up failed");
		goto end;
	}

	usleep_range(15000, 15100);

	rc = cam_ois_mcu_wait_idle(client, 5);
	if (rc < 0) {
		LOG_ERR("waiting ois idle status failed");
		LOG_WARN("MCU NACK, need to update FW");
		is_force_update = true;
		is_mcu_nack = true;
	}

	rc = cam_ois_mcu_get_fw_status(client);
	if (rc) {
		LOG_ERR("Previous update had not been properly, start force update");
		is_force_update = true;
		if (rc == -2) {
			LOG_ERR("MCU NACK, may need update FW");
			is_mcu_nack = true;
		}
	} else {
		is_need_retry = false;
	}
	// when retry it will skip, not to overwirte the mod ver which might be cracked
	//becase of previous update fail
	if (!is_need_retry && !is_force_update) {
		rc = cam_ois_mcu_read_module_ver(mcu_info, client);
		if (rc < 0) {
			LOG_ERR("read module version fail %d. skip fw update", rc);
			mcu_info->no_module_ver = true;
			if (rc == -2)
				is_mcu_nack = true;
			else if (rc == -1 && strncmp(mcu_info->module_ver, "TSD1", OIS_MCU_VERSION_SIZE) == '\0')
				LOG_INF("skip pwr_dwn for module %s", mcu_info->module_ver);
			else
				goto pwr_dwn;
		}
	}

	rc = cam_ois_mcu_read_phone_ver(mcu_info);
	if (rc < 0) {
		mcu_info->no_module_ver = true;
		LOG_ERR("No available OIS FW exists in system");
	}

	if (strncmp(mcu_info->module_ver, "TSD1", OIS_MCU_VERSION_SIZE) == '\0' &&
		strncmp(mcu_info->phone_ver, "CSD1", OIS_MCU_VERSION_SIZE) == '\0') {
		is_mcu_nack = true;
		LOG_INF("Force update OIS FW");
	}

	LOG_INF("[OIS version] phone : %s, cal %s, module %s",
		mcu_info->phone_ver, mcu_info->cal_ver, mcu_info->module_ver);

	for (i = 0; i < (int)(sizeof(ois_dev_core)/sizeof(char)); i++) {
		if (mcu_info->module_ver[0] == ois_dev_core[i]) {
			if (is_mcu_nack != true) {
				LOG_ERR("devleopment module(core version : %c), skip update FW",
					mcu_info->module_ver[0]);
				//goto pwr_dwn;
			}
		}
	}

	if (force_fw_update > 0) {
		is_mcu_nack = true;
		LOG_INF("Force update OIS FW");
	}

	if (update_retries < 0)
		is_mcu_nack = false;

	//check if it is same hw (phone ver = module ver)
	if (strncmp(mcu_info->phone_ver, mcu_info->module_ver, OIS_MCU_VERSION_SIZE) == '\0' ||
		is_mcu_nack == true) {
		if ((strncmp(mcu_info->phone_ver, mcu_info->module_ver, OIS_VER_SIZE) > '\0')
			|| is_force_update || is_mcu_nack == true) {
			LOG_INF("update OIS FW from phone");
			LOG_INF("is_force_update %d , is_mcu_nack %d ", is_force_update, is_mcu_nack);
			rc = cam_ois_mcu_fw_update_wbootloader(mcu_info, client);
			if (rc < 0) {
				is_need_retry = true;
				LOG_ERR("update fw fail, it will retry (%d)", 4 - update_retries);
				if (--update_retries < 0) {
					LOG_ERR("update fw fail, stop retry");
					is_need_retry = false;
				}
			} else {
				LOG_INF("update succeeded from phone");
				is_need_retry = false;
				mcu_info->is_updated = 1;
			}
		}
	}

	if (!is_need_retry) {
		rc = cam_ois_mcu_read_module_ver(mcu_info, client);
		if (rc < 0) {
			mcu_info->no_module_ver = true;
			LOG_ERR("read module version fail %d.", rc);
		}
	}

pwr_dwn:
	rc = cam_ois_mcu_get_fw_status(client);
	if (rc < 0)
		is_fw_crack = true;

	if (!is_need_retry) { //when retry not to change mod ver
		if (is_fw_crack)
			memcpy(mcu_info->module_ver, fw_ver_ng, (OIS_VER_SIZE) * sizeof(uint8_t));
		else if (is_cal_wrong)
			memcpy(mcu_info->module_ver, cal_ver_ng, (OIS_VER_SIZE) * sizeof(uint8_t));
	}

	cam_ois_mcu_print_fw_version(mcu_info, "Init Module");
	cam_ois_mcu_power_down(mcu_info);

	if (is_need_retry) {
		LOG_INF("Re-try for FW update");
		goto FW_UPDATE_RETRY;
	}
end:
	LOG_INF("X");
	return rc;
}
#endif
