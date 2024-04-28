#ifndef CAM_OIS_DEFINE_H
#define CAM_OIS_DEFINE_H

#define ENABLE_AOIS                      1
#define OIS_AF_MAIN_NAME                 AFDRV_DW9825AF_OIS_MCU

#define MCU_I2C_SLAVE_W_ADDR             0xC4
#define OIS_GYRO_SCALE_FACTOR            114 // LSM6DSO

#define OIS_GYRO_WX_POLE                 0x01
#define OIS_GYRO_WY_POLE                 0x01
#define OIS_GYRO_ORIENTATION             0x01

#endif

