LOCAL_PATH := $(call my-dir)
MAIN_PATH := $(LOCAL_PATH)

ifeq ($(strip $(MTK_FM_SUPPORT)), yes)
    ifeq ($(FM_LAYERDEC_2),)
        include $(MAIN_PATH)/Include.mk
    else
#        # soc
#        BUILD_CONNAC2 := false
#        FM_CHIP := mt6580
#        FM_PLAT := soc
#        include $(MAIN_PATH)/Include.mk
#
#        # mt6625
#        BUILD_CONNAC2 := false
#        FM_CHIP := mt6625
#        FM_PLAT := mt6625
#        include $(MAIN_PATH)/Include.mk
#
#        # mt6627
#        BUILD_CONNAC2 := false
#        FM_CHIP := mt6627
#        FM_PLAT := mt6627
#        include $(MAIN_PATH)/Include.mk
#
#        # mt6630
#        BUILD_CONNAC2 := false
#        FM_CHIP := mt6630
#        FM_PLAT := mt6630
#        include $(MAIN_PATH)/Include.mk
#
#        # mt6632
#        BUILD_CONNAC2 := false
#        FM_CHIP := mt6632
#        FM_PLAT := mt6632
#        include $(MAIN_PATH)/Include.mk
#
#        # mt6631 connac 1.x
#        BUILD_CONNAC2 := false
#        FM_CHIP := mt6631
#        FM_PLAT := mt6631
#        include $(MAIN_PATH)/Include.mk
#
#        # mt6635 connac 1.x
#        BUILD_CONNAC2 := false
#        FM_CHIP := mt6635
#        FM_PLAT := mt6635
#        include $(MAIN_PATH)/Include.mk
#
#        # dynamic mt6631/mt6635 connac 1.x
#        BUILD_CONNAC2 := false
#        FM_CHIP :=
#        FM_PLAT := mt6631_6635
#        include $(MAIN_PATH)/Include.mk

        # mt6635 connac 2.x
        BUILD_CONNAC2 := true
        FM_CHIP := mt6635
        FM_PLAT := connac2x
        include $(MAIN_PATH)/Include.mk
    endif
endif
