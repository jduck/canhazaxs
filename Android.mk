LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := canhazaxs.c
LOCAL_MODULE := charm-static
include $(BUILD_STATIC_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := canhazaxs.c
LOCAL_MODULE := charm
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := canhazaxs.c
LOCAL_MODULE := charm-pie
LOCAL_CFLAGS += -Wall -pie -fPIE
LOCAL_LDFLAGS += -pie -fPIE
include $(BUILD_EXECUTABLE)

include $(call all-makefiles-under,$(LOCAL_PATH))
