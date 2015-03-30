LOCAL_PATH := $(my-dir)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := \
	main.cpp \
	backend.cpp

LOCAL_C_INCLUDES += \
	$(ARMHOOK_ROOT_PATH)/core/helper \
	bionic \
	bionic/libstdc++/include \
	external/stlport/stlport

LOCAL_SHARED_LIBRARIES := libstlport
LOCAL_MODULE_TAGS := optional

LOCAL_MODULE := libpickle
include $(BUILD_SHARED_LIBRARY)
