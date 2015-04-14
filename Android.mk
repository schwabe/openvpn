LOCAL_PATH:= $(call my-dir)/

include $(CLEAR_VARS)

LOCAL_LDLIBS := -lz -latomic
LOCAL_C_INCLUDES := openssl/include lzo/include openssl/crypto openssl openvpn/src/compat openvpn/src/openvpn openvpn/include breakpad/src google-breakpad/src/common/android/include mbedtls/include openvpn/android-config/




LOCAL_CFLAGS= -DHAVE_CONFIG_H -DTARGET_ABI=\"${TARGET_ABI}\"
LOCAL_STATIC_LIBRARIES :=  liblzo-static

ifeq ($(WITH_MBEDTLS),1)
LOCAL_STATIC_LIBRARIES +=  mbedtls-static
LOCAL_CFLAGS += -DENABLE_CRYPTO_MBEDTLS=1
else
#LOCAL_SHARED_LIBRARIES :=  libssl libcrypto
LOCAL_STATIC_LIBRARIES +=  libssl_static libcrypto_static
LOCAL_CFLAGS += -DENABLE_CRYPTO_OPENSSL=1
endif

ifeq ($(WITH_BREAKPAD),1)
LOCAL_STATIC_LIBRARIES += breakpad_client
LOCAL_CFLAGS += -DGOOGLE_BREAKPAD=1
endif

LOCAL_MODULE = openvpn



LOCAL_SRC_FILES:= \


ifeq ($(WITH_BREAKPAD),1)
LOCAL_SRC_FILES+=src/openvpn/breakpad.cpp
endif


include $(BUILD_SHARED_LIBRARY)
#include $(BUILD_EXECUTABLE)
