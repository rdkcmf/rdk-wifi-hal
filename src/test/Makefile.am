AM_CFLAGS = -D_ANSC_LINUX
AM_CFLAGS += -D_ANSC_USER

AM_CPPFLAGS = -Wall -g -Werror
AM_CXXFLAGS = -std=c++11

ACLOCAL_AMFLAGS = -I m4
bin_PROGRAMS = rdk_wifi_hal_gtest.bin
rdk_wifi_hal_gtest_bin_CPPFLAGS = -I$(PKG_CONFIG_SYSROOT_DIR)$(includedir)/gtest -I${top_srcdir}/gtest/include -I${top_srcdir}/source -I${top_srcdir}/source/include
rdk_wifi_hal_gtest_bin_SOURCES =  RdkWifiHalTest.cpp gtest_main.cpp
rdk_wifi_hal_gtest_bin_LDFLAGS = -lgtest -lgmock -lgcov -lpthread
