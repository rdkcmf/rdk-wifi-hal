/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2018 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <linux/types.h>
#include <asm/byteorder.h>
#include <stdint.h>
#include <inttypes.h>
#include <errno.h>
#include <unistd.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <linux/filter.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <pthread.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <aes_siv.h>
#include <wifi_hal_rdk_framework.h>

wifi_device_callbacks_t    g_device_callbacks;

wifi_device_callbacks_t *get_device_callbacks()
{
    return &g_device_callbacks;
}

char *to_mac_str (mac_address_t mac, mac_addr_str_t key) {
    snprintf(key, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    return (char *)key;
}

void to_mac_bytes (mac_addr_str_t key, mac_address_t bmac) {
   unsigned int mac[6];
    sscanf(key, "%02x:%02x:%02x:%02x:%02x:%02x",
             &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
   bmac[0] = mac[0]; bmac[1] = mac[1]; bmac[2] = mac[2];
   bmac[3] = mac[3]; bmac[4] = mac[4]; bmac[5] = mac[5];

}

const char *wifi_freq_bands_to_string(wifi_freq_bands_t band)
{
#define BANDS2S(x) case x: return #x;
    switch (band) {
    BANDS2S(WIFI_FREQUENCY_2_4_BAND)
    BANDS2S(WIFI_FREQUENCY_5_BAND)
    BANDS2S(WIFI_FREQUENCY_5L_BAND)
    BANDS2S(WIFI_FREQUENCY_5H_BAND)
    BANDS2S(WIFI_FREQUENCY_6_BAND)
    BANDS2S(WIFI_FREQUENCY_60_BAND)
    }

    return "WIFI_FREQUENCY_UNKNOWN";
}

char *get_formatted_time(char *time)
{
    struct tm *tm_info;
    struct timeval tv_now;
    char tmp[128];

    gettimeofday(&tv_now, NULL);
    tm_info = localtime(&tv_now.tv_sec);

    strftime(tmp, 128, "%y%m%d-%T", tm_info);

    snprintf(time, 128, "%s.%06lu", tmp, tv_now.tv_usec);
    return time;
}


static int move_radio_capability(wifi_radio_capabilities_t *tmp_cap, wifi_radio_capabilities_t *cap,
    unsigned int arr_loc)
{
    unsigned j = 0;

    tmp_cap->index = cap->index;
    tmp_cap->numSupportedFreqBand = 1;
    tmp_cap->band[0] = cap->band[arr_loc];
    memcpy(&tmp_cap->channel_list[0], &cap->channel_list[arr_loc], sizeof(wifi_channels_list_t));
    memcpy(&tmp_cap->channelWidth[0], &cap->channelWidth[arr_loc], sizeof(wifi_ieee80211Variant_t));
    memcpy(&tmp_cap->mode[0], &cap->mode[arr_loc], sizeof(wifi_ieee80211Variant_t));
    tmp_cap->maxBitRate[0] = cap->maxBitRate[arr_loc];
    tmp_cap->supportedBitRate[0] = cap->supportedBitRate[arr_loc];
    memcpy(&tmp_cap->transmitPowerSupported_list[0], &cap->transmitPowerSupported_list[arr_loc], sizeof(wifi_radio_trasmitPowerSupported_list_t));
    tmp_cap->autoChannelSupported = cap->autoChannelSupported;
    tmp_cap->DCSSupported = cap->DCSSupported;
    tmp_cap->zeroDFSSupported=cap->zeroDFSSupported;
    memcpy(&tmp_cap->csi, &cap->csi, sizeof(wifi_radio_csi_capabilities_t));
    tmp_cap->cipherSupported = cap->cipherSupported;
    tmp_cap->numcountrySupported = cap->numcountrySupported;
    tmp_cap->maxNumberVAPs = cap->maxNumberVAPs;
    for (j=0 ; j<tmp_cap->numcountrySupported ; j++) {
        tmp_cap->countrySupported[j] = cap->countrySupported[j];
    }
    memcpy(cap, tmp_cap, sizeof(wifi_radio_capabilities_t));
    return RETURN_OK;
}

// The radio can support several bands. The actual band used by driver is retrieved from VAP name
// and set as the first band so the higher layers can access it at 0 index.
int adjust_radio_capability_band(wifi_radio_capabilities_t *cap, unsigned int radio_band)
{
    wifi_radio_capabilities_t tmp_cap;
    unsigned int i = 0;

    memset(&tmp_cap, 0, sizeof(wifi_radio_capabilities_t));
    for (i = 0; i <= cap->numSupportedFreqBand; i++) {
        // The driver reports 5G low and high bands as 5G band. We fix the band based on VAP name.
        if (cap->band[i] == WIFI_FREQUENCY_5_BAND && (radio_band == WIFI_FREQUENCY_5H_BAND ||
            radio_band == WIFI_FREQUENCY_5L_BAND)) {
            cap->band[i] = radio_band;
        }

        // Find band that is actually used and move its capabilities to 0 index.
        if (cap->band[i] == radio_band) {
            move_radio_capability(&tmp_cap, cap, i);
            break;
        }
    }
    return RETURN_OK;
}

