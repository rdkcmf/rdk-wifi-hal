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
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <stdarg.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/rtnetlink.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include "wifi_hal.h"
#include "wifi_hal_priv.h"
#include <assert.h>
#include "hostapd/eap_register.h"

#define MAC_ADDRESS_LEN 6

static int g_fd_arr[MAX_VAP] = {0};
static int g_IfIdx_arr[MAX_VAP] = {0};
static unsigned char g_vapSmac[MAX_VAP][MAC_ADDRESS_LEN] = {'\0'};

INT wifi_hal_getHalCapability(wifi_hal_capability_t *hal)
{
    unsigned int i;
    wifi_interface_info_t *interface;
    wifi_radio_info_t *radio;
    wifi_radio_capabilities_t *cap;
    wifi_vap_info_t *vap;
    bool is_band_found = false;
    unsigned int radio_band = 0;

    hal->version.major = WIFI_HAL_MAJOR;
    hal->version.minor = WIFI_HAL_MINOR;

    hal->wifi_prop.numRadios = g_wifi_hal.num_radios;

    for (i = 0; i < hal->wifi_prop.numRadios; i++) {
        radio_band = 0;
        is_band_found = false;
        radio = get_radio_by_rdk_index(i);
        wifi_hal_info_print("%s:%d:Enumerating interfaces on PHY radio index: %d, RDK radio index:%d\n", __func__, __LINE__, radio->index, i);

        interface = hash_map_get_first(radio->interface_map);
        while (interface != NULL) {
            vap = &interface->vap_info;
            if (is_band_found == false) {
                if (strstr(vap->vap_name, "2g") != NULL) {
                    is_band_found = true;
                    radio_band = WIFI_FREQUENCY_2_4_BAND;
                } else if (strstr(vap->vap_name, "5g") != NULL) {
                    is_band_found = true;
                    radio_band = WIFI_FREQUENCY_5_BAND;
                } else if (strstr(vap->vap_name, "6g") != NULL) {
                    is_band_found = true;
                    radio_band = WIFI_FREQUENCY_6_BAND;
                }
            }
            wifi_hal_info_print("%s:%d: interface name: %s, vap index: %d, vap name: %s\n", __func__, __LINE__,
                    interface->name, vap->vap_index, vap->vap_name);
            interface = hash_map_get_next(radio->interface_map, interface);
        }

        cap = &hal->wifi_prop.radiocap[i];
        memcpy((unsigned char *)cap, (unsigned char *)&radio->capab, sizeof(wifi_radio_capabilities_t));
        update_radio_capabilty_band_arr_loc(cap, radio_band);
    }

    get_wifi_interface_info_map(hal->wifi_prop.interface_map);

    return RETURN_OK;
}

INT wifi_hal_setApWpsButtonPush(INT ap_index)
{
    wifi_hal_info_print("%s:%d: WPS Push Button for radio index %d\n", __func__, __LINE__, ap_index);

    wifi_hal_nl80211_wps_pbc(ap_index);

    return 0;
}

INT wifi_hal_init()
{
    unsigned int i;
    wifi_radio_info_t *radio;
    char *drv_name;
    wifi_hal_info_print("%s:%d: start\n", __func__, __LINE__);

    if ((drv_name = get_wifi_drv_name()) == NULL) {
        wifi_hal_error_print("%s:%d: driver not found, get drv name failed\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    /* check if driver is loaded */
    while (lsmod_by_name(drv_name) == false) {
        usleep(5000);
    }

    if (init_nl80211() != 0) {
        return RETURN_ERR;
    }

    if (nl80211_init_primary_interfaces() != 0) {
        return RETURN_ERR;
    }

    if (nl80211_init_radio_info() != 0) {
        return RETURN_ERR;
    }

    if (eloop_init() < 0) {
        wifi_hal_error_print("%s:%d: Failed to setup eloop\n", __func__, __LINE__);
        close(g_wifi_hal.nl_event_fd);
        return RETURN_ERR;
    }

    if (pthread_create(&g_wifi_hal.nl_tid, NULL, nl_recv_func, &g_wifi_hal) != 0) {
        wifi_hal_error_print("%s:%d:ssp_main create failed\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    if (eap_server_register_methods() != 0) {
        wifi_hal_error_print("%s:%d: failing to register eap server default methods\n", __func__, __LINE__);
        close(g_wifi_hal.nl_event_fd);
        return RETURN_ERR;
    }

    for (i = 0; i < g_wifi_hal.num_radios; i++) {
        radio = get_radio_by_rdk_index(i);
        if(update_hostap_interfaces(radio) != RETURN_OK) {
            return RETURN_ERR;
        }
    }

    if (update_channel_flags() != 0) {
        return RETURN_ERR;
    }

    wifi_hal_info_print("%s:%d: done\n", __func__, __LINE__);

    return RETURN_OK;
}

INT wifi_hal_pre_init()
{
    platform_pre_init_t  pre_init_fn;
    if ((pre_init_fn = get_platform_pre_init_fn()) != NULL) {
        wifi_hal_info_print("%s:%d: platfrom pre init\n", __func__, __LINE__);
        pre_init_fn();
    }
    return RETURN_OK;
}

INT wifi_hal_post_init(wifi_vap_info_map_t *vap_map)
{
    platform_post_init_t post_init_fn;
    if ((post_init_fn = get_platform_post_init_fn()) != NULL) {
        wifi_hal_info_print("%s:%d: platform post init\n", __func__, __LINE__);
        post_init_fn(vap_map);
    }

    return RETURN_OK;
}

INT wifi_hal_get_default_ssid(char *ssid, int vap_index)
{
    platform_ssid_default_t platform_ssid_default_fn;
    if ((platform_ssid_default_fn = get_platform_ssid_default_fn()) != NULL) {
        wifi_hal_dbg_print("%s:%d: platform ssid init\n", __func__, __LINE__);
        return (platform_ssid_default_fn(ssid, vap_index));
    }

    return RETURN_ERR;
}

INT wifi_hal_get_default_country_code(char *code)
{
    platform_country_code_default_t platform_country_code_default_fn;
    if ((platform_country_code_default_fn = get_platform_country_code_default_fn()) != NULL) {
        wifi_hal_dbg_print("%s:%d: platform country code init\n", __func__, __LINE__);
        return(platform_country_code_default_fn(code));
    }
    return RETURN_ERR;
}

INT wifi_hal_get_default_keypassphrase(char *password, int vap_index)
{
    platform_keypassphrase_default_t platform_keypassphrase_default_fn;
    if ((platform_keypassphrase_default_fn = get_platform_keypassphrase_default_fn()) != NULL) {
        wifi_hal_dbg_print("%s:%d: platform passphrase init\n", __func__, __LINE__);
        return (platform_keypassphrase_default_fn(password, vap_index));
    }

    return RETURN_ERR;
}
INT wifi_hal_get_default_radius_key(char *radius_key)
{
    platform_radius_key_default_t platform_radius_key_default_fn;
    if ((platform_radius_key_default_fn = get_platform_radius_key_default_fn()) != NULL) {
        wifi_hal_dbg_print("%s:%d: platform  default_radius_key\n", __func__, __LINE__);
        return (platform_radius_key_default_fn(radius_key));
    }

    return RETURN_ERR;
}

INT wifi_hal_get_default_wps_pin(char *pin)
{
    platform_wps_pin_default_t platform_wps_pin_default_fn;
    if ((platform_wps_pin_default_fn = get_platform_wps_pin_default_fn()) != NULL) {
        wifi_hal_dbg_print("%s:%d: platform wps pin init\n", __func__, __LINE__);
        return (platform_wps_pin_default_fn(pin));
    }

    return RETURN_ERR;
}

INT wifi_hal_hostApGetErouter0Mac(char *out)
{
    if (out == NULL) {
        return RETURN_ERR;
    }
    strcpy(out, "01:23:12:44:65:ab");
    return RETURN_OK;
}

INT wifi_hal_setRadioOperatingParameters(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam)
{
    wifi_radio_info_t *radio;
    int op_class;
    platform_set_radio_params_t  set_radio_params_fn;
    wifi_interface_info_t *interface = NULL;
    wifi_interface_info_t *primary_interface = NULL;
    wifi_radio_operationParam_t old_operationParam;
    platform_set_radio_pre_init_t set_radio_pre_init_fn;

    if ((op_class = get_op_class_from_radio_params(operationParam)) == -1) {
        wifi_hal_error_print("%s:%d:Could not find country code for radio index:%d\n", __func__, __LINE__, index);
        return RETURN_ERR;
    }

    operationParam->op_class = op_class;
        
    wifi_hal_dbg_print("%s:%d:Index:%d Country: %d, Channel: %d, Op Class:%d\n", 
        __func__, __LINE__, index, operationParam->countryCode, operationParam->channel, operationParam->op_class);

    radio = get_radio_by_rdk_index(index);
    if (radio == NULL) {
        wifi_hal_error_print("%s:%d:Could not find radio index:%d\n", __func__, __LINE__, index);
        return RETURN_ERR;
    }
    if ((set_radio_pre_init_fn = get_platform_set_radio_pre_init_fn()) != NULL) {
        if (set_radio_pre_init_fn(index, operationParam) < 0){
            wifi_hal_dbg_print("%s:%d: Error in setting radio pre init\n", __func__, __LINE__);
            return RETURN_ERR;
        }
    } else {
        wifi_hal_dbg_print("%s:%d: Unable to fetch se_radio_pre_init_fn()\n", __func__, __LINE__);
    }

    primary_interface = get_primary_interface(radio);
    if (primary_interface == NULL) {
        wifi_hal_error_print("%s:%d: Error updating dev:%d no vprimary interface exist\n", __func__, __LINE__, radio->index);
        return RETURN_ERR;
    }
    memcpy((unsigned char *)&old_operationParam, (unsigned char *)&radio->oper_param, sizeof(wifi_radio_operationParam_t));

    nl80211_interface_enable(primary_interface->name, operationParam->enable);

    if (radio->configured && radio->oper_param.enable != operationParam->enable) {
        memcpy((unsigned char *)&radio->oper_param, (unsigned char *)operationParam, sizeof(wifi_radio_operationParam_t));

        if (update_hostap_config_params(radio) != RETURN_OK ) {
            wifi_hal_error_print("%s:%d:Failed to update hostap config params\n", __func__, __LINE__);
            return RETURN_ERR;
        }

        interface = hash_map_get_first(radio->interface_map);
        if (interface == NULL ) {
            wifi_hal_error_print("%s:%d: Interface map is empty for radio\n", __func__, __LINE__);
            goto Exit;
        }

        while (interface != NULL) {
            if (interface->vap_info.vap_mode == wifi_vap_mode_ap) {
                if (radio->oper_param.enable && interface->vap_info.u.bss_info.enabled) {
                    nl80211_interface_enable(interface->name, true);
                    if (update_hostap_interface_params(interface) != RETURN_OK) {
                        return RETURN_ERR;
                    }
                    start_bss(interface);
                    interface->bss_started = true;
                }

                if (radio->oper_param.enable == false && interface->bss_started) {
                    interface->beacon_set = 0;
                    hostapd_reload_config(interface->u.ap.hapd.iface);
#ifdef CONFIG_SAE
                    if (interface->u.ap.conf.sae_groups) {
                        interface->u.ap.conf.sae_groups = NULL;
                    }
#endif
                    nl80211_enable_ap(interface, false);
                    hostapd_bss_deinit_no_free(&interface->u.ap.hapd);
                    hostapd_free_hapd_data(&interface->u.ap.hapd);
                    if (interface->u.ap.hapd.conf->ssid.wpa_psk && !interface->u.ap.hapd.conf->ssid.wpa_psk->next)
                        hostapd_config_clear_wpa_psk(&interface->u.ap.hapd.conf->ssid.wpa_psk);

                    if (update_hostap_interface_params(interface) != RETURN_OK) {
                        return RETURN_ERR;
                    }
                    interface->bss_started = false;
                    nl80211_interface_enable(interface->name, false);
                }
            }

            if (interface->vap_info.vap_mode == wifi_vap_mode_sta) {
                if (radio->oper_param.enable == false) {
                    if (interface->u.sta.state == WPA_COMPLETED) {
                        nl80211_disconnect_sta(interface);
                    }
                    nl80211_interface_enable(interface->name, false);
                }

                if (radio->oper_param.enable) {
                    nl80211_interface_enable(interface->name, true);
                    wifi_drv_set_operstate(interface, 1);
                }
            }

            interface = hash_map_get_next(radio->interface_map, interface);
        }

        goto Exit;
    }

    if (radio->configured && radio->oper_param.enable && (radio->oper_param.channel != operationParam->channel ||
        radio->oper_param.channelWidth != operationParam->channelWidth)) {
        radio->oper_param.channel = operationParam->channel;
        radio->oper_param.channelWidth = operationParam->channelWidth;
        radio->oper_param.op_class = operationParam->op_class;
        radio->oper_param.autoChannelEnabled = operationParam->autoChannelEnabled;
        if (memcmp((unsigned char *)&radio->oper_param, (unsigned char *)operationParam, sizeof(wifi_radio_operationParam_t)) == 0) {
            wifi_hal_dbg_print("%s:%d:Switch channel on radio index:%d\n", __func__, __LINE__, index);

            update_hostap_config_params(radio);
            nl80211_switch_channel(radio);
            goto Exit;
        }
    }

    if (radio->oper_param.countryCode != operationParam->countryCode) {
        wifi_hal_dbg_print("%s:%d:Set country code:%d\n", __func__, __LINE__, operationParam->countryCode);
        nl80211_set_regulatory_domain(operationParam->countryCode);
    }

    memcpy((unsigned char *)&radio->oper_param, (unsigned char *)operationParam, sizeof(wifi_radio_operationParam_t));
    // update the hostap_config parameters
    if (update_hostap_config_params(radio) != RETURN_OK ) {
        wifi_hal_error_print("%s:%d:Failed to update hostap config params\n", __func__, __LINE__);
        goto reload_config;
    }

    if (nl80211_update_wiphy(radio) != 0) {
        wifi_hal_error_print("%s:%d:Failed to update radio\n", __func__, __LINE__);
        goto reload_config;
    }

    // Call Vendor HAL
    if (wifi_setRadioDfsAtBootUpEnable(index,operationParam->DfsEnabledBootup) != 0) {
        wifi_hal_dbg_print("%s:%d:Failed to Enable DFSAtBootUp on radio %d\n", __func__, __LINE__, index);
    }

Exit:
    if ((set_radio_params_fn = get_platform_set_radio_fn()) != NULL) {
        wifi_hal_info_print("%s:%d: set radio params to nvram for radio : %d\n", __func__, __LINE__, index);
        set_radio_params_fn(index, operationParam);
    }

    if (!radio->configured) {
        radio->configured = true;
    }
    return RETURN_OK;

reload_config:
    if (radio->configured == true) {
        memcpy((unsigned char *)&radio->oper_param, (unsigned char *)&old_operationParam, sizeof(wifi_radio_operationParam_t));
    }
    if (update_hostap_config_params(radio) != RETURN_OK ) {
        wifi_hal_error_print("%s:%d:Failed to update hostap config params, Got into a bad state radioindex : %d\n", __func__, __LINE__, index);
        return RETURN_ERR;
    }

    if (nl80211_update_wiphy(radio) != 0) {
        wifi_hal_error_print("%s:%d:Failed to update radio : %d\n", __func__, __LINE__, index);
        return RETURN_ERR;
    }
    return RETURN_ERR;

}

INT wifi_hal_connect(INT ap_index, wifi_bss_info_t *bss)
{
    wifi_interface_info_t *interface;
    wifi_vap_info_t *vap;
    bssid_t null_mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    wifi_bss_info_t *backhaul, *tmp = NULL, *best = NULL;
    wifi_sta_priv_t *sta;
    int best_rssi = -100;

    if ((interface = get_interface_by_vap_index(ap_index)) == NULL) {
        wifi_hal_error_print("%s:%d:interface for ap index:%d not found\n", __func__, __LINE__, ap_index);
        return RETURN_ERR;
    }

    vap = &interface->vap_info;
    if (vap->vap_mode != wifi_vap_mode_sta) {
        wifi_hal_error_print("%s:%d:interface for vap index:%d not found\n", __func__, __LINE__, vap->vap_index);
        return RETURN_ERR;
    }

    sta = &interface->u.sta;
    backhaul = &sta->backhaul;

    if ((bss != NULL) && (memcmp(null_mac, bss->bssid, sizeof(bssid_t)) != 0)) {
        memcpy(backhaul, bss, sizeof(wifi_bss_info_t));
    } else {
        // find from scan list
        tmp = hash_map_get_first(sta->scan_info_map);
        while (tmp != NULL) {
            if ((strcmp(tmp->ssid, vap->u.sta_info.ssid) == 0) &&
                    (tmp->rssi > best_rssi)) {
                best_rssi = tmp->rssi;
                best = tmp;

            }
            tmp = hash_map_get_next(sta->scan_info_map, tmp);
        }

        if (best == NULL) {
            wifi_hal_error_print("%s:%d: Could not find bssid from scan data\n", __func__, __LINE__);
            return RETURN_ERR;
        }

        memcpy(backhaul, best, sizeof(wifi_bss_info_t));
    }

    if (nl80211_connect_sta(interface) != 0) {
        return RETURN_ERR;
    }

    return RETURN_OK;
}

INT wifi_hal_disconnect(INT ap_index)
{
    wifi_interface_info_t *interface;
    wifi_vap_info_t *vap;

    if ((interface = get_interface_by_vap_index(ap_index)) == NULL) {
        wifi_hal_error_print("%s:%d:interface for ap index:%d not found\n", __func__, __LINE__, ap_index);
        return RETURN_ERR;
    }

    vap = &interface->vap_info;
    if (vap->vap_mode != wifi_vap_mode_sta) {
        wifi_hal_error_print("%s:%d:interface for vap index:%d not found\n", __func__, __LINE__, vap->vap_index);
        return RETURN_ERR;
    }

    if (nl80211_disconnect_sta(interface) != 0) {
        return RETURN_ERR;
    }

    return RETURN_OK;
}


INT wifi_hal_findNetworks(INT ap_index, wifi_channel_t *channel, wifi_bss_info_t **bss_array, UINT *num_bss)
{
    wifi_interface_info_t *interface;
    wifi_vap_info_t *vap;
    wifi_sta_priv_t *sta;
    wifi_bss_info_t *bss;
    unsigned int num = 0;
    wifi_bss_info_t *bss_info;
    u8 chan;

    if ((interface = get_interface_by_vap_index(ap_index)) == NULL) {
        wifi_hal_error_print("%s:%d:interface for ap index:%d not found\n", __func__, __LINE__, ap_index);
        return RETURN_ERR;
    }

    vap = &interface->vap_info;
    if (vap->vap_mode != wifi_vap_mode_sta) {
        wifi_hal_error_print("%s:%d:interface for vap index:%d not found\n", __func__, __LINE__, vap->vap_index);
        return RETURN_ERR;
    }

    sta = &interface->u.sta;

    // we may need to lock the hash map so that scan results handlers do not change the map
    bss = hash_map_get_first(sta->scan_info_map);
    while (bss != NULL) {
        if (channel->channel == 0) {
            num++;
        } else {
            ieee80211_freq_to_chan(bss->freq, &chan);
            if (chan == channel->channel) {
                num++;
            }
        }
        bss = hash_map_get_next(sta->scan_info_map, bss);
    }

    bss_info = malloc(num*sizeof(wifi_bss_info_t));
    *bss_array = bss_info;
    *num_bss = num;

    bss = hash_map_get_first(sta->scan_info_map);
    while (bss != NULL) {
        if (channel->channel == 0) {
            memcpy(bss_info, bss, sizeof(wifi_bss_info_t));
        } else {
            ieee80211_freq_to_chan(bss->freq, &chan);
            if (chan == channel->channel) {
                memcpy(bss_info, bss, sizeof(wifi_bss_info_t));
            }
        }
        bss = hash_map_get_next(sta->scan_info_map, bss); bss_info++;
    }

    return RETURN_OK;
}

INT wifi_hal_createVAP(wifi_radio_index_t index, wifi_vap_info_map_t *map)
{
    wifi_radio_info_t *radio;
    wifi_interface_info_t *interface;
    wifi_vap_info_t *vap;
    platform_create_vap_t set_vap_params_fn;
    unsigned int i;
    int filtermode;
    //bssid_t null_mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    wifi_hal_dbg_print("%s:%d: before get_radio_by_index:%d\r\n",__func__, __LINE__, index);
    radio = get_radio_by_rdk_index(index);
    if (radio == NULL) {
        wifi_hal_error_print("%s:%d:Could not find radio index:%d\n", __func__, __LINE__, index);
        return RETURN_ERR;
    }

    // now create vaps on the interfaces
    for (i = 0; i < map->num_vaps; i++) {
        vap = &map->vap_array[i];
        interface = get_interface_by_vap_index(vap->vap_index);

        wifi_hal_dbg_print("%s:%d:vap_index:%d\r\n",__func__, __LINE__, vap->vap_index);
        if (interface == NULL) {
            wifi_hal_info_print("%s:%d:Could not find vap index:%d on radio:%d\n", __func__, __LINE__, vap->vap_index, index);
            assert(0);
            if ((nl80211_create_interface(radio, vap, &interface) != 0) || (interface == NULL)) {
                wifi_hal_error_print("%s:%d: Could not create interface index:%d on radio:%s\n", __func__, __LINE__,
                    vap->vap_index, radio->name);
                continue;
            }
        }

        if (vap->vap_mode == wifi_vap_mode_ap) {
            memcpy(vap->u.bss_info.bssid, interface->mac, sizeof(vap->u.bss_info.bssid));
        } else {
            memcpy(vap->u.sta_info.mac, interface->mac, sizeof(vap->u.sta_info.mac));
        }
        memcpy((unsigned char *)&interface->vap_info, (unsigned char *)vap, sizeof(wifi_vap_info_t));
        nl80211_interface_enable(interface->name, false);

        if (vap->vap_mode == wifi_vap_mode_sta) {
            nl80211_remove_from_bridge(interface->name);
        }

        if (nl80211_update_interface(interface) != 0) {
            wifi_hal_error_print("%s:%d:Failed to update interface:%s\r\n",__func__, __LINE__, interface->name);
            return RETURN_ERR;
        }

        if (radio->configured && radio->oper_param.enable) {
            nl80211_interface_enable(interface->name, true);
        }

        if (vap->vap_mode == wifi_vap_mode_ap) {
            // create the bridge
            if (vap->bridge_name[0] != '\0') {
                if ((nl80211_create_bridge(interface->name, vap->bridge_name) != 0) ||
                        (nl80211_interface_enable(vap->bridge_name, true) != 0)) {
                    wifi_hal_info_print("Failed to bounce interface and create bridge\n");
                    continue;
                }
            }

            if (update_hostap_interface_params(interface) != RETURN_OK) {
                return RETURN_ERR;
            }

            if (interface->vap_initialized == true) {
                if (!(interface->bss_started)) {
                    if (vap->u.bss_info.enabled && radio->configured && radio->oper_param.enable) {
                        start_bss(interface);
                        interface->bss_started = true;
                    }
                } else {
                    // reload vaps config
                    interface->beacon_set = 0;
                    hostapd_reload_config(interface->u.ap.hapd.iface);
#ifdef CONFIG_SAE
                    if (interface->u.ap.conf.sae_groups) {
                        interface->u.ap.conf.sae_groups = NULL;
                    }
#endif
                    nl80211_enable_ap(interface, false);
                    hostapd_bss_deinit_no_free(&interface->u.ap.hapd);
                    hostapd_free_hapd_data(&interface->u.ap.hapd);
                    if (interface->u.ap.hapd.conf->ssid.wpa_psk && !interface->u.ap.hapd.conf->ssid.wpa_psk->next)
                        hostapd_config_clear_wpa_psk(&interface->u.ap.hapd.conf->ssid.wpa_psk);

                    if (update_hostap_interface_params(interface) != RETURN_OK) {
                        return RETURN_ERR;
                    }

                    if (vap->u.bss_info.enabled && radio->configured && radio->oper_param.enable) {
                        start_bss(interface);
                        interface->bss_started = true;
                    }
                    else {
                        interface->bss_started = false;
                    }
                }
            } else {
                interface->vap_initialized = true;
                if (update_hostap_interfaces(radio)!= RETURN_OK) {
                    wifi_hal_error_print("%s:%d:Failed to update hostap interface:%s\r\n",__func__, __LINE__, radio->name);
                    return RETURN_ERR;
                }
                if (vap->u.bss_info.enabled && radio->configured && radio->oper_param.enable) {
                    start_bss(interface);
                    interface->bss_started = true;
                }
            }
            if (radio->configured && radio->oper_param.enable) {
                nl80211_interface_enable(interface->name, vap->u.bss_info.enabled);
            }

            // set the vap mode on the interface
            interface->vap_info.vap_mode = vap->vap_mode;

        } else if (vap->vap_mode == wifi_vap_mode_sta) {
            //XXX set correct status after reconfigure and call conn status callback
            //nl80211_start_scan(interface);
            interface->vap_initialized = true;
            if (radio->configured && radio->oper_param.enable) {
                wifi_drv_set_operstate(interface, 1);
            } else {
                nl80211_interface_enable(interface->name, false);
            }
        }
        //Call vendor HAL
        if (vap->vap_mode == wifi_vap_mode_ap) {
            if (vap->u.bss_info.mac_filter_enable == TRUE) {
                if (vap->u.bss_info.mac_filter_mode == wifi_mac_filter_mode_black_list) {
                    //blacklist
                    filtermode = 2;
                } else {
                    //whitelist
                    filtermode = 1;
                }
            } else {
                //disabled
                filtermode  = 0;
            }

            if (wifi_setApMacAddressControlMode(vap->vap_index, filtermode) < 0) {
                wifi_hal_error_print("%s:%d: wifi_setApMacAddressControlMode apIndex %d failed\n",
                                         __func__, __LINE__, vap->vap_index);
                return RETURN_ERR;
            }
        }
    }

    if ((set_vap_params_fn = get_platform_create_vap_fn()) != NULL) {
        wifi_hal_info_print("%s:%d: set vap params to nvram\n", __func__, __LINE__);
        set_vap_params_fn(index, map);
    }

    return RETURN_OK;
}

INT wifi_hal_kickAssociatedDevice(INT ap_index, mac_address_t mac)
{
    wifi_interface_info_t *interface;

    interface  = get_interface_by_vap_index(ap_index);
    if (interface ==  NULL) {
        wifi_hal_error_print("%s:%d: NULL Interface pointer \n", __func__, __LINE__);
        return RETURN_ERR;
    }

    if (nl80211_kick_device(interface, mac) != 0) {
        wifi_hal_error_print("%s:%d: nl80211_kick_device failed for device %02x:....%02x\n", __func__, __LINE__, mac[0], mac[5]);
        return RETURN_ERR;
    }

    return RETURN_OK;
}

INT wifi_hal_getRadioVapInfoMap(wifi_radio_index_t index, wifi_vap_info_map_t *map)
{
    unsigned int itr = 0;
    wifi_interface_info_t *interface = NULL;
    wifi_radio_info_t *radio =  NULL;

    if((index >= MAX_NUM_RADIOS) || (map == NULL)) {
        wifi_hal_error_print("%s:%d: Inalid radio index or vapmap is NULL:%d\n", __func__, __LINE__, index);
        return RETURN_ERR;
    }

    radio = get_radio_by_rdk_index(index);
    if (radio == NULL) {
        wifi_hal_error_print("%s:%d: Could not find radio index:%d\n", __func__, __LINE__, index);
        return RETURN_ERR;
    }

    if (radio->interface_map == NULL) {
        wifi_hal_error_print("%s:%d: No interface map is empty for radio index:%d\n", __func__, __LINE__, index);
        return RETURN_ERR;
    }

    interface = hash_map_get_first(radio->interface_map);
    if (interface == NULL ) {
        wifi_hal_error_print("%s:%d: Interface map is empty for radio\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    while (interface != NULL) {
        memcpy(&map->vap_array[itr], &interface->vap_info, sizeof(wifi_vap_info_t));

        if (strncmp((char *)map->vap_array[itr].vap_name, "mesh_sta", strlen("mesh_sta")) != 0) {
            memcpy(map->vap_array[itr].u.bss_info.bssid, interface->mac, sizeof(map->vap_array[itr].u.bss_info.bssid));
        } else {
            memcpy(map->vap_array[itr].u.sta_info.mac, interface->mac, sizeof(map->vap_array[itr].u.sta_info.mac));
        }

        interface = hash_map_get_next(radio->interface_map, interface);

        itr++;
    }

    map->num_vaps = itr;

    return RETURN_OK;
}

INT wifi_hal_getScanResults(wifi_radio_index_t index, wifi_channel_t *channel, wifi_bss_info_t **bss, UINT *num_bss)
{
    wifi_radio_info_t *radio;
    wifi_interface_info_t *interface;
//    wifi_vap_info_t *vap;
    wifi_radio_operationParam_t *radio_param;
    bool found = false;
    unsigned int freq = 0, total_count = 0;
    char country[8];
    wifi_sta_priv_t *sta;
    wifi_bss_info_t *scan_info, *tmp_bss;

    radio = get_radio_by_rdk_index(index);
    if (radio == NULL) {
        wifi_hal_error_print("%s:%d: Could not find radio for index: %d\n", __func__, __LINE__, index);
        return RETURN_ERR;
    }

    interface = hash_map_get_first(radio->interface_map);

    while (interface != NULL) {

        if (interface->vap_info.vap_mode == wifi_vap_mode_sta) {
            found = true;
            break;
        }

        interface = hash_map_get_next(radio->interface_map, interface);
    }

    if (found == false) {
        wifi_hal_error_print("%s:%d: Could not find sta interface on radio index: %d, start scan failure\n",
            __func__, __LINE__, index);
        return RETURN_ERR;
    }

//    vap = &interface->vap_info;
    radio_param = &radio->oper_param;

    get_coutry_str_from_code(radio_param->countryCode, country);

    if (channel != NULL) {
        if (radio_param->band != channel->band) {
            wifi_hal_error_print("%s:%d: Channel not valid on radio index: %d band : 0x%x\n", __func__, __LINE__, index, channel->band);
            return RETURN_ERR;
        } else if ((freq = ieee80211_chan_to_freq(country, radio_param->op_class, channel->channel)) == -1) {
            wifi_hal_error_print("%s:%d: Channel argument error for index : %d channel : %d\n", __func__, __LINE__, index, channel->channel);
            return RETURN_ERR;
        }
    }

    sta = &interface->u.sta;

    scan_info = hash_map_get_first(sta->scan_info_map);
    while (scan_info != NULL) {
        if (freq == 0) {
            total_count += 1;
        } else {
            total_count += (freq == scan_info->freq) ? 1:0;
        }
        scan_info = hash_map_get_next(sta->scan_info_map, scan_info);
    }

    *num_bss = total_count;
    tmp_bss = malloc(total_count*sizeof(wifi_bss_info_t));
    *bss = tmp_bss;

    scan_info = hash_map_get_first(sta->scan_info_map);
    while (scan_info != NULL) {
        if (freq == 0) {
            memcpy(tmp_bss, scan_info, sizeof(wifi_bss_info_t));
        } else {
            if (freq == scan_info->freq) {
                memcpy(tmp_bss, scan_info, sizeof(wifi_bss_info_t));

            }
        }
        tmp_bss++;
        scan_info = hash_map_get_next(sta->scan_info_map, scan_info);
    }


    return RETURN_OK;
}

static int chann_to_freq(unsigned char radio_index, unsigned char chan)
{
    switch(radio_index) {
        case 0:
            if (chan >= 1 && chan <= 11) {
                return 2407 + 5 * chan;
            } else {
                return 0;
            }
            break;
        case 1:
            if (chan >= 36 && chan <= 165) {
                return 5000 + 5 * chan;
            } else {
                return 0;
            }
            break;
        default:
            wifi_hal_error_print("%s:%d:wrong radio_index: %d\n", __func__, __LINE__, radio_index);
            return RETURN_ERR;
    }
}


INT wifi_hal_sendDataFrame( int vap_id, unsigned char *dmac, unsigned char *data_buff, int data_len, BOOL insert_llc, int protocol, int priority)
{
    struct sockaddr_ll addr;
    struct ether_header *ethHdr;
    unsigned int t_data[1600/4];
    int t_len=0;
    wifi_interface_info_t *interface = NULL;
    wifi_hal_dbg_print("Entering for %s:%d:for : %d\n", __func__, __LINE__, vap_id);

    if ((t_len = (data_len + sizeof(struct ether_header))) > sizeof(t_data))
         return RETURN_ERR;

    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL);

    if(g_fd_arr[vap_id] <= 0 ) {
        g_fd_arr[vap_id] = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (g_fd_arr[vap_id] < 0)
            return RETURN_ERR;

        interface = get_interface_by_vap_index((unsigned int)vap_id);
        if (interface != NULL) {
            g_IfIdx_arr[vap_id] = interface->index;
            memcpy(&g_vapSmac[vap_id][0], interface->mac, sizeof(mac_address_t));
        } else {
            close(g_fd_arr[vap_id]);
            g_fd_arr[vap_id] = -1;
            g_IfIdx_arr[vap_id] = -1;
            return RETURN_ERR;
        }

        addr.sll_ifindex = g_IfIdx_arr[vap_id];
        if (bind(g_fd_arr[vap_id], (const struct sockaddr *)&addr, sizeof(addr)) < 0) {
            close(g_fd_arr[vap_id]);
            g_fd_arr[vap_id] = -1;
            g_IfIdx_arr[vap_id] = -1;
            return RETURN_ERR;
        }
    }

    ethHdr = (struct ether_header *) t_data;
    memcpy(ethHdr->ether_shost, &g_vapSmac[vap_id][0], sizeof(mac_address_t));
    memcpy(ethHdr->ether_dhost, dmac, sizeof(mac_address_t));
    ethHdr->ether_type = htons(protocol);
    ethHdr++;

    memcpy((void *)ethHdr, data_buff, data_len);
    t_len = sizeof(struct ether_header) + data_len;

    addr.sll_ifindex = g_IfIdx_arr[vap_id];
    addr.sll_halen = ETH_ALEN;
    memcpy(addr.sll_addr, dmac, ETH_ALEN);

    if (sendto(g_fd_arr[vap_id], t_data, t_len, 0, (struct sockaddr *)&addr, sizeof(addr)) == t_len) {
        return RETURN_OK;
    }
    return RETURN_ERR;
}

INT wifi_hal_startScan(wifi_radio_index_t index, wifi_neighborScanMode_t scan_mode, INT dwell_time, UINT num, UINT *chan_list)
{
    wifi_radio_info_t *radio;
    wifi_interface_info_t *interface;
    wifi_vap_info_t *vap;
    bool found = false;
    wifi_radio_operationParam_t *radio_param;
    char country[8] = {0}, tmp_str[32] = {0}, chan_list_str[512] = {0};
    unsigned int freq_list[32], i;
    ssid_t  ssid_list[8];

    radio = get_radio_by_rdk_index(index);
    if (radio == NULL) {
        wifi_hal_error_print("%s:%d:Could not find radio for index: %d\n", __func__, __LINE__, index);
        return RETURN_ERR; 
    }

    interface = hash_map_get_first(radio->interface_map);

    while (interface != NULL) {

        if (interface->vap_info.vap_mode == wifi_vap_mode_sta) {
            found = true;
            break;
        }

        interface = hash_map_get_next(radio->interface_map, interface);
    }

    if (found == false) {
        wifi_hal_error_print("%s:%d:Could not find sta interface on radio index: %d, start scan failure\n", 
            __func__, __LINE__, index);
        return RETURN_ERR;
    }

    vap = &interface->vap_info;
    radio_param = &radio->oper_param;

    if (scan_mode == WIFI_RADIO_SCAN_MODE_ONCHAN) {
        num = 1;
    } else if (scan_mode == WIFI_RADIO_SCAN_MODE_OFFCHAN) {
        if ((num == 0) || (chan_list == NULL)) {
            wifi_hal_error_print("%s:%d: Channels not speified for offchannel scan mode\n", __func__, __LINE__);
            return RETURN_ERR; 
        }
    } else {
        wifi_hal_error_print("%s:%d: Incorrect scan mode\n", __func__, __LINE__);
        return RETURN_ERR; 
    }

    get_coutry_str_from_code(radio_param->countryCode, country);

    for (i = 0; i < num; i++) {
        //freq_list[i] = ieee80211_chan_to_freq(country, radio_param->op_class, (scan_mode == WIFI_RADIO_SCAN_MODE_ONCHAN)? radio_param->channel:chan_list[i]);
        freq_list[i] = chann_to_freq(index, (scan_mode == WIFI_RADIO_SCAN_MODE_ONCHAN)? radio_param->channel:chan_list[i]);
        if (freq_list[i] == RETURN_ERR) {
            wifi_hal_error_print("%s:%d: wrong radio index:%d channel:%d\n", __func__, __LINE__, index,
                        (scan_mode == WIFI_RADIO_SCAN_MODE_ONCHAN)? radio_param->channel:chan_list[i]);
            return RETURN_ERR;
        }
        sprintf(tmp_str, "%d ", freq_list[i]);
        strcat(chan_list_str, tmp_str);
    }

    strcpy(ssid_list[0], vap->u.sta_info.ssid);
    wifi_hal_info_print("%s:%d: Scan Frequencies:%s for ssid:%s\n", __func__, __LINE__, chan_list_str, ssid_list);

    return (nl80211_start_scan(interface, num, freq_list, 1, ssid_list) == 0) ? RETURN_OK:RETURN_ERR;
}

INT wifi_hal_mgmt_frame_callbacks_register(wifi_receivedMgmtFrame_callback func)
{
    wifi_device_callbacks_t *callbacks;
    callbacks = get_hal_device_callbacks();
    if (callbacks == NULL) {
        return RETURN_ERR;
    }
    callbacks->mgmt_frame_rx_callback = func;

    return 0;
}

void wifi_hal_newApAssociatedDevice_callback_register(wifi_newApAssociatedDevice_callback func)
{
    wifi_device_callbacks_t *callbacks;

    callbacks = get_hal_device_callbacks();

    if (callbacks == NULL || callbacks->num_assoc_cbs > MAX_REGISTERED_CB_NUM) {
        return;
    }

    callbacks->assoc_cb[callbacks->num_assoc_cbs] = func;
    callbacks->num_assoc_cbs++;
}

void wifi_hal_apDeAuthEvent_callback_register(wifi_apDeAuthEvent_callback func)
{
    wifi_device_callbacks_t *callbacks;

    callbacks = get_hal_device_callbacks();

    if (callbacks == NULL || callbacks->num_apDeAuthEvent_cbs > MAX_REGISTERED_CB_NUM) {
        return;
    }

    callbacks->apDeAuthEvent_cb[callbacks->num_apDeAuthEvent_cbs] = func;
    callbacks->num_apDeAuthEvent_cbs++;
}

INT wifi_vapstatus_callback_register(wifi_vapstatus_callback func) {
    wifi_device_callbacks_t *callbacks;

    callbacks = get_hal_device_callbacks();

    if(callbacks == NULL || callbacks->num_vapstatus_cbs > MAX_REGISTERED_CB_NUM) {
        return RETURN_ERR;
    }
    callbacks->vapstatus_cb[callbacks->num_vapstatus_cbs] = func;
    callbacks->num_vapstatus_cbs++;
    return RETURN_OK;
}

void wifi_hal_apDisassociatedDevice_callback_register(wifi_apDisassociatedDevice_callback func)
{
    wifi_device_callbacks_t *callbacks;

    callbacks = get_hal_device_callbacks();

    if (callbacks == NULL || callbacks->num_disassoc_cbs> MAX_REGISTERED_CB_NUM) {
        return;
    }

    callbacks->disassoc_cb[callbacks->num_disassoc_cbs] = func;
    callbacks->num_disassoc_cbs++;
}

void wifi_hal_staConnectionStatus_callback_register(wifi_staConnectionStatus_callback func)
{
    wifi_device_callbacks_t *callbacks;

    callbacks = get_hal_device_callbacks();
    if (callbacks == NULL) {
        return;
    }

    callbacks->sta_conn_status_callback = func;

    return;
}

void wifi_hal_scanResults_callback_register(wifi_scanResults_callback func)
{
    wifi_device_callbacks_t *callbacks;

    callbacks = get_hal_device_callbacks();
    if (callbacks == NULL) {
        return;
    }

    callbacks->scan_result_callback = func;

    return;
}

INT wifi_hal_analytics_callback_register(wifi_analytics_callback l_callback_cb)
{
    wifi_device_callbacks_t *callbacks;

    callbacks = get_hal_device_callbacks();
    if (callbacks == NULL) {
       return RETURN_ERR;
    }

    callbacks->analytics_callback = l_callback_cb;
    return RETURN_OK;
}

INT wifi_chan_event_register(wifi_chan_event_CB_t event_cb)
{
    wifi_device_callbacks_t *callbacks;

    callbacks = get_hal_device_callbacks();
    if (callbacks == NULL) {
       return RETURN_ERR;
    }

    callbacks->channel_change_event_callback = event_cb;
    return RETURN_OK;
}

wifi_device_callbacks_t *get_hal_device_callbacks()
{
    return &g_wifi_hal.device_callbacks;
}

