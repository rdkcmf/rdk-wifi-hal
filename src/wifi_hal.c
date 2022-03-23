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
#include <net/if.h>
#include "wifi_hal.h"
#include "wifi_hal_priv.h"
#include <assert.h>
#include "hostapd/eap_register.h"

INT wifi_hal_getHalCapability(wifi_hal_capability_t *hal)
{
    unsigned int i;
    wifi_interface_info_t *interface;
    wifi_radio_info_t *radio;
    wifi_radio_capabilities_t *cap;
    wifi_vap_info_t *vap;

    hal->version.major = WIFI_HAL_MAJOR;
    hal->version.minor = WIFI_HAL_MINOR;

    hal->wifi_prop.numRadios = g_wifi_hal.num_radios;

    for (i = 0; i < hal->wifi_prop.numRadios; i++) {
        radio = &g_wifi_hal.radio_info[i];
        wifi_hal_dbg_print("%s:%d:Enumerating interfaces on radio index: %d\n", __func__, __LINE__, radio->index);

        interface = hash_map_get_first(radio->interface_map);
        while (interface != NULL) {
	    vap = &interface->vap_info;
            wifi_hal_dbg_print("%s:%d: interface name: %s, vap index: %d, vap name: %s\n", __func__, __LINE__,
                		interface->name, vap->vap_index, vap->vap_name);
            interface = hash_map_get_next(radio->interface_map, interface);
        }

        cap = &hal->wifi_prop.radiocap[i];
        memcpy((unsigned char *)cap, (unsigned char *)&radio->capab, sizeof(wifi_radio_capabilities_t));

    }

    get_wifi_interface_info_map(hal->wifi_prop.interface_map);

    return RETURN_OK;
}

INT wifi_hal_init()
{
    unsigned int i;
    wifi_radio_info_t *radio;
    char *drv_name;
    const char *device_name = 
#ifdef RASPBERRY_PI_PORT
        "pi4";
#else
        "tcxb7";
#endif

    if ((drv_name = get_wifi_drv_name(device_name)) == NULL) {
		wifi_hal_dbg_print("%s:%d: driver not found, init failed\n", __func__, __LINE__);
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

    if (pthread_create(&g_wifi_hal.nl_tid, NULL, nl_recv_func, &g_wifi_hal) != 0) {
        wifi_hal_dbg_print("%s:%d:ssp_main create failed\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    if (eloop_init() < 0) {
        wifi_hal_dbg_print("%s:%d: Failed to setup eloop\n", __func__, __LINE__);
        close(g_wifi_hal.nl_event_fd);
        return RETURN_ERR;
    }

    if (eap_server_register_methods() != 0) {
        wifi_hal_dbg_print("%s:%d: failing to register eap server default methods\n", __func__, __LINE__);
        close(g_wifi_hal.nl_event_fd);
        return RETURN_ERR;
    }

    for (i = 0; i < g_wifi_hal.num_radios; i++) {
        radio = &g_wifi_hal.radio_info[i];
        if(update_hostap_interfaces(radio) != RETURN_OK) {
            return RETURN_ERR;
        }
    }

    return RETURN_OK;
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

    if ((op_class = get_op_class_from_radio_params(operationParam)) == -1) {
        wifi_hal_dbg_print("%s:%d:Could not find country code for radio index:%d\n", __func__, __LINE__, index);
        return RETURN_ERR;
    }

    operationParam->op_class = op_class;
        
    wifi_hal_dbg_print("%s:%d:Index:%d Country: %d, Channel: %d, Op Class:%d\n", 
        __func__, __LINE__, index, operationParam->countryCode, operationParam->channel, operationParam->op_class);

    radio = get_radio_by_rdk_index(index);
    if (radio == NULL) {
        wifi_hal_dbg_print("%s:%d:Could not find radio index:%d\n", __func__, __LINE__, index);
        return RETURN_ERR;
    }

    memcpy((unsigned char *)&radio->oper_param, (unsigned char *)operationParam, sizeof(wifi_radio_operationParam_t));
    if (nl80211_update_wiphy(radio) != 0) {
        wifi_hal_dbg_print("%s:%d:Failed to update radio\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    // update the hostap_config parameters
    if (update_hostap_config_params(radio) != RETURN_OK ) {
        wifi_hal_dbg_print("%s:%d:Failed to update hostap config params\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    return RETURN_OK;
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
        wifi_hal_dbg_print("%s:%d:interface for ap index:%d not found\n", __func__, __LINE__, ap_index);
        return RETURN_ERR;
    }

    vap = &interface->vap_info;
    if (vap->vap_mode != wifi_vap_mode_sta) {
        wifi_hal_dbg_print("%s:%d:interface for vap index:%d not found\n", __func__, __LINE__, vap->vap_index);
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
            wifi_hal_dbg_print("%s:%d: Could not find bssid from scan data\n", __func__, __LINE__);
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
        wifi_hal_dbg_print("%s:%d:interface for ap index:%d not found\n", __func__, __LINE__, ap_index);
        return RETURN_ERR;
    }

    vap = &interface->vap_info;
    if (vap->vap_mode != wifi_vap_mode_sta) {
        wifi_hal_dbg_print("%s:%d:interface for vap index:%d not found\n", __func__, __LINE__, vap->vap_index);
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
        wifi_hal_dbg_print("%s:%d:interface for ap index:%d not found\n", __func__, __LINE__, ap_index);
        return RETURN_ERR;
    }

    vap = &interface->vap_info;
    if (vap->vap_mode != wifi_vap_mode_sta) {
        wifi_hal_dbg_print("%s:%d:interface for vap index:%d not found\n", __func__, __LINE__, vap->vap_index);
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
    unsigned int i;
    //bssid_t null_mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    wifi_hal_dbg_print("%s:%d: before get_radio_by_index:%d\r\n",__func__, __LINE__, index);
    radio = get_radio_by_rdk_index(index);
    if (radio == NULL) {
        wifi_hal_dbg_print("%s:%d:Could not find radio index:%d\n", __func__, __LINE__, index);
        return RETURN_ERR;
    }

    // now create vaps on the interfaces
    for (i = 0; i < map->num_vaps; i++) {
        vap = &map->vap_array[i];
        interface = get_interface_by_vap_index(vap->vap_index);

        wifi_hal_dbg_print("%s:%d:vap_index:%d\r\n",__func__, __LINE__, vap->vap_index);
        if (interface == NULL) {
            wifi_hal_dbg_print("%s:%d:Could not find vap index:%d on radio:%d\n", __func__, __LINE__, vap->vap_index, index);
            assert(0);
            if ((nl80211_create_interface(radio, vap, &interface) != 0) || (interface == NULL)) {
                wifi_hal_dbg_print("%s:%d: Could not create interface index:%d on radio:%s\n", __func__, __LINE__,
                    vap->vap_index, radio->name);
                continue;
            }
        }

        memcpy((unsigned char *)&interface->vap_info, (unsigned char *)vap, sizeof(wifi_vap_info_t));
        nl80211_interface_enable(interface->name, false);

        if (vap->vap_mode == wifi_vap_mode_sta) {
            nl80211_remove_from_bridge(interface->name);
        }

        if (nl80211_update_interface(interface) != 0) {
            wifi_hal_dbg_print("%s:%d:Failed to update interface:%s\r\n",__func__, __LINE__, interface->name);
            return RETURN_ERR;
        }

        nl80211_interface_enable(interface->name, true);

        if (vap->vap_mode == wifi_vap_mode_ap) {
            // create the bridge
            if ((nl80211_create_bridge(interface->name, vap->bridge_name) != 0) ||
                    (nl80211_interface_enable(vap->bridge_name, true) != 0)) {
                wifi_hal_dbg_print("Failed to bounce interface and create bridge\n");
                continue;
            }

            if (update_hostap_interface_params(interface) != RETURN_OK) {
                return RETURN_ERR;
            }

            if (interface->vap_initialized == true) {
                if (!(interface->bss_started)) {
                    if (vap->u.bss_info.enabled) {
                        start_bss(interface);
                        interface->bss_started = true;
                    }
                } else {
                    // reload vaps config
                    hostapd_reload_config(interface->u.ap.hapd.iface);
                    nl80211_enable_ap(interface, vap->u.bss_info.enabled);
                }
            } else {
                interface->vap_initialized = true;
                if (update_hostap_interfaces(radio)!= RETURN_OK) {
                    wifi_hal_dbg_print("%s:%d:Failed to update hostap interface:%s\r\n",__func__, __LINE__, radio->name);
                    return RETURN_ERR;
                }
                if (vap->u.bss_info.enabled) {
                    start_bss(interface);
                    interface->bss_started = true;
                }
            }
            nl80211_interface_enable(interface->name, vap->u.bss_info.enabled);

            // set the vap mode on the interface
            interface->vap_info.vap_mode = vap->vap_mode;
            memcpy(vap->u.bss_info.bssid, interface->vap_info.u.bss_info.bssid, sizeof(vap->u.bss_info.bssid));

        } else if (vap->vap_mode == wifi_vap_mode_sta) {
            //XXX set correct status after reconfigure and call conn status callback
            //nl80211_start_scan(interface);
            interface->vap_initialized = true;
            wifi_drv_set_operstate(interface, 1);
            memcpy(vap->u.sta_info.bssid, interface->vap_info.u.bss_info.bssid, sizeof(vap->u.bss_info.bssid));
        }
    }

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
        wifi_hal_dbg_print("%s:%d: Could not find radio for index: %d\n", __func__, __LINE__, index);
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
        wifi_hal_dbg_print("%s:%d: Could not find sta interface on radio index: %d, start scan failure\n",
            __func__, __LINE__, index);
        return RETURN_ERR;
    }

//    vap = &interface->vap_info;
    radio_param = &radio->oper_param;

    get_coutry_str_from_code(radio_param->countryCode, country);

    if (channel != NULL) {
        if (radio_param->band != channel->band) {
            wifi_hal_dbg_print("%s:%d: Channel not valid on radio index: %d\n", __func__, __LINE__, index);
            return RETURN_ERR;
        } else if ((freq = ieee80211_chan_to_freq(country, radio_param->op_class, channel->channel)) == -1) {
            wifi_hal_dbg_print("%s:%d: Channel argument error\n", __func__, __LINE__);
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
        wifi_hal_dbg_print("%s:%d:Could not find radio for index: %d\n", __func__, __LINE__, index);
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
        wifi_hal_dbg_print("%s:%d:Could not find sta interface on radio index: %d, start scan failure\n", 
            __func__, __LINE__, index);
        return RETURN_ERR;
    }

    vap = &interface->vap_info;
    radio_param = &radio->oper_param;

    if (scan_mode == WIFI_RADIO_SCAN_MODE_ONCHAN) {
        num = 1;
    } else if (scan_mode == WIFI_RADIO_SCAN_MODE_OFFCHAN) {
        if ((num == 0) || (chan_list == NULL)) {
            wifi_hal_dbg_print("%s:%d: Channels not speified for offchannel scan mode\n", __func__, __LINE__);
            return RETURN_ERR; 
        }
    } else {
        wifi_hal_dbg_print("%s:%d: Incorrect scan mode\n", __func__, __LINE__);
        return RETURN_ERR; 
    }

    get_coutry_str_from_code(radio_param->countryCode, country);

    for (i = 0; i < num; i++) {
        freq_list[i] = ieee80211_chan_to_freq(country, radio_param->op_class, (scan_mode == WIFI_RADIO_SCAN_MODE_ONCHAN)? radio_param->channel:chan_list[i]);
        sprintf(tmp_str, "%d ", freq_list[i]);
        strcat(chan_list_str, tmp_str);
    }
    wifi_hal_dbg_print("%s:%d: Scan Frequencies: %s\n", __func__, __LINE__, chan_list_str);

    strcpy(ssid_list[0], vap->u.sta_info.ssid);

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

wifi_device_callbacks_t *get_hal_device_callbacks()
{
    return &g_wifi_hal.device_callbacks;
}

