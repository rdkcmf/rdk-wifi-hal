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
#include <stdbool.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <stdarg.h>
#include <pthread.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/rtnetlink.h>
#include <netpacket/packet.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <netlink/handlers.h>
#include <netlink/attr.h>
#include <netlink/genl/genl.h>
#include "wifi_hal.h"
#include "wifi_hal_priv.h"
#include <linux/nl80211.h>

int no_seq_check(struct nl_msg *msg, void *arg)
{
    return NL_OK;
}

static void nl80211_frame_tx_status_event(wifi_interface_info_t *interface, struct nlattr **tb)
{
    struct nlattr *frame, *addr, *cookie, *ack, *attr;
    union wpa_event_data event;
    const struct ieee80211_hdr *hdr;
    mac_addr_str_t  sta_mac_str;
    u16 reason = 0;
    u16 fc;
    struct sta_info *station = NULL;
    wifi_device_callbacks_t *callbacks = NULL;
    wifi_frame_t mgmt_frame;
    int sig_dbm = -100;

    wifi_mgmtFrameType_t mgmt_type = WIFI_MGMT_FRAME_TYPE_INVALID;
    wifi_vap_info_t *vap;
    wifi_direction_t dir;
    mac_address_t   sta, bmac = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    callbacks = get_hal_device_callbacks();

    if ((frame = tb[NL80211_ATTR_FRAME]) == NULL) {
        wifi_hal_error_print("%s:%d: frame attribute not present\n", __func__, __LINE__);
        return;
    }

    vap = &interface->vap_info;
    if ((addr = tb[NL80211_ATTR_MAC]) == NULL) {
        //wifi_hal_dbg_print("%s:%d: mac attribute not present\n", __func__, __LINE__);
    }

    if ((cookie = tb[NL80211_ATTR_COOKIE]) == NULL) {
        wifi_hal_info_print("%s:%d: cookie attribute not present\n", __func__, __LINE__);
    }

    if ((ack = tb[NL80211_ATTR_ACK]) == NULL) {
        wifi_hal_info_print("%s:%d: ack attribute not present\n", __func__, __LINE__);
    }

    if (tb[NL80211_ATTR_RX_SIGNAL_DBM]) {
        sig_dbm = nla_get_u32(tb[NL80211_ATTR_RX_SIGNAL_DBM]);
    }

    hdr = (const struct ieee80211_hdr *)nla_data(frame);
    fc = le_to_host16(hdr->frame_control);

    if (memcmp(hdr->addr1, interface->mac, sizeof(mac_address_t)) == 0) {
        memcpy(sta, hdr->addr2, sizeof(mac_address_t));
        dir = wifi_direction_uplink;
    } else if (memcmp(hdr->addr2, interface->mac, sizeof(mac_address_t)) == 0) {
        memcpy(sta, hdr->addr1, sizeof(mac_address_t));
        dir = wifi_direction_downlink;
    } else if (memcmp(hdr->addr1, bmac, sizeof(mac_address_t)) == 0) {
        memcpy(sta, hdr->addr2, sizeof(mac_address_t));
        dir = wifi_direction_uplink;
    } else {
        wifi_hal_error_print("%s:%d: unknown interface... dropping\n", __func__, __LINE__);
        return;
    }

    os_memset(&event, 0, sizeof(event));
    event.tx_status.type = WLAN_FC_GET_TYPE(fc);
    event.tx_status.stype = WLAN_FC_GET_STYPE(fc);
    event.tx_status.dst = hdr->addr1;
    event.tx_status.data = nla_data(frame);
    event.tx_status.data_len = nla_len(frame);
    event.tx_status.ack = ack != NULL;

   if (event.tx_status.type  == WLAN_FC_TYPE_MGMT &&
     (event.tx_status.stype == WLAN_FC_STYPE_AUTH ||
        event.tx_status.stype == WLAN_FC_STYPE_ASSOC_RESP ||
        event.tx_status.stype == WLAN_FC_STYPE_REASSOC_RESP ||
        event.tx_status.stype == WLAN_FC_STYPE_DISASSOC ||
        event.tx_status.stype == WLAN_FC_STYPE_DEAUTH ||
        event.tx_status.stype == WLAN_FC_STYPE_PROBE_RESP ||
        event.tx_status.stype == WLAN_FC_STYPE_ACTION)) {

        switch(event.tx_status.stype) {
         case WLAN_FC_STYPE_AUTH:
            mgmt_type = WIFI_MGMT_FRAME_TYPE_AUTH;
            break;

        case WLAN_FC_STYPE_ASSOC_RESP:
            mgmt_type = WIFI_MGMT_FRAME_TYPE_ASSOC_RSP;
            break;

        case WLAN_FC_STYPE_REASSOC_RESP:
            mgmt_type = WIFI_MGMT_FRAME_TYPE_REASSOC_RSP;
            break;

        case WLAN_FC_STYPE_DISASSOC:
            mgmt_type = WIFI_MGMT_FRAME_TYPE_DISASSOC;
            wifi_hal_dbg_print("%s:%d: Received disassoc frame from: %s\n", __func__, __LINE__,
                           to_mac_str(sta, sta_mac_str));
            station = ap_get_sta(&interface->u.ap.hapd, sta);
            if (station) {
                if (station->disconnect_reason_code == WLAN_RADIUS_GREYLIST_REJECT) {
                    reason = station->disconnect_reason_code;
                }
                ap_free_sta(&interface->u.ap.hapd, station);
            }

            for (int i = 0; i < callbacks->num_disassoc_cbs; i++) {
                if (callbacks->disassoc_cb[i] != NULL) {
                    callbacks->disassoc_cb[i](vap->vap_index, to_mac_str(sta, sta_mac_str), reason);
                }
            }
            break;

        case WLAN_FC_STYPE_DEAUTH:
            mgmt_type = WIFI_MGMT_FRAME_TYPE_DEAUTH;
            wifi_hal_dbg_print("%s:%d: Received deauth frame from: %s\n", __func__, __LINE__,
                           to_mac_str(sta, sta_mac_str));
            if (callbacks->num_apDeAuthEvent_cbs == 0) {
                break;
            }
            if ((attr = tb[NL80211_ATTR_REASON_CODE]) != NULL) {
                reason = nla_get_u16(attr);
            }
            station = ap_get_sta(&interface->u.ap.hapd, sta);
            if (station) {
                if (station->disconnect_reason_code == WLAN_RADIUS_GREYLIST_REJECT) {
                    reason = station->disconnect_reason_code;
                    wifi_hal_info_print("reason from disconnect reason code is %d\n",reason);
                }
                ap_free_sta(&interface->u.ap.hapd, station);
            }

            for (int i = 0; i < callbacks->num_apDeAuthEvent_cbs; i++) {
                if (callbacks->apDeAuthEvent_cb[i] != NULL) {
                   callbacks->apDeAuthEvent_cb[i](vap->vap_index, to_mac_str(sta, sta_mac_str), reason);
                }
            }
            break;

        case WLAN_FC_STYPE_PROBE_RESP:
            mgmt_type = WIFI_MGMT_FRAME_TYPE_PROBE_RSP;
            break;

        case WLAN_FC_STYPE_ACTION:
            mgmt_type = WIFI_MGMT_FRAME_TYPE_ACTION;
            break;

        default:
            break;
        }

        callbacks = get_hal_device_callbacks();
        if (callbacks->mgmt_frame_rx_callback) {
            mgmt_frame.ap_index = vap->vap_index; 
            memcpy(mgmt_frame.sta_mac, sta, sizeof(mac_address_t));
            mgmt_frame.type = mgmt_type;
            mgmt_frame.dir = dir;
            mgmt_frame.sig_dbm = sig_dbm; 
            mgmt_frame.len = event.tx_status.data_len;
            mgmt_frame.data = (unsigned char *)event.tx_status.data; 
#ifdef WIFI_HAL_VERSION_3_PHASE2
            callbacks->mgmt_frame_rx_callback(vap->vap_index, &mgmt_frame);
#else
            callbacks->mgmt_frame_rx_callback(vap->vap_index, sta, (unsigned char *)event.tx_status.data,
                event.tx_status.data_len, mgmt_type, dir);
#endif
        }
    }
    wpa_supplicant_event(&interface->u.ap.hapd, EVENT_TX_STATUS, &event);
}

static void nl80211_new_scan_results_event(wifi_interface_info_t *interface, struct nlattr **tb)
{
    int rem;
    struct nlattr *nl;

    wifi_hal_dbg_print("%s:%d:Enter for interface:%s\n", __func__, __LINE__, interface->name);
    
    if (tb[NL80211_ATTR_SCAN_SSIDS]) {
        nla_for_each_nested(nl, tb[NL80211_ATTR_SCAN_SSIDS], rem) {
            ;//wifi_hal_dbg_print("%s:%d: Scan probed for SSID '%s'", __func__, __LINE__, nla_data(nl));
        }
    } else {
        wifi_hal_info_print("%s:%d:attribute scan_ssids not present\n", __func__, __LINE__);
    }

    nl80211_get_scan_results(interface);
}

void send_sta_connection_status_to_cb(unsigned char *mac, unsigned int vap_index, wifi_connection_status_t conn_status)
{
    wifi_bss_info_t bss;
    wifi_station_stats_t sta;
    wifi_device_callbacks_t *callbacks;
    callbacks = get_hal_device_callbacks();

    if ((callbacks != NULL) && (callbacks->sta_conn_status_callback)) {
        memcpy(bss.bssid, mac, sizeof(bssid_t));

        sta.vap_index = vap_index;
        sta.connect_status = conn_status;

        wifi_hal_purgeScanResult(vap_index, mac);
        callbacks->sta_conn_status_callback(vap_index, &bss, &sta);
    }
}

static void nl80211_connect_event(wifi_interface_info_t *interface, struct nlattr **tb)
{
    mac_address_t mac;
    mac_addr_str_t mac_str;
    unsigned short status;
    char *assoc_req, *assoc_rsp;
    mac_addr_str_t bssid_str;
    wifi_bss_info_t *backhaul;
    wifi_vap_security_t *sec;
    sec = &interface->vap_info.u.sta_info.security;

    backhaul = &interface->u.sta.backhaul;

    wifi_hal_dbg_print("%s:%d:bssid:%s frequency:%d ssid:%s\n", __func__, __LINE__,
        to_mac_str(backhaul->bssid, bssid_str), backhaul->freq, backhaul->ssid);

    assoc_req = interface->u.sta.assoc_req;
    assoc_rsp = interface->u.sta.assoc_rsp;

    if (tb[NL80211_ATTR_STATUS_CODE] == NULL) {
        wifi_hal_error_print("%s:%d: status code attribute absent\n", __func__, __LINE__);
        return;
    } else {
        memcpy((unsigned char *)&status, nla_data(tb[NL80211_ATTR_STATUS_CODE]), nla_len(tb[NL80211_ATTR_STATUS_CODE]));
    }

    if (status != WLAN_STATUS_SUCCESS) {
        wifi_hal_error_print("%s:%d: status code unsuccessful, returning\n", __func__, __LINE__);
        send_sta_connection_status_to_cb(backhaul->bssid, interface->vap_info.vap_index, wifi_connection_status_ap_not_found);
        return;    
    }

    if (tb[NL80211_ATTR_MAC] == NULL) {
        wifi_hal_error_print("%s:%d: mac attribute absent\n", __func__, __LINE__);
        return;
    } else {
        memcpy(mac, nla_data(tb[NL80211_ATTR_MAC]), nla_len(tb[NL80211_ATTR_MAC]));
        wifi_hal_dbg_print("%s:%d: Connect indication for %s\n", __func__, __LINE__,
            to_mac_str(mac, mac_str));

    }

    if (tb[NL80211_ATTR_REQ_IE] == NULL) { 
        wifi_hal_dbg_print("%s:%d: req ie attribute absent\n", __func__, __LINE__);
    } else {
        interface->u.sta.assoc_req_len = nla_len(tb[NL80211_ATTR_REQ_IE]);
        memcpy(assoc_req, nla_data(tb[NL80211_ATTR_REQ_IE]), nla_len(tb[NL80211_ATTR_REQ_IE])); 
    }

    if (tb[NL80211_ATTR_RESP_IE] == NULL) {
        wifi_hal_dbg_print("%s:%d: resp ie attribute absent\n", __func__, __LINE__);
    } else {
        interface->u.sta.assoc_rsp_len = nla_len(tb[NL80211_ATTR_RESP_IE]);
        memcpy(assoc_rsp, nla_data(tb[NL80211_ATTR_RESP_IE]), nla_len(tb[NL80211_ATTR_RESP_IE])); 
    }

    if (tb[NL80211_ATTR_TIMED_OUT] == NULL) {
        wifi_hal_dbg_print("%s:%d: timed out attribute absent\n", __func__, __LINE__);
    }

    if (tb[NL80211_ATTR_TIMEOUT_REASON] == NULL) {
        wifi_hal_dbg_print("%s:%d: timed out reason attribute absent\n", __func__, __LINE__);
    }

    if (tb[NL80211_ATTR_PMK] == NULL) {
        wifi_hal_dbg_print("%s:%d: pmk attribute absent\n", __func__, __LINE__);
    }

    if (tb[NL80211_ATTR_PMKID] == NULL) {
        wifi_hal_dbg_print("%s:%d: pmkid attribute absent\n", __func__, __LINE__);
    }

    update_wpa_sm_params(interface);
    update_eapol_sm_params(interface);
    eapol_sm_notify_portEnabled(interface->u.sta.wpa_sm->eapol, TRUE);

    if (interface->u.sta.pending_rx_eapol) {
        struct ieee802_1x_hdr *hdr;

        hdr = (struct ieee802_1x_hdr *)(interface->u.sta.rx_eapol_buff + sizeof(struct ieee8023_hdr));

        //XXX: eapol_sm_rx_eapol
        wpa_sm_rx_eapol(interface->u.sta.wpa_sm, (unsigned char *)&interface->u.sta.src_addr, (unsigned char *)hdr,
            interface->u.sta.buff_len - sizeof(struct ieee8023_hdr));
        interface->u.sta.pending_rx_eapol = false;
    }

    if (sec->mode == wifi_security_mode_none) {
        wpa_sm_set_state(interface->u.sta.wpa_sm, WPA_COMPLETED);
    }

    interface->u.sta.state = WPA_ASSOCIATED;
}

static void nl80211_disconnect_event(wifi_interface_info_t *interface, struct nlattr **tb)
{
    mac_address_t mac;
    mac_addr_str_t mac_str;
    struct nlattr *attr;

    wifi_device_callbacks_t *callbacks;
    wifi_vap_info_t *vap;
    wifi_bss_info_t bss;
    wifi_station_stats_t sta;

    vap = &interface->vap_info;
    interface->u.sta.state = WPA_DISCONNECTED;

    callbacks = get_hal_device_callbacks();

    if (callbacks->sta_conn_status_callback) {
        memcpy(bss.bssid, interface->u.sta.backhaul.bssid, sizeof(bssid_t));

        sta.vap_index = vap->vap_index;
        sta.connect_status = wifi_connection_status_disconnected;

        callbacks->sta_conn_status_callback(vap->vap_index, &bss, &sta);
    }

    if (interface->u.sta.wpa_sm != NULL) {
        wpa_sm_deinit(interface->u.sta.wpa_sm);
        interface->u.sta.wpa_sm = NULL;
    }

    if ((attr = tb[NL80211_ATTR_REASON_CODE]) != NULL) {
        wifi_hal_info_print("%s:%d: reason code:%d\n", __func__, __LINE__, nla_get_u16(attr));
    } else {
        wifi_hal_dbg_print("%s:%d: reason code attribute absent\n", __func__, __LINE__);
    }

    if (tb[NL80211_ATTR_MAC] == NULL) {
        wifi_hal_error_print("%s:%d: mac attribute absent\n", __func__, __LINE__);
        return;
    } else {
        memcpy(mac, nla_data(tb[NL80211_ATTR_MAC]), nla_len(tb[NL80211_ATTR_MAC]));
        wifi_hal_dbg_print("%s:%d: Disconnect indication for %s\n", __func__, __LINE__,
            to_mac_str(mac, mac_str));

    }

    if (tb[NL80211_ATTR_DISCONNECTED_BY_AP] == NULL) {
        wifi_hal_dbg_print("%s:%d: disconnected by ap attribute absent\n", __func__, __LINE__);
    }

}

static void nl80211_ch_switch_notify_event(wifi_interface_info_t *interface, struct nlattr **tb, wifi_chan_eventType_t wifi_chan_event_type)
{
    int ifidx = 0, freq = 0, bw = NL80211_CHAN_WIDTH_20_NOHT, cf1 = 0, cf2 = 0;
    enum nl80211_channel_type ch_type = 0;
    u8 channel;
    wifi_channel_change_event_t radio_channel_param;
    int l_channel_width, op_class;
    enum nl80211_radar_event event_type = 0;
    unsigned int *p_prev_channel, *p_prev_channelWidth;

    p_prev_channel      = &g_wifi_hal.radio_info[interface->vap_info.radio_index].prev_channel;
    p_prev_channelWidth = &g_wifi_hal.radio_info[interface->vap_info.radio_index].prev_channelWidth;

    wifi_hal_dbg_print("%s:%d: wifi_chan_event_type:%d\n", __func__, __LINE__, wifi_chan_event_type);
    
    if (wifi_chan_event_type == WIFI_EVENT_CHANNELS_CHANGED && interface->u.ap.hapd.csa_in_progress) {
        hostapd_cleanup_cs_params(&interface->u.ap.hapd);
        ieee802_11_set_beacon(&interface->u.ap.hapd);
    }

    memset(&radio_channel_param, 0, sizeof(radio_channel_param));

    if (tb[NL80211_ATTR_IFINDEX]) {
        ifidx = nla_get_u32(tb[NL80211_ATTR_IFINDEX]);
    }

    if(tb[NL80211_ATTR_WIPHY_FREQ] == NULL) {
        wifi_hal_dbg_print("%s:%d: channel attribute not present\n", __func__, __LINE__);
        return;
    } else {
        freq = nla_get_u32(tb[NL80211_ATTR_WIPHY_FREQ]);
        ieee80211_freq_to_chan(freq, &channel);
    }

    if(tb[NL80211_ATTR_WIPHY_CHANNEL_TYPE]) {
        ch_type = nla_get_u32(tb[NL80211_ATTR_WIPHY_CHANNEL_TYPE]);
    }

    if(tb[NL80211_ATTR_CHANNEL_WIDTH]) {
        bw = nla_get_u32(tb[NL80211_ATTR_CHANNEL_WIDTH]);
    }

    if(tb[NL80211_ATTR_CENTER_FREQ1]) {
        cf1 = nla_get_u32(tb[NL80211_ATTR_CENTER_FREQ1]);
    }

    if(tb[NL80211_ATTR_CENTER_FREQ2]) {
        cf2 = nla_get_u32(tb[NL80211_ATTR_CENTER_FREQ2]);
    }
    
    if (tb[NL80211_ATTR_RADAR_EVENT]) {
        event_type = nla_get_u32(tb[NL80211_ATTR_RADAR_EVENT]);
        radio_channel_param.sub_event = (wifi_radar_eventType_t)event_type;
    }

    wifi_device_callbacks_t *callbacks;
    callbacks = get_hal_device_callbacks();


    wifi_radio_info_t *radio;
    radio = get_radio_by_rdk_index(interface->vap_info.radio_index);
    if (radio == NULL) {
        wifi_hal_error_print("%s:%d: could not find radio index:%d\n", __func__, __LINE__, interface->vap_info.radio_index);
        return;
    }

    wifi_radio_operationParam_t *radio_param;
    radio_param = &radio->oper_param;

    switch (bw) {
    case NL80211_CHAN_WIDTH_20:
        l_channel_width = WIFI_CHANNELBANDWIDTH_20MHZ;
        break;
    case NL80211_CHAN_WIDTH_40:
        l_channel_width = WIFI_CHANNELBANDWIDTH_40MHZ;
        break;
    case NL80211_CHAN_WIDTH_80:
        l_channel_width = WIFI_CHANNELBANDWIDTH_80MHZ;
        break;
    case NL80211_CHAN_WIDTH_160:
        l_channel_width = WIFI_CHANNELBANDWIDTH_160MHZ;
        break;
    case NL80211_CHAN_WIDTH_80P80:
        l_channel_width = WIFI_CHANNELBANDWIDTH_80_80MHZ;
        break;
    default:
        l_channel_width = WIFI_CHANNELBANDWIDTH_20MHZ;
        break;
    }

    if ((wifi_chan_event_type == WIFI_EVENT_CHANNELS_CHANGED) && ((*p_prev_channel == channel)
                             && (*p_prev_channelWidth == l_channel_width))) {
        return;
    } else {
        wifi_hal_dbg_print("%s:%d: ifidx:%d vap_name:%s on radio:%d channel:%d freq:%d bandwidth:%d cf1:%d cf2:%d \
                            channelType:%d wifi_chan_event_type:%d radar_event_type %d\n", __func__, __LINE__,
                            ifidx, interface->vap_info.vap_name, interface->vap_info.radio_index, channel, freq, bw,
                            cf1, cf2, ch_type, wifi_chan_event_type, event_type);
    }

    radio_param->channelWidth = l_channel_width;
    radio_param->channel = channel;
    if ((op_class = get_op_class_from_radio_params(radio_param)) == -1) {
        wifi_hal_error_print("%s:%d: could not find op_class for radio index:%d\n", __func__, __LINE__, interface->vap_info.radio_index);
        return;
    }
    radio_param->op_class = op_class;

    if ((callbacks != NULL) && (callbacks->channel_change_event_callback)) {
        radio_channel_param.radioIndex = interface->vap_info.radio_index;
        radio_channel_param.event = wifi_chan_event_type;
        radio_channel_param.channel = channel;
        radio_channel_param.channelWidth = radio_param->channelWidth;
        radio_channel_param.op_class = op_class;
        callbacks->channel_change_event_callback(radio_channel_param);
    }

    *p_prev_channel = channel;
    *p_prev_channelWidth = l_channel_width;

}

static void do_process_drv_event(wifi_interface_info_t *interface, int cmd, struct nlattr **tb)
{
    switch (cmd) {
    case NL80211_CMD_FRAME_TX_STATUS:
        nl80211_frame_tx_status_event(interface, tb);
        break;

    case NL80211_CMD_NEW_SCAN_RESULTS:
        nl80211_new_scan_results_event(interface, tb);
        break;

    case NL80211_CMD_CONNECT:
        nl80211_connect_event(interface, tb);
        break;

    case NL80211_CMD_DISCONNECT:
        nl80211_disconnect_event(interface, tb);
        break;

    case NL80211_CMD_CHANNEL_SWITCH:
        break;

    case NL80211_CMD_CH_SWITCH_NOTIFY:
        nl80211_ch_switch_notify_event(interface, tb, WIFI_EVENT_CHANNELS_CHANGED);
        break;

    case NL80211_CMD_RADAR_DETECT:
        nl80211_ch_switch_notify_event(interface, tb, WIFI_EVENT_DFS_RADAR_DETECTED);
        break;

   default:
        break;
    }
}

int process_global_nl80211_event(struct nl_msg *msg, void *arg)
{
    wifi_hal_priv_t *priv = (wifi_hal_priv_t *)arg;
    struct genlmsghdr *gnlh;
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    unsigned int ifidx = 0;
    int wiphy_idx_rx = -1;
    //unsigned long wdev_id = 0;
    wifi_radio_info_t *radio;
    wifi_interface_info_t *interface;
    unsigned int i;

    gnlh = nlmsg_data(nlmsg_hdr(msg));
    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

    if (tb[NL80211_ATTR_IFINDEX]) {
        ifidx = nla_get_u32(tb[NL80211_ATTR_IFINDEX]);
    } else if (tb[NL80211_ATTR_WIPHY]) {
        wiphy_idx_rx = nla_get_u32(tb[NL80211_ATTR_WIPHY]);
    }
    //else if (tb[NL80211_ATTR_WDEV]) {
      //  wdev_id = nla_get_u64(tb[NL80211_ATTR_WDEV]);
    //}

    //wifi_hal_dbg_print("%s:%d:event %d for interface (ifindex %d wdev 0x%llx wiphy %d)\n",
                //__func__, __LINE__, gnlh->cmd,
                //ifidx, (long long unsigned int) wdev_id, wiphy_idx_rx);

    for (i = 0; i < priv->num_radios; i++) {
        radio = &priv->radio_info[i];
        interface = hash_map_get_first(radio->interface_map);
        while (interface != NULL) {
            if ((wiphy_idx_rx != -1) || ((ifidx == interface->index) && (interface->vap_configured == true)) ) {
                do_process_drv_event(interface, gnlh->cmd, tb);
            } else {
                //wifi_hal_dbg_print("%s:%d: Skipping event %d for foreign interface (ifindex %d wdev 0x%llx)\n", 
                    //__func__, __LINE__,
                    //gnlh->cmd,
                    //ifidx, (long long unsigned int) wdev_id);
            }

            interface = hash_map_get_next(radio->interface_map, interface);
        }

    }

    return NL_SKIP;
}
