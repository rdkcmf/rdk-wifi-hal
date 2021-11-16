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
    struct nlattr *frame, *addr, *cookie, *ack;
    union wpa_event_data event;
    const struct ieee80211_hdr *hdr;
    u16 fc;
    
    if ((frame = tb[NL80211_ATTR_FRAME]) == NULL) {
        wifi_hal_dbg_print("%s:%d: frame attribute not present\n", __func__, __LINE__);
        return;
    } 
    
    if ((addr = tb[NL80211_ATTR_MAC]) == NULL) {
        //wifi_hal_dbg_print("%s:%d: mac attribute not present\n", __func__, __LINE__);
    } 
    
    if ((cookie = tb[NL80211_ATTR_COOKIE]) == NULL) {
        wifi_hal_dbg_print("%s:%d: cookie attribute not present\n", __func__, __LINE__);
    } 
    
    if ((ack = tb[NL80211_ATTR_ACK]) == NULL) {
        wifi_hal_dbg_print("%s:%d: ack attribute not present\n", __func__, __LINE__);
    }

    hdr = (const struct ieee80211_hdr *)nla_data(frame);
    fc = le_to_host16(hdr->frame_control);

    os_memset(&event, 0, sizeof(event));
    event.tx_status.type = WLAN_FC_GET_TYPE(fc);
    event.tx_status.stype = WLAN_FC_GET_STYPE(fc);
    event.tx_status.dst = hdr->addr1;
    event.tx_status.data = nla_data(frame);
    event.tx_status.data_len = nla_len(frame);
    event.tx_status.ack = ack != NULL;

    wpa_supplicant_event(&interface->u.ap.hapd, EVENT_TX_STATUS, &event);
}

static void nl80211_new_station_event(wifi_interface_info_t *interface, struct nlattr **tb)
{
    union wpa_event_data event;
    unsigned char *ies = NULL;
    size_t ies_len = 0;
    struct nlattr *attr;
    mac_address_t mac;
    mac_addr_str_t mac_str;

    if ((attr = tb[NL80211_ATTR_MAC]) == NULL) {
        wifi_hal_dbg_print("%s:%d: mac attribute not present ... dropping\n", __func__, __LINE__);
        return;
    }

    memcpy(mac, nla_data(attr), sizeof(mac_address_t));

    if (tb[NL80211_ATTR_IE]) {
        ies = nla_data(tb[NL80211_ATTR_IE]);
        ies_len = nla_len(tb[NL80211_ATTR_IE]);
    } else {
        wifi_hal_dbg_print("%s:%d:ie attribute not present\n", __func__, __LINE__);
        return;
    }
    
    //my_print_hex_dump(ies_len, ies);
    wifi_hal_dbg_print("%s:%d: New station:%s, sending event: EVENT_ASSOC\n", __func__, __LINE__, 
        to_mac_str(mac, mac_str));

    os_memset(&event, 0, sizeof(event));
    event.assoc_info.reassoc = 0;
    event.assoc_info.req_ies = ies;
    event.assoc_info.req_ies_len = ies_len;
    event.assoc_info.addr = (unsigned char *)&mac;
    
    wpa_supplicant_event(&interface->u.ap.hapd, EVENT_ASSOC, &event);
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
        wifi_hal_dbg_print("%s:%d:attribute scan_ssids not present\n", __func__, __LINE__);
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
        wifi_hal_dbg_print("%s:%d: status code attribute absent\n", __func__, __LINE__);
        return;
    } else {
        memcpy((unsigned char *)&status, nla_data(tb[NL80211_ATTR_STATUS_CODE]), nla_len(tb[NL80211_ATTR_STATUS_CODE]));
    }

    if (status != WLAN_STATUS_SUCCESS) {
        wifi_hal_dbg_print("%s:%d: status code unsuccessful, returning\n", __func__, __LINE__);
        send_sta_connection_status_to_cb(backhaul->bssid, interface->vap_info.vap_index, wifi_connection_status_ap_not_found);
        return;    
    }

    if (tb[NL80211_ATTR_MAC] == NULL) {
        wifi_hal_dbg_print("%s:%d: mac attribute absent\n", __func__, __LINE__);
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

    if (tb[NL80211_ATTR_REASON_CODE] == NULL) {
        wifi_hal_dbg_print("%s:%d: reason code attribute absent\n", __func__, __LINE__);
    }

    if (tb[NL80211_ATTR_MAC] == NULL) {
        wifi_hal_dbg_print("%s:%d: mac attribute absent\n", __func__, __LINE__);
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

static void do_process_drv_event(wifi_interface_info_t *interface, int cmd, struct nlattr **tb)
{
    switch (cmd) {
    case NL80211_CMD_NEW_STATION:
        nl80211_new_station_event(interface, tb);
        break;

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

    default:
        break;
    }
}

int process_global_nl80211_event(struct nl_msg *msg, void *arg)
{
    wifi_hal_priv_t *priv = (wifi_hal_priv_t *)arg;
    struct genlmsghdr *gnlh;
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    unsigned int ifidx = 0;//, wiphy_idx_rx;
    //unsigned long wdev_id;
    wifi_radio_info_t *radio;
    wifi_interface_info_t *interface;
    unsigned int i;

    gnlh = nlmsg_data(nlmsg_hdr(msg));
    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

    if (tb[NL80211_ATTR_IFINDEX])
        ifidx = nla_get_u32(tb[NL80211_ATTR_IFINDEX]);
#if 0
    else if (tb[NL80211_ATTR_WDEV]) {
        wdev_id = nla_get_u64(tb[NL80211_ATTR_WDEV]);
    } else if (tb[NL80211_ATTR_WIPHY]) {
        wiphy_idx_rx = nla_get_u32(tb[NL80211_ATTR_WIPHY]);
    }
#endif
    //wifi_hal_dbg_print("%s:%d:event %d (%s) for interface (ifindex %d wdev 0x%llx)\n",
                //__func__, __LINE__, gnlh->cmd, nl80211_command_to_string(gnlh->cmd),
                //ifidx, (long long unsigned int) wdev_id);

    for (i = 0; i < priv->num_radios; i++) {
        radio = &priv->radio_info[i];
        interface = hash_map_get_first(radio->interface_map);
        while (interface != NULL) {
            if ((ifidx == interface->index) && (interface->vap_configured == true)) {
                do_process_drv_event(interface, gnlh->cmd, tb);
            } else {
                //wifi_hal_dbg_print("%s:%d: Skipping event %d (%s) for foreign interface (ifindex %d wdev 0x%llx)\n", 
                    //__func__, __LINE__,
                    //gnlh->cmd, nl80211_command_to_string(gnlh->cmd),
                    //ifidx, (long long unsigned int) wdev_id);

            }

            interface = hash_map_get_next(radio->interface_map, interface);
        }

    }

    return NL_SKIP;
}
