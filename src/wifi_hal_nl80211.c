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
 *
 * Some material is:
 * Copyright (c) 2002-2015, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2003-2004, Instant802 Networks, Inc.
 * Copyright (c) 2005-2006, Devicescape Software, Inc.
 * Copyright (c) 2007, Johannes Berg <johannes@sipsolutions.net>
 * Copyright (c) 2009-2010, Atheros Communications
 * Licensed under the BSD-3 License
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
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/rtnetlink.h>
#include <netpacket/packet.h>
#include <linux/nl80211.h>
#include <netlink/route/link/bridge.h>
#include "wifi_hal.h"
#include "wifi_hal_priv.h"
#include "wpa_auth_i.h"
#include "driver_nl80211.h"
#include "ap/sta_info.h"
#include <sys/wait.h>

#define OVS_MODULE "/sys/module/openvswitch"

static int scan_info_handler(struct nl_msg *msg, void *arg);

struct family_data {
    const char *group;
    int id;
};

void prepare_interface_fdset(wifi_hal_priv_t *priv)
{
    wifi_radio_info_t *radio;
    wifi_interface_info_t *interface;
    wifi_vap_info_t *vap;
    unsigned int i;
    int sock_fd;
        
    FD_ZERO(&priv->drv_rfds);
    FD_SET(priv->nl_event_fd, &priv->drv_rfds);
    FD_SET(priv->link_fd, &priv->drv_rfds);

    for (i = 0; i < priv->num_radios; i++) {
        radio = &priv->radio_info[i];
        interface = hash_map_get_first(radio->interface_map);

        while (interface != NULL) {
            if (interface->vap_configured == true) {
                vap = &interface->vap_info;
                sock_fd = (vap->vap_mode == wifi_vap_mode_ap) ? 
                                    interface->u.ap.br_sock_fd:interface->u.sta.sta_sock_fd;
                FD_SET(sock_fd, &priv->drv_rfds);
                if (interface->vap_info.vap_mode == wifi_vap_mode_ap) {
                    FD_SET(interface->nl_event_fd, &priv->drv_rfds);
                }
            }

            interface = hash_map_get_next(radio->interface_map, interface);
        }
 
    }
    eloop_sock_table_read_set_fds(&priv->drv_rfds);
}

int get_biggest_in_fdset(wifi_hal_priv_t *priv)
{
    int sock_fd = 0;
    wifi_radio_info_t *radio;
    wifi_interface_info_t *interface;
    wifi_vap_info_t *vap;
    unsigned int i;
    int eloop_sock_fd = 0;
        
    sock_fd = priv->nl_event_fd > priv->link_fd ? priv->nl_event_fd : priv->link_fd;

    for (i = 0; i < priv->num_radios; i++) {
        radio = &priv->radio_info[i];
        interface = hash_map_get_first(radio->interface_map);

        while (interface != NULL) {
            if (interface->vap_configured == true) {
                vap = &interface->vap_info;
                if (sock_fd < ((vap->vap_mode == wifi_vap_mode_ap) ? 
                        interface->u.ap.br_sock_fd:interface->u.sta.sta_sock_fd)) {
                    sock_fd = (vap->vap_mode == wifi_vap_mode_ap) ? 
                                    interface->u.ap.br_sock_fd:interface->u.sta.sta_sock_fd;
                }
                if (interface->vap_info.vap_mode == wifi_vap_mode_ap && sock_fd < interface->nl_event_fd) {
                    sock_fd = interface->nl_event_fd;
                }

            }

            interface = hash_map_get_next(radio->interface_map, interface);
        }
 
    }
    eloop_sock_fd = eloop_sock_table_read_get_biggest_fd();
    if(sock_fd < eloop_sock_fd) {
        sock_fd = eloop_sock_fd;
    }
    //wifi_hal_dbg_print("%s:%d:Biggest descriptor:%d\n", __func__, __LINE__, fd);
    return sock_fd;
}

static u32 sta_flags_nl80211(int flags)
{
    u32 f = 0;

    if (flags & WPA_STA_AUTHORIZED)
        f |= BIT(NL80211_STA_FLAG_AUTHORIZED);
    if (flags & WPA_STA_WMM)
        f |= BIT(NL80211_STA_FLAG_WME);
    if (flags & WPA_STA_SHORT_PREAMBLE)
        f |= BIT(NL80211_STA_FLAG_SHORT_PREAMBLE);
    if (flags & WPA_STA_MFP)
        f |= BIT(NL80211_STA_FLAG_MFP);
    if (flags & WPA_STA_TDLS_PEER)
        f |= BIT(NL80211_STA_FLAG_TDLS_PEER);
    if (flags & WPA_STA_AUTHENTICATED)
        f |= BIT(NL80211_STA_FLAG_AUTHENTICATED);
    if (flags & WPA_STA_ASSOCIATED)
        f |= BIT(NL80211_STA_FLAG_ASSOCIATED);

    return f;
}

bool mgmt_fd_isset(wifi_hal_priv_t *priv, wifi_interface_info_t **intf)
{
    bool found = false;
    wifi_radio_info_t *radio;
    wifi_interface_info_t *interface;
    unsigned int i;
        
    for (i = 0; i < priv->num_radios; i++) {
        radio = &priv->radio_info[i];
        interface = hash_map_get_first(radio->interface_map);
        while (interface != NULL) {
            if ((interface->vap_configured == true) && (interface->vap_info.vap_mode == wifi_vap_mode_ap) &&
                    FD_ISSET(interface->nl_event_fd, &priv->drv_rfds)) {
                found = true;
                *intf = interface;
                break; 
            }

            interface = hash_map_get_next(radio->interface_map, interface);
        }
 
    }

    return found;
}


bool bridge_fd_isset(wifi_hal_priv_t *priv, wifi_interface_info_t **intf)
{
    bool found = false;
    wifi_radio_info_t *radio;
    wifi_interface_info_t *interface;
    wifi_vap_info_t *vap;
    unsigned int i;
        
    for (i = 0; i < priv->num_radios; i++) {
        radio = &priv->radio_info[i];
        interface = hash_map_get_first(radio->interface_map);
        vap = &interface->vap_info;

        while (interface != NULL) {
            if ((interface->vap_configured == true) && 
                    FD_ISSET(((vap->vap_mode == wifi_vap_mode_ap)?
                            interface->u.ap.br_sock_fd:interface->u.sta.sta_sock_fd), &priv->drv_rfds)) {
                found = true;
                *intf = interface;
                break; 
            }

            interface = hash_map_get_next(radio->interface_map, interface);
        }
 
    }

    return found;
}

int process_mgmt_frame(struct nl_msg *msg, void *arg)
{
    wifi_interface_info_t *interface;
    wifi_mgmtFrameType_t mgmt_type;
    wifi_direction_t dir;
    struct genlmsghdr *gnlh;
    struct nlattr *tb[NL80211_ATTR_MAX + 1], *attr;
    unsigned int len;
    unsigned char cat;
    struct ieee80211_mgmt *mgmt;
    unsigned short fc, stype;
    mac_address_t   sta, bmac = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    mac_addr_str_t  sta_mac_str, interface_mac_str, frame_da_str;
    wifi_vap_info_t *vap;
    bool drop = false;
    int reason = 0;
    wifi_device_callbacks_t *callbacks;
    struct sta_info *station = NULL;
    wifi_frame_t mgmt_frame;
    int sig_dbm = -100;

    gnlh = nlmsg_data(nlmsg_hdr(msg));
    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

    interface = (wifi_interface_info_t *)arg;
    vap = &interface->vap_info;

    //wifi_hal_dbg_print("%s:%d: BSS Event %d (%s) received for %s\n", __func__, __LINE__, 
           //gnlh->cmd, nl80211_command_to_string(gnlh->cmd),
           //interface->name);

    if (gnlh->cmd != NL80211_CMD_FRAME) {
        wifi_hal_error_print("%s:%d: Unknown event\n", __func__, __LINE__);
        return NL_SKIP;
    }

    if ((attr = tb[NL80211_ATTR_FRAME]) == NULL) {
        wifi_hal_error_print("%s:%d: frame attribute absent ... dropping\n", __func__, __LINE__);
        return NL_SKIP;
    } 
        
    callbacks = get_hal_device_callbacks();
    mgmt = (struct ieee80211_mgmt *)nla_data(attr);
    len = nla_len(attr);

    //my_print_hex_dump(len, mgmt);
    if ((attr = tb[NL80211_ATTR_MAC]) == NULL) {
        //;
    }

    if (tb[NL80211_ATTR_RX_SIGNAL_DBM]) {
        sig_dbm = nla_get_u32(tb[NL80211_ATTR_RX_SIGNAL_DBM]);
    }

    if (memcmp(mgmt->da, interface->mac, sizeof(mac_address_t)) == 0) {
        memcpy(sta, mgmt->sa, sizeof(mac_address_t));
        dir = wifi_direction_uplink;
    } else if (memcmp(mgmt->sa, interface->mac, sizeof(mac_address_t)) == 0) {
        memcpy(sta, mgmt->da, sizeof(mac_address_t));
        dir = wifi_direction_downlink;
    } else if (memcmp(mgmt->da, bmac, sizeof(mac_address_t)) == 0) {
        memcpy(sta, mgmt->sa, sizeof(mac_address_t));
        dir = wifi_direction_uplink;
    } else {
        to_mac_str(interface->mac, interface_mac_str);
        to_mac_str(mgmt->sa, sta_mac_str);
        to_mac_str(mgmt->da, frame_da_str);
        wifi_hal_error_print("%s:%d: unknown interface... dropping\n", __func__, __LINE__);
        if ((callbacks != NULL) && (callbacks->analytics_callback != NULL)) {
            callbacks->analytics_callback("Dropping mgmt frame from interface:%s sta mac:%s frame da:%s",
                interface_mac_str, sta_mac_str, frame_da_str);
        }
        return NL_SKIP;
    }

    fc = le_to_host16(mgmt->frame_control);
    stype = WLAN_FC_GET_STYPE(fc);

    switch(stype) {
    case WLAN_FC_STYPE_AUTH:
        mgmt_type = WIFI_MGMT_FRAME_TYPE_AUTH;
        wifi_hal_dbg_print("%s:%d: Received auth frame from: %s\n", __func__, __LINE__, 
                           to_mac_str(sta, sta_mac_str)); 
        break;

    case WLAN_FC_STYPE_ASSOC_REQ:
        /* fall through */
    case WLAN_FC_STYPE_REASSOC_REQ:
        mgmt_type = WIFI_MGMT_FRAME_TYPE_ASSOC_REQ;
        wifi_hal_dbg_print("%s:%d: Received assoc frame from: %s\n", __func__, __LINE__, 
                           to_mac_str(sta, sta_mac_str));
        break;

    case WLAN_FC_STYPE_ASSOC_RESP:
        mgmt_type = WIFI_MGMT_FRAME_TYPE_ASSOC_RSP;
        break;

    case WLAN_FC_STYPE_PROBE_REQ:
        mgmt_type = WIFI_MGMT_FRAME_TYPE_PROBE_REQ;
        //wifi_hal_dbg_print("%s:%d: Received probe req frame from: %s\n", __func__, __LINE__, 
        //to_mac_str(sta, sta_mac_str));
        break;

    case WLAN_FC_STYPE_ACTION:
        mgmt_type = WIFI_MGMT_FRAME_TYPE_ACTION;
        cat = mgmt->u.action.category;

        wifi_hal_dbg_print("%s:%d: Received action frame from: %s, category %d\n", __func__, __LINE__, 
                           to_mac_str(sta, sta_mac_str), cat);

        switch (cat) {
        case wifi_action_frame_type_public:
            handle_public_action_frame(vap->vap_index, sta, (wifi_publicActionFrameHdr_t *)mgmt, len);
            break;
        default:
            break;
        }
        break;

    case WLAN_FC_STYPE_DISASSOC:
        mgmt_type = WIFI_MGMT_FRAME_TYPE_DISASSOC;
        wifi_hal_dbg_print("%s:%d: Received disassoc frame from: %s\n", __func__, __LINE__, 
                           to_mac_str(sta, sta_mac_str));


        station = ap_get_sta(&interface->u.ap.hapd, sta);
        if (station) {
            wifi_hal_dbg_print("station disassocreason in disassoc frame is %d\n",station->disconnect_reason_code);
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

        u16 reason = 0;

        if (callbacks->num_apDeAuthEvent_cbs == 0) {
            break;
        }

        if ((attr = tb[NL80211_ATTR_REASON_CODE]) != NULL) {
            reason = nla_get_u16(attr);
        }

        for (int i = 0; i < callbacks->num_apDeAuthEvent_cbs; i++) {
            if (callbacks->apDeAuthEvent_cb[i] != NULL) {
                callbacks->apDeAuthEvent_cb[i](vap->vap_index, to_mac_str(sta, sta_mac_str), reason);
            }
        }
        break;    

    default:
        drop = true;
        break;
    }

    if (drop == true) {
        wifi_hal_error_print("%s:%d: unknown interface... dropping\n", __func__, __LINE__);
        return NL_SKIP;
    }

    if (callbacks->mgmt_frame_rx_callback) {
            mgmt_frame.ap_index = vap->vap_index; 
            memcpy(mgmt_frame.sta_mac, sta, sizeof(mac_address_t));
            mgmt_frame.type = mgmt_type;
            mgmt_frame.dir = dir;
            mgmt_frame.sig_dbm = sig_dbm; 
            mgmt_frame.len = len;
            mgmt_frame.data = (unsigned char *)mgmt; 

#ifdef WIFI_HAL_VERSION_3_PHASE2
        callbacks->mgmt_frame_rx_callback(vap->vap_index, &mgmt_frame);
#else
        callbacks->mgmt_frame_rx_callback(vap->vap_index, sta, (unsigned char *)mgmt, len, mgmt_type, dir);
#endif
    }

    //mgmt_frame_received_callback(vap->vap_index, sta, mgmt, len, mgmt_type, dir);
    {
        union wpa_event_data event;

        os_memset(&event, 0, sizeof(event));
        event.rx_mgmt.frame = (unsigned char *)mgmt;
        event.rx_mgmt.frame_len = len;
        wpa_supplicant_event(&interface->u.ap.hapd, EVENT_RX_MGMT, &event);
    }

    return NL_SKIP;
}

void recv_data_frame(wifi_interface_info_t *interface)
{
    unsigned char buff[2048];
    struct sockaddr saddr;
    int buflen, saddr_len;
    struct ieee8023_hdr *eth_hdr;
    //wifi_direction_t dir;
    wifi_vap_info_t *vap;
    mac_address_t sta;
    union wpa_event_data event;
    struct ieee802_1x_hdr *hdr;
    mac_addr_str_t  frame_sa_str, frame_da_str, interface_mac_str;
    wifi_device_callbacks_t *callbacks;

    callbacks = get_hal_device_callbacks();

    vap = &interface->vap_info;
    saddr_len = sizeof(saddr);
    memset(buff, 0, sizeof(buff));

    //Receive a network packet and copy in to buffer
    buflen = recvfrom((vap->vap_mode == wifi_vap_mode_ap) ? interface->u.ap.br_sock_fd:interface->u.sta.sta_sock_fd,
        buff, sizeof(buff), 0, &saddr, (socklen_t *)&saddr_len);
    //wifi_hal_dbg_print("%s:%d: %s bridge descriptor set, received %d bytes of data\n", __func__, __LINE__, 
        //interface->name, buflen);

    //my_print_hex_dump(buflen, buff);
    eth_hdr = (struct ieee8023_hdr *)buff;

    if (eth_hdr->ethertype != host_to_be16(ETH_P_EAPOL)) {
        return;
    }

    if (memcmp(eth_hdr->dest, interface->mac, sizeof(mac_address_t)) == 0) {
        // received frame
      //  dir = wifi_direction_uplink;  
        memcpy(sta, eth_hdr->src, sizeof(mac_address_t));   
    } else if (memcmp(eth_hdr->src, interface->mac, sizeof(mac_address_t)) == 0) {
        // transmitted frame
      //  dir = wifi_direction_downlink;     
        memcpy(sta, eth_hdr->dest, sizeof(mac_address_t));   
    } else {
        // drop
        to_mac_str(interface->mac, interface_mac_str);
        to_mac_str(eth_hdr->dest, frame_da_str);
        to_mac_str(eth_hdr->src, frame_sa_str);
        if ((callbacks != NULL) && (callbacks->analytics_callback != NULL)) {
            callbacks->analytics_callback("Dropping eapol frame interface:%s frame sa:%s frame da:%s",
                interface_mac_str, frame_sa_str, frame_da_str);
        }
        wifi_hal_info_print("%s:%d: dropping eapol frame\n", __func__, __LINE__);
        return;
    }


    //data_frame_received_callback(vap->vap_index, sta, buff, buflen, WIFI_DATA_FRAME_TYPE_8021x, dir);
        
    hdr = (struct ieee802_1x_hdr *)(buff + sizeof(struct ieee8023_hdr));
    wifi_hal_dbg_print("%s:%d:version:%d type:%d length:%d\n", __func__, __LINE__,
        hdr->version, hdr->type, hdr->length);
    if (vap->vap_mode == wifi_vap_mode_ap) {
        os_memset(&event, 0, sizeof(event));
        event.eapol_rx.src = (unsigned char *)&sta;
        event.eapol_rx.data = (unsigned char *)hdr;
        event.eapol_rx.data_len = buflen - sizeof(struct ieee8023_hdr);
        wpa_supplicant_event(&interface->u.ap.hapd, EVENT_EAPOL_RX, &event);
    } else if (vap->vap_mode == wifi_vap_mode_sta) {
        if (interface->u.sta.wpa_sm) {
            if (!interface->u.sta.wpa_sm->eapol || !eapol_sm_rx_eapol(interface->u.sta.wpa_sm->eapol,(unsigned char *)&sta,
                (unsigned char *)hdr, buflen - sizeof(struct ieee8023_hdr))) {
                wpa_sm_rx_eapol(interface->u.sta.wpa_sm, (unsigned char *)&sta, (unsigned char *)hdr, buflen - sizeof(struct ieee8023_hdr));
            }
        }
        else if (interface->u.sta.state < WPA_ASSOCIATED) {
            interface->u.sta.pending_rx_eapol = true;
            memcpy(interface->u.sta.rx_eapol_buff, buff, sizeof(buff));
            interface->u.sta.buff_len = buflen;
            memcpy(interface->u.sta.src_addr, sta, sizeof(mac_address_t));
        }
    }
}

int parsertattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{

    if ((tb == NULL) && (rta == NULL)) {
        return -1;
    }

    memset(tb, 0 , sizeof(struct rtattr *) * (max + 1));

    while (RTA_OK(rta, len)) {
        if (rta->rta_type <= max) {
            tb[rta->rta_type] = rta;
        }
        rta = RTA_NEXT(rta,len);
    }
    return 0;
}

void process_vapstatus_event(wifi_interface_info_t *interface, bool status)
{

    unsigned int i;
    wifi_device_callbacks_t *callbacks;
    wifi_vapstatus_t vap_status;
    callbacks = get_hal_device_callbacks();

    if (interface == NULL) {
        return;
    }
    
    if (callbacks == NULL) {
        return;
    }

    if(status) {
        vap_status = wifi_vapstatus_up;
    } else {
        vap_status = wifi_vapstatus_down;
    }
    if ((interface != NULL) && (interface->interface_status != status)) {
        interface->interface_status = status;
        for (i = 0; i < callbacks->num_vapstatus_cbs; i++) {
            if ((callbacks->vapstatus_cb[i] != NULL)){
                callbacks->vapstatus_cb[i](interface->vap_info.vap_index,vap_status);
            }
        }
    }
}

void recv_link_status()
{

    struct sockaddr_nl local;
    char buf[8192];
    struct iovec iov;
    iov.iov_base = buf;
    iov.iov_len = sizeof(buf);
    bool status;
    char *ifName=NULL;
    wifi_interface_info_t *interface = NULL;
    wifi_radio_info_t *radio;
    unsigned int i = 0;
    bool found = false;

    memset(&local, 0, sizeof(local));

    local.nl_family = AF_NETLINK;
    local.nl_groups = RTMGRP_LINK;
    local.nl_pid = getpid();

    struct msghdr msg;
    {
        msg.msg_name = &local;
        msg.msg_namelen = sizeof(local);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
    }

    ssize_t recvlen = recvmsg(g_wifi_hal.link_fd, &msg, 0);

    if (recvlen < 0) {
        return;
    }

    struct nlmsghdr *nlmsgHdr;

    for (nlmsgHdr = (struct nlmsghdr *)buf; NLMSG_OK(nlmsgHdr, (unsigned int)recvlen); nlmsgHdr = NLMSG_NEXT(nlmsgHdr, recvlen)) {
        if (nlmsgHdr->nlmsg_type == NLMSG_DONE) {
            return;
        }

        if (nlmsgHdr->nlmsg_type == NLMSG_ERROR) {
            return;
        }

        if ((nlmsgHdr->nlmsg_type == RTM_NEWLINK) || (nlmsgHdr->nlmsg_type == RTM_DELLINK)) {
            struct ifinfomsg *ifi;
            struct rtattr *tb[IFLA_MAX + 1];

            ifi = (struct ifinfomsg*) NLMSG_DATA(nlmsgHdr);

            if (parsertattr(tb, IFLA_MAX, IFLA_RTA(ifi), nlmsgHdr->nlmsg_len) < 0) {
                return;
            }

            if (tb[IFLA_IFNAME]) {
                ifName = (char *)RTA_DATA(tb[IFLA_IFNAME]);
                for (i = 0; ((i < g_wifi_hal.num_radios) && !found) ; i++) {
                    radio = get_radio_by_rdk_index(i); 
                    if (radio == NULL) continue;
                    if (radio->interface_map == NULL) continue;
                    interface = hash_map_get_first(radio->interface_map);
                    while (interface != NULL) {
                        if(strncmp(interface->name, ifName, strlen(interface->name)+1) == 0) {
                            found = true;
                            break;
                        }
                        interface = hash_map_get_next(radio->interface_map, interface);
                    }
                }
            }
            if (!found) {
                return;
            }

            if (ifi->ifi_flags & IFF_UP) {
                status = true;
            } else {
                status = false;
            }

            switch (nlmsgHdr->nlmsg_type) {
            case RTM_NEWLINK:
            case RTM_DELLINK:
                    process_vapstatus_event(interface, status);
                    break;
            }
        }
    }
}

void *nl_recv_func(void *arg)
{
    int ret, res;
    struct timeval tv_towait;
    wifi_hal_priv_t *priv = (wifi_hal_priv_t *)arg;
    wifi_interface_info_t *interface;
    int eloop_timeout_ms;

    while (1) {

        prepare_interface_fdset(priv);

        eloop_timeout_ms = eloop_get_timeout_ms();
        if (eloop_timeout_ms >= 0) {
            tv_towait.tv_sec = (eloop_timeout_ms / 1000);
            tv_towait.tv_usec = (eloop_timeout_ms % 1000) * 1000;
        } else {
            tv_towait.tv_sec = 1;
            tv_towait.tv_usec = 0;
        }

        ret = select(get_biggest_in_fdset(priv) + 1, &priv->drv_rfds, NULL, NULL, &tv_towait);
        if (ret < 0) {
            if ((errno == EINTR) || (errno == EBADF)) {
                continue;
            } else {
                wifi_hal_error_print("%s:%d:select error %d\n", __func__, __LINE__, errno);
                return NULL;
            }
        }

        eloop_timeout_run();

        if (FD_ISSET(priv->nl_event_fd, &priv->drv_rfds)) {
            res = nl_recvmsgs((struct nl_sock *)priv->nl_event, priv->nl_cb);
            if (res < 0) {
                wifi_hal_info_print("%s:%d: %s->nl_recvmsgs failed: %d\n", __func__, __LINE__, __func__, res);
            }
        }

        if (mgmt_fd_isset(priv, &interface)) {
            //wifi_hal_dbg_print("%s:%d:Mgmt frame descriptor is set\n", __func__, __LINE__);
            res = nl_recvmsgs((struct nl_sock *)interface->nl_event, interface->nl_cb);
            if (res < 0) {
                wifi_hal_info_print("%s:%d: %s->nl_recvmsgs failed: %d\n", __func__, __LINE__, __func__, res);
            }
        }

        if (bridge_fd_isset(priv, &interface)) {
            recv_data_frame(interface);
        }

        if (FD_ISSET(priv->link_fd, &priv->drv_rfds)) {
            recv_link_status();
        }

        eloop_sock_table_read_dispatch(&priv->drv_rfds);
    }
    
    return NULL;
}

static int ack_handler(struct nl_msg *msg, void *arg)
{
    int *err = arg;
    *err = 0;
    return NL_STOP;
}

static int finish_handler(struct nl_msg *msg, void *arg)
{
    int *ret = arg;
    *ret = 0; 

    return NL_SKIP;
}

static int cookie_handler(struct nl_msg *msg, void *arg)
{
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    u64 *cookie = arg;
    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
              genlmsg_attrlen(gnlh, 0), NULL);
    if (tb[NL80211_ATTR_COOKIE]) {
        *cookie = nla_get_u64(tb[NL80211_ATTR_COOKIE]);
    }
    return NL_SKIP;
}

static int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err,
             void *arg)
{
    struct nlmsghdr *nlh = (struct nlmsghdr *) err - 1;
    int len = nlh->nlmsg_len;
    struct nlattr *attrs;
    struct nlattr *tb[NLMSGERR_ATTR_MAX + 1];
    int *ret = arg;
    int ack_len = sizeof(*nlh) + sizeof(int) + sizeof(*nlh);

    *ret = err->error;

    if (!(nlh->nlmsg_flags & NLM_F_ACK_TLVS))
        return NL_SKIP;

    if (!(nlh->nlmsg_flags & NLM_F_CAPPED))
        ack_len += err->msg.nlmsg_len - sizeof(*nlh);

    if (len <= ack_len)
        return NL_STOP;

    attrs = (void *) ((unsigned char *) nlh + ack_len);
    len -= ack_len;

    nla_parse(tb, NLMSGERR_ATTR_MAX, attrs, len, NULL);
    if (tb[NLMSGERR_ATTR_MSG]) {
        len = strnlen((char *) nla_data(tb[NLMSGERR_ATTR_MSG]),
                  nla_len(tb[NLMSGERR_ATTR_MSG]));
        wifi_hal_dbg_print("%s:%d: kernel reports: %*s\n", __func__, __LINE__, len, (char *) nla_data(tb[NLMSGERR_ATTR_MSG]));
    }

    return NL_SKIP;
}


static void nl_destroy_handles(struct nl_handle **handle)
{
    if (*handle == NULL)
        return;

    nl_socket_free((struct nl_sock *)*handle);

    *handle = NULL;
}

void nl80211_handle_destroy(struct nl_handle *handle)
{
    uint32_t port = nl_socket_get_local_port((const struct nl_sock *)handle);

    port >>= 22;
    g_wifi_hal.port_bitmap[port / 32] &= ~(1 << (port % 32));

    nl_socket_free((struct nl_sock *)handle);
}

struct nl_handle *nl_create_handle(struct nl_cb *cb, const char *dbg)
{
    struct nl_handle *handle;
    uint32_t pid = getpid() & 0x3FFFFF;
    int i;

    handle = (struct nl_handle *)nl_socket_alloc_cb(cb);
    if (handle == NULL) {
        wifi_hal_error_print("%s:%d: Failed to allocate netlink callbacks (%s)\n", __func__, __LINE__, dbg);
        return NULL;
    }


    for (i = 0; i < 1024; i++) {
        if (g_wifi_hal.port_bitmap[i / 32] & (1 << (i % 32))) {
            continue;
        }
        g_wifi_hal.port_bitmap[i / 32] |= 1 << (i % 32);
        pid += i << 22;
        break;
    }

    nl_socket_set_local_port((struct nl_sock *)handle, pid);


    if (genl_connect((struct nl_sock *)handle)) {
        wifi_hal_error_print("%s:%d: Failed to connect to generic netlink (%s)\n", __func__, __LINE__, dbg);
        nl80211_handle_destroy(handle);
        return NULL;
    }

    return handle;
}

static void nl80211_nlmsg_clear(struct nl_msg *msg)
{
    /*
     * Clear nlmsg data, e.g., to make sure key material is not left in
     * heap memory for unnecessarily long time.
     */
    if (msg) {
        struct nlmsghdr *hdr = nlmsg_hdr(msg);
        void *data = nlmsg_data(hdr);
        /*
         * This would use nlmsg_datalen() or the older nlmsg_len() if
         * only libnl were to maintain a stable API.. Neither will work
         * with all released versions, so just calculate the length
         * here.
         */
        int len = hdr->nlmsg_len - NLMSG_HDRLEN;

        memset(data, 0, len);
    }
}

static int send_and_recv(struct nl_cb *cb_ctx,
             struct nl_handle *nl_handle, struct nl_msg *msg,
             int (*valid_handler)(struct nl_msg *, void *),
             void *valid_data,
             int (*valid_finish_handler)(struct nl_msg *, void *),
             void *valid_finish_data)
{
    struct nl_cb *cb;
    wifi_finish_data_t  *finish_arg;
    int err = -ENOMEM, opt;

    if (!msg)
        return -ENOMEM;

    cb = nl_cb_clone(cb_ctx);
    if (!cb)
        goto out;

    /* try to set NETLINK_EXT_ACK to 1, ignoring errors */
    opt = 1;
    setsockopt(nl_socket_get_fd((const struct nl_sock *)nl_handle), SOL_NETLINK,
           NETLINK_EXT_ACK, &opt, sizeof(opt));

    /* try to set NETLINK_CAP_ACK to 1, ignoring errors */
    opt = 1;
    setsockopt(nl_socket_get_fd((const struct nl_sock *)nl_handle), SOL_NETLINK,
           NETLINK_CAP_ACK, &opt, sizeof(opt));

    err = nl_send_auto_complete((struct nl_sock *)nl_handle, msg);
    if (err < 0)
        goto out;

    err = 1;

    nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &err);
    if ((valid_finish_handler != NULL) && (valid_finish_data != NULL)) {
        finish_arg = (wifi_finish_data_t *)valid_finish_data;
        finish_arg->err = &err;
        nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, valid_finish_handler, valid_finish_data);
    } else {
        nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);
    }
    nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err);

    if (valid_handler) {
        nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, valid_handler, valid_data);
    }

    while (err > 0) {
        int res = nl_recvmsgs((struct nl_sock *)nl_handle, cb);
        if (res < 0) {
            wifi_hal_error_print("%s:%d:%s->nl_recvmsgs failed: %d\n", __func__, __LINE__, __func__, res);
            if (res == -NLE_NOMEM) {
                break;
            }
        }
    }
 out:
    nl_cb_put(cb);
    if (!valid_handler && valid_data == (void *) -1)
        nl80211_nlmsg_clear(msg);
    nlmsg_free(msg);
    return err;
}

static int family_handler(struct nl_msg *msg, void *arg)
{
    struct family_data *res = arg;
    struct nlattr *tb[CTRL_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *mcgrp;
    int i;

    nla_parse(tb, CTRL_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
          genlmsg_attrlen(gnlh, 0), NULL);
    if (!tb[CTRL_ATTR_MCAST_GROUPS])
        return NL_SKIP;

    nla_for_each_nested(mcgrp, tb[CTRL_ATTR_MCAST_GROUPS], i) {
        struct nlattr *tb2[CTRL_ATTR_MCAST_GRP_MAX + 1];
        nla_parse(tb2, CTRL_ATTR_MCAST_GRP_MAX, nla_data(mcgrp),
              nla_len(mcgrp), NULL);
        if (!tb2[CTRL_ATTR_MCAST_GRP_NAME] ||
            !tb2[CTRL_ATTR_MCAST_GRP_ID] ||
            strncmp(nla_data(tb2[CTRL_ATTR_MCAST_GRP_NAME]),
                   res->group,
                   nla_len(tb2[CTRL_ATTR_MCAST_GRP_NAME])) != 0) {
            continue;
        }
        res->id = nla_get_u32(tb2[CTRL_ATTR_MCAST_GRP_ID]);
        break;
    };

    return NL_SKIP;
}

static inline int min_int(int a, int b)
{
    if (a < b) {
        return a;
    }
    return b;
}

static int get_key_handler(struct nl_msg *msg, void *arg)
{
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
                genlmsg_attrlen(gnlh, 0), NULL);

    /*
    * TODO: validate the key index and mac address!
    * Otherwise, there's a race condition as soon as
    * the kernel starts sending key notifications.
    */

    if (tb[NL80211_ATTR_KEY_SEQ]) {
        memcpy(arg, nla_data(tb[NL80211_ATTR_KEY_SEQ]),
           min_int(nla_len(tb[NL80211_ATTR_KEY_SEQ]), 6));
    }
    nl80211_nlmsg_clear(msg);
    return NL_SKIP;
}

static int nl_get_multicast_id(const char *family, const char *group)
{
    struct nl_msg *msg;
    int ret;
    struct family_data res = { group, -ENOENT };

    msg = nlmsg_alloc();
    if (!msg)
        return -ENOMEM;
    if (!genlmsg_put(msg, 0, 0, genl_ctrl_resolve((struct nl_sock *)g_wifi_hal.nl, "nlctrl"),
             0, 0, CTRL_CMD_GETFAMILY, 0) ||
        nla_put_string(msg, CTRL_ATTR_FAMILY_NAME, family)) {
        nlmsg_free(msg);
        return -1;
    }

    ret = send_and_recv(g_wifi_hal.nl_cb, g_wifi_hal.nl, msg, family_handler, &res, NULL, NULL);
    if (ret == 0)
        ret = res.id;
    return ret;
}

struct nl_msg *nl80211_cmd_msg_build(int nl80211_id, wifi_interface_info_t *intf, int flags, uint8_t cmd, struct nl_msg *msg)
{
    if (msg == NULL) {
        return NULL;
    }

    if (genlmsg_put(msg, 0, 0, nl80211_id, 0, flags, cmd, 0) == NULL) {
        nlmsg_free(msg);
        return NULL;
    }

    if (intf != NULL) {
        nla_put_u32(msg, NL80211_ATTR_IFINDEX, intf->index);
        nla_put_u32(msg, NL80211_ATTR_WIPHY, intf->phy_index);
    }

    return msg;
}

struct nl_msg *nl80211_ifindex_msg(int nl80211_id, wifi_interface_info_t *intf, int flags, uint8_t cmd,
    int ifindex)
{
    struct nl_msg *msg;

    msg = nlmsg_alloc();
    if (msg == NULL) {
        return NULL;
    }

    if (genlmsg_put(msg, 0, 0, nl80211_id, 0, flags, cmd, 0) == NULL) {
        nlmsg_free(msg);
        return NULL;
    }

    if (nla_put_u32(msg, NL80211_ATTR_IFINDEX, ifindex) < 0) {
        nlmsg_free(msg);
        return NULL;
    }

    return msg;
}

struct nl_msg *nl80211_drv_cmd_msg(int nl80211_id, wifi_interface_info_t *intf, int flags, uint8_t cmd)
{
    struct nl_msg *msg;

    msg = nlmsg_alloc();
    if (msg == NULL) {
        return NULL;
    }

    if (genlmsg_put(msg, 0, 0, nl80211_id, 0, flags, cmd, 0) == NULL) {
        nlmsg_free(msg);
        return NULL;
    }

    if (intf != NULL) {
        nla_put_u32(msg, NL80211_ATTR_IFINDEX, intf->index);
        nla_put_u32(msg, NL80211_ATTR_WIPHY, intf->phy_index);
    }

    return msg;
}

int get_vap_state(const char *ifname, short *flags)
{
    struct ifreq ifr;
    int fd, res;

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        wifi_hal_error_print("socket error %s\n", strerror(errno));
        return -1;
    }

    res = ioctl(fd, SIOCGIFFLAGS, &ifr);
    close(fd);

    *flags = ifr.ifr_flags;

    return res;
}

#define run_prog(p, ...) ({ \
        int rc = -1, status; \
        pid_t pid = fork(); \
        if (!pid) \
                exit(execlp(p, p, ##__VA_ARGS__, NULL)); \
        if (pid < 0) {\
                rc = -1;\
        } else {\
                while ((rc = waitpid(pid, &status, 0)) == -1 && errno == EINTR); \
                rc = (rc == pid && WIFEXITED(status)) ? WEXITSTATUS(status) : -1; \
        }\
        rc;\
})

static
int ovs_add_br(const char *brname)
{
    wifi_hal_dbg_print("%s:%d ovs-vsctl add-br %s  \n", __func__, __LINE__, brname);
    if (run_prog("/usr/bin/ovs-vsctl", "add-br", brname)) {
        return -1;
    }
    return 0;
}

static
int ovs_br_exists(const char *brname)
{
    char buf[128] = {};
    char *p;
    FILE *f;

    f = popen("/usr/bin/ovs-vsctl list-br", "r");
    while (f && (p = fgets(buf, sizeof(buf), f))) {
        if (!strcmp(strsep(&p, "\n") ?: "", brname)) {
            if (f) pclose(f);
            return 0;
        }
    }

    if (f) pclose(f);
    return -1;
}

static
int ovs_if_get_br(char *brname, const char *ifname)
{
    char cmd[128];
    char *p;
    FILE *f;

    os_snprintf(cmd, sizeof(cmd), "/usr/bin/ovs-vsctl port-to-br %s", ifname);
    f = popen(cmd, "r");
    if (!f) return -1;
    p = fgets(brname, IFNAMSIZ, f);
    pclose(f);
    if (p == NULL || strlen(p) == 0) return -1;
    strsep(&p, "\n"); /* chomp \n */
    return 0;
}

static
int ovs_br_add_if(const char *brname, const char *ifname)
{
	wifi_hal_dbg_print("%s:%d ovs-vsctl add-port %s %s\r \n", __func__, __LINE__, brname, ifname);
    if (run_prog("/usr/bin/ovs-vsctl", "add-port", brname, ifname))
        return -1;
    return 0;
}

static
int ovs_br_del_if(const char *brname, const char *ifname)
{
    wifi_hal_dbg_print("%s:%d ovs-vsctl del-port %s %s\r\n", __func__, __LINE__, brname, ifname);
    if (run_prog("/usr/bin/ovs-vsctl", "del-port", brname, ifname))
        return -1;
    return 0;
}

int nl80211_remove_from_bridge(const char *if_name)
{
    struct nl_sock *sk;
    struct nl_cache *link_cache;
    struct rtnl_link *device;
    char ovs_brname[IFNAMSIZ];

    if (access(OVS_MODULE, F_OK) == 0) {
        if (ovs_if_get_br(ovs_brname, if_name) == 0) {
            wifi_hal_dbg_print("%s:%d delete interface:%s mapping from ovs_brname:%s\n",  __func__, __LINE__, if_name, ovs_brname);
	    if(ovs_br_del_if(ovs_brname, if_name) != 0) {
                wifi_hal_error_print("%s:%d deleting interface:%s on bridge:%s failed\n",  __func__, __LINE__, if_name, ovs_brname);
                return -1;
            }
	}
    }

    sk = nl_socket_alloc();

    if (nl_connect(sk, NETLINK_ROUTE)) {
        wifi_hal_error_print("Unable to connect socket");
        nl_socket_free(sk);
        return -1;
    }

    if (rtnl_link_alloc_cache(sk, AF_UNSPEC, &link_cache)) {
        wifi_hal_error_print("Unable to allocate cache");
        nl_socket_free(sk);
        return -1;
    }

    nl_cache_refill(sk, link_cache);

    device = rtnl_link_get_by_name(link_cache, if_name);

    if (rtnl_link_release(sk, device)) {
        wifi_hal_error_print("%s:%d:Unable to release interface:%s \n", __func__, __LINE__, if_name);
        nl_cache_free(link_cache);
        nl_socket_free(sk);
        return -1;
    }

    rtnl_link_put(device);

    nl_cache_free(link_cache);
    nl_socket_free(sk);

    return 0;
}

int nl80211_create_bridge(const char *if_name, const char *br_name)
{
    struct nl_sock *sk;
    struct nl_cache *link_cache;
    struct rtnl_link *bridge, *device;
    char ovs_brname[IFNAMSIZ];
    bool is_hotspot_interface = false;
    is_hotspot_interface = is_wifi_hal_vap_hotspot_from_interfacename(if_name);

    if (access(OVS_MODULE, F_OK) == 0 && !is_hotspot_interface) {
        if (ovs_if_get_br(ovs_brname, if_name) == 0) {
            if (strcmp(br_name, ovs_brname) != 0) {
                wifi_hal_dbg_print("%s:%d mismatch\n",  __func__, __LINE__);
                if((ovs_br_del_if(ovs_brname, if_name) != 0) || (ovs_br_add_if(br_name, if_name) != 0)) {
                    wifi_hal_error_print("%s:%d adding interface:%s to bridge:%s failed\n",  __func__, __LINE__, if_name, br_name);
                    return -1;
                }
            }
        } else {
            if(ovs_br_exists(br_name) == 0) {
                if (ovs_br_add_if(br_name, if_name) != 0) {
                    wifi_hal_error_print("%s:%d adding interface:%s to bridge:%s failed\n",  __func__, __LINE__, if_name, br_name);
                    return -1;
                }
            } else {
                if (ovs_add_br(br_name) == 0) {
                    if (ovs_br_add_if(br_name, if_name) != 0) {
                        wifi_hal_error_print("%s:%d adding interface:%s to bridge:%s failed\n",  __func__, __LINE__, if_name, br_name);
                        return -1;
                    }
                }
            }
        }
        wifi_hal_dbg_print("%s:%d ovs bridge mapping for bridge:%s, interface:%s is created\n",  __func__, __LINE__, br_name, if_name);
        return 0;
    }

    sk = nl_socket_alloc();

    if (nl_connect(sk, NETLINK_ROUTE)) {
        wifi_hal_error_print("Unable to connect socket");
        nl_socket_free(sk);
        return -1;
    }

    rtnl_link_bridge_add(sk, br_name);

    if (rtnl_link_alloc_cache(sk, AF_UNSPEC, &link_cache)) {
        wifi_hal_error_print("Unable to allocate cache");
        nl_socket_free(sk);
        return -1;
    }

    nl_cache_refill(sk, link_cache);

    bridge = rtnl_link_get_by_name(link_cache, br_name);
    device = rtnl_link_get_by_name(link_cache, if_name);

    if (rtnl_link_enslave(sk, bridge, device)) {
        wifi_hal_error_print("%s:%d:Unable to enslave interface:%s to bridge:%s\n", __func__, __LINE__, if_name, br_name);
        nl_cache_free(link_cache);
        nl_socket_free(sk);
        return -1;
    }

    rtnl_link_put(bridge);
    rtnl_link_put(device);

    nl_cache_free(link_cache);
    nl_socket_free(sk);

    return 0;
}

int nl80211_interface_enable(const char *ifname, bool enable)
{
    struct ifreq ifr;
    int fd, res;
    short flags;

    if (get_vap_state(ifname, &flags) < 0) {
        wifi_hal_error_print("%s:%d could not get state of interface %s\n", __func__, __LINE__, ifname);
        return -1;
    }

    if (enable == true) {
        if (flags & IFF_UP) {
            // already up
            wifi_hal_dbg_print("%s:%d interface %s already up\n", __func__, __LINE__, ifname);
            return 0;
        } else {
            flags |= IFF_UP;
        }
    } else {
        if ((flags | ~IFF_UP) == 0) {
            // already down
            wifi_hal_dbg_print("%s:%d interface %s already down\n", __func__, __LINE__, ifname);
            return 0;
        } else {
            flags &= ~IFF_UP;
        }
    }

    ifr.ifr_flags = flags;
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        wifi_hal_error_print("socket error %s\n", strerror(errno));
        return -1;
    }

    res = ioctl(fd, SIOCSIFFLAGS, &ifr);
    close(fd);

    wifi_hal_dbg_print("Interface %s %s\n", ifname, enable ? "enabled" : "disabled");

    return res;
}

static int phy_info_rates(wifi_radio_info_t *radio, struct hostapd_hw_modes *mode, enum nl80211_band band, struct nlattr *tb)
{
    static struct nla_policy rate_policy[NL80211_BITRATE_ATTR_MAX + 1] = {
        [NL80211_BITRATE_ATTR_RATE] = { .type = NLA_U32 },
        [NL80211_BITRATE_ATTR_2GHZ_SHORTPREAMBLE] =
        { .type = NLA_FLAG },
    };
    struct nlattr *tb_rate[NL80211_BITRATE_ATTR_MAX + 1];
    struct nlattr *nl_rate;
    int rem_rate, idx;

    if (tb == NULL) {
        return NL_OK;
    }

    nla_for_each_nested(nl_rate, tb, rem_rate) {
        nla_parse(tb_rate, NL80211_BITRATE_ATTR_MAX, nla_data(nl_rate), nla_len(nl_rate), rate_policy);
        if (!tb_rate[NL80211_BITRATE_ATTR_RATE])
            continue;
        mode->num_rates++;
    }

    mode->rates = radio->rates[band];

    idx = 0;

    //wifi_hal_dbg_print("%s:%d: band: %d mode:%p number of rates: %d Rates: ", __func__, __LINE__, 
    //    band, mode, mode->num_rates);
    nla_for_each_nested(nl_rate, tb, rem_rate) {
        nla_parse(tb_rate, NL80211_BITRATE_ATTR_MAX, nla_data(nl_rate), nla_len(nl_rate), rate_policy);
        if (!tb_rate[NL80211_BITRATE_ATTR_RATE]) {
            continue;
        }
        mode->rates[idx] = nla_get_u32(tb_rate[NL80211_BITRATE_ATTR_RATE]);
        //wifi_hal_dbg_print("%d ", mode->rates[idx]);
        idx++;
    }

    //wifi_hal_dbg_print("\n");

    return NL_OK;
}


static void phy_info_ht_capa(struct hostapd_hw_modes *mode, struct nlattr *capa,
                 struct nlattr *ampdu_factor,
                 struct nlattr *ampdu_density,
                 struct nlattr *mcs_set)
{
    if (capa)
        mode->ht_capab = nla_get_u16(capa);

    if (ampdu_factor)
        mode->a_mpdu_params |= nla_get_u8(ampdu_factor) & 0x03;

    if (ampdu_density)
        mode->a_mpdu_params |= nla_get_u8(ampdu_density) << 2;

    if (mcs_set && nla_len(mcs_set) >= 16) {
        u8 *mcs;
        mcs = nla_data(mcs_set);
        os_memcpy(mode->mcs_set, mcs, 16);
    }
}


static void phy_info_vht_capa(struct hostapd_hw_modes *mode,
                  struct nlattr *capa,
                  struct nlattr *mcs_set)
{
    if (capa)
        mode->vht_capab = nla_get_u32(capa);

    if (mcs_set && nla_len(mcs_set) >= 8) {
        u8 *mcs;
        mcs = nla_data(mcs_set);
        os_memcpy(mode->vht_mcs_set, mcs, 8);
    }
}

static struct hostapd_hw_modes *phy_info_freqs(wifi_radio_info_t *radio, struct nlattr *tb, enum nl80211_band *nlband)
{
    struct nlattr *tb_freq[NL80211_FREQUENCY_ATTR_MAX + 1];
    struct nlattr *nl_freq;
    int rem_freq;
    wifi_radio_capabilities_t *cap;
    wifi_channels_list_t *channels;
    unsigned int freq = 0, freq_band = 0, i;
    struct hostapd_hw_modes *mode = NULL;
    struct hostapd_channel_data *chan;
    enum nl80211_dfs_state dfs_state;
    enum nl80211_band band;
    static struct nla_policy wmm_policy[NL80211_WMMR_MAX + 1] = {
        [NL80211_WMMR_CW_MIN] = { .type = NLA_U16 },
        [NL80211_WMMR_CW_MAX] = { .type = NLA_U16 },
        [NL80211_WMMR_AIFSN] = { .type = NLA_U8 },
        [NL80211_WMMR_TXOP] = { .type = NLA_U16 },
    };
    struct nlattr *nl_wmm;
    struct nlattr *tb_wmm[NL80211_WMMR_MAX + 1];
    int rem_wmm, ac, count = 0, found = 0;;
    char channel_str[8], channels_str[512] = {};

    nla_for_each_nested(nl_freq, tb, rem_freq) {
        nla_parse(tb_freq, NL80211_FREQUENCY_ATTR_MAX, nla_data(nl_freq), nla_len(nl_freq), NULL);
        if (!tb_freq[NL80211_FREQUENCY_ATTR_FREQ]) {
            continue;
        }

        freq = nla_get_u32(tb_freq[NL80211_FREQUENCY_ATTR_FREQ]);
        if ((freq >= MIN_FREQ_MHZ_2G) && (freq <= MAX_FREQ_MHZ_2G)) {
            freq_band = WIFI_FREQUENCY_2_4_BAND;
            band = NL80211_BAND_2GHZ;
        } else if ((freq >= MIN_FREQ_MHZ_5G) && (freq <= MAX_FREQ_MHZ_5G)) {
            freq_band = WIFI_FREQUENCY_5_BAND;
            band = NL80211_BAND_5GHZ;
        } else if ((freq >= MIN_FREQ_MHZ_6G) && (freq <= MAX_FREQ_MHZ_6G)) {
            freq_band = WIFI_FREQUENCY_6_BAND;
#ifndef LINUX_VM_PORT
            band = NL80211_BAND_6GHZ;
#endif
        } else {
            //wifi_hal_dbg_print("%s:%d: Unknown frequency: %d in attribute of phy index: %d\n", __func__, __LINE__, 
            //    freq_band, radio->index);
            return NULL;
        }

        *nlband = band;

        mode = &radio->hw_modes[band];
        mode->channels = radio->channel_data[band];

        for (i = 0; i < mode->num_channels; i++) {
            if (freq == radio->channel_data[band][i].freq) {
                chan = &radio->channel_data[band][i];
                found = 1;
                break;
            }
        }

        if (!found) {
            chan = &radio->channel_data[band][mode->num_channels];
        }
        memset((unsigned char *)chan, 0, sizeof(struct hostapd_channel_data));
        chan->freq = nla_get_u32(tb_freq[NL80211_FREQUENCY_ATTR_FREQ]);
        chan->flag = 0;
        chan->allowed_bw = ~0;
        chan->dfs_cac_ms = 0;


        ieee80211_freq_to_chan(chan->freq, (u8 *)&chan->chan);

        if (chan->chan == 0) {
            continue;
        }

        if (tb_freq[NL80211_FREQUENCY_ATTR_DISABLED]) {
            chan->flag |= HOSTAPD_CHAN_DISABLED;
        }

        if (tb_freq[NL80211_FREQUENCY_ATTR_NO_IR]) {
            chan->flag |= HOSTAPD_CHAN_NO_IR;
        }

        if (tb_freq[NL80211_FREQUENCY_ATTR_RADAR]) {
            chan->flag |= HOSTAPD_CHAN_RADAR;
        }

        if (tb_freq[NL80211_FREQUENCY_ATTR_INDOOR_ONLY]) {
            chan->flag |= HOSTAPD_CHAN_INDOOR_ONLY;
        }

        if (tb_freq[NL80211_FREQUENCY_ATTR_GO_CONCURRENT]) {
            chan->flag |= HOSTAPD_CHAN_GO_CONCURRENT;
        }

        if (tb_freq[NL80211_FREQUENCY_ATTR_NO_10MHZ]) {
            chan->allowed_bw &= ~HOSTAPD_CHAN_WIDTH_10;
        }

        if (tb_freq[NL80211_FREQUENCY_ATTR_NO_20MHZ]) {
            chan->allowed_bw &= ~HOSTAPD_CHAN_WIDTH_20;
        }

        if (tb_freq[NL80211_FREQUENCY_ATTR_NO_HT40_PLUS]) {
            chan->allowed_bw &= ~HOSTAPD_CHAN_WIDTH_40P;
        }

        if (tb_freq[NL80211_FREQUENCY_ATTR_NO_HT40_MINUS]) {
            chan->allowed_bw &= ~HOSTAPD_CHAN_WIDTH_40M;
        }

        if (tb_freq[NL80211_FREQUENCY_ATTR_NO_80MHZ]) {
            chan->allowed_bw &= ~HOSTAPD_CHAN_WIDTH_80;
        }

        if (tb_freq[NL80211_FREQUENCY_ATTR_NO_160MHZ]) {
            chan->allowed_bw &= ~HOSTAPD_CHAN_WIDTH_160;
        }

        if (tb_freq[NL80211_FREQUENCY_ATTR_DFS_STATE]) {
            dfs_state = nla_get_u32(tb_freq[NL80211_FREQUENCY_ATTR_DFS_STATE]);

            switch (dfs_state) {
                case NL80211_DFS_USABLE:
                    chan->flag |= HOSTAPD_CHAN_DFS_USABLE;
                    break;

                case NL80211_DFS_AVAILABLE:
                    chan->flag |= HOSTAPD_CHAN_DFS_AVAILABLE;
                    break;

                case NL80211_DFS_UNAVAILABLE:
                    chan->flag |= HOSTAPD_CHAN_DFS_UNAVAILABLE;
                    break;
            }
        }

        if (tb_freq[NL80211_FREQUENCY_ATTR_DFS_CAC_TIME]) {
            chan->dfs_cac_ms = nla_get_u32(tb_freq[NL80211_FREQUENCY_ATTR_DFS_CAC_TIME]);
        }
            
        chan->wmm_rules_valid = 0;
    
        if (tb_freq[NL80211_FREQUENCY_ATTR_WMM]) {
            nla_for_each_nested(nl_wmm, tb_freq[NL80211_FREQUENCY_ATTR_WMM], rem_wmm) {
                if (nla_parse_nested(tb_wmm, NL80211_WMMR_MAX, nl_wmm, wmm_policy)) {
                    wifi_hal_info_print("%s:%d:Failed to parse WMM rules attribute\n", __func__, __LINE__);
                    break;
                }

                if (!tb_wmm[NL80211_WMMR_CW_MIN] || !tb_wmm[NL80211_WMMR_CW_MAX] || !tb_wmm[NL80211_WMMR_AIFSN] || !tb_wmm[NL80211_WMMR_TXOP]) {
                    wifi_hal_info_print("%s:%d: Channel is missing WMM rule attribute\n", __func__, __LINE__);
                    break;
                }

                ac = nl_wmm->nla_type;
                if (ac < 0 || ac >= WMM_AC_NUM) {
                    wifi_hal_info_print("%s:%d: Invalid AC value %d", __func__, __LINE__, ac);
                    break;
                }

                chan->wmm_rules[ac].min_cwmin = nla_get_u16(tb_wmm[NL80211_WMMR_CW_MIN]);
                chan->wmm_rules[ac].min_cwmax = nla_get_u16(tb_wmm[NL80211_WMMR_CW_MAX]);
                chan->wmm_rules[ac].min_aifs = nla_get_u8(tb_wmm[NL80211_WMMR_AIFSN]);
                chan->wmm_rules[ac].max_txop = nla_get_u16(tb_wmm[NL80211_WMMR_TXOP]) / 32;
                count++;
            }

            /* Set valid flag if all the AC rules are present */
            if (count == WMM_AC_NUM) {
                chan->wmm_rules_valid = 1;
            }
        }


        if (!found) {
            mode->num_channels++;
        }
        found = 0;
    }

    if (!mode)
        return NULL;
    cap = &radio->capab;
    cap->band[cap->numSupportedFreqBand] = freq_band;
    channels = &cap->channel_list[cap->numSupportedFreqBand];
    channels->num_channels = mode->num_channels;
    chan = mode->channels;

    for (i = 0; i < channels->num_channels; i++) {
        u8 channel = 0;
        ieee80211_freq_to_chan(chan->freq, &channel);
        channels->channels_list[i] = channel;
        snprintf(channel_str, sizeof(channel_str), "%u ", channels->channels_list[i]);
        strcat(channels_str, channel_str);
        chan++;
    }
    wifi_hal_dbg_print("%s:%d: Freq Band: %s for radio: %d num channels: %d channels:\n%s\n",
        __func__, __LINE__, wifi_freq_bands_to_string(freq_band), radio->index,
        mode->num_channels, channels_str);

    return mode;
}

static int phy_info_band(wifi_radio_info_t *radio, struct nlattr *nl_band)
{
    struct nlattr *tb[NL80211_BAND_ATTR_MAX + 1];
    struct nlattr *tb_band[NL80211_BAND_ATTR_MAX + 1];
    struct hostapd_hw_modes *mode = NULL;
    enum nl80211_band band = 0;

    nla_parse(tb, NL80211_BAND_ATTR_MAX, nla_data(nl_band), nla_len(nl_band), NULL);

    if (tb[NL80211_BAND_ATTR_FREQS] == NULL) {
        wifi_hal_dbg_print("%s:%d: Frequency attributes not present\n", __func__, __LINE__);
        return NL_OK;
    }

    // get the hw mode also
    if ((mode = phy_info_freqs(radio, tb[NL80211_BAND_ATTR_FREQS], &band)) == NULL) {
        return NL_OK;
    }

    mode->mode = NUM_HOSTAPD_MODES;
    mode->flags = HOSTAPD_MODE_FLAG_HT_INFO_KNOWN | HOSTAPD_MODE_FLAG_VHT_INFO_KNOWN;
    mode->vht_mcs_set[0] = 0xff;
    mode->vht_mcs_set[1] = 0xff;
    mode->vht_mcs_set[4] = 0xff;
    mode->vht_mcs_set[5] = 0xff;

    nla_parse(tb_band, NL80211_BAND_ATTR_MAX, nla_data(nl_band), nla_len(nl_band), NULL);
    phy_info_ht_capa(mode, tb_band[NL80211_BAND_ATTR_HT_CAPA],
             tb_band[NL80211_BAND_ATTR_HT_AMPDU_FACTOR],
             tb_band[NL80211_BAND_ATTR_HT_AMPDU_DENSITY],
             tb_band[NL80211_BAND_ATTR_HT_MCS_SET]);
    phy_info_vht_capa(mode, tb_band[NL80211_BAND_ATTR_VHT_CAPA],
              tb_band[NL80211_BAND_ATTR_VHT_MCS_SET]);
    phy_info_rates(radio, mode, band, tb_band[NL80211_BAND_ATTR_RATES]);

    return NL_OK;
}

static int phy_info_cipher(wifi_radio_info_t *radio, struct nlattr *nl_cipher)
{
    unsigned int num, i, *cipher;
    
    num = nla_len(nl_cipher)/sizeof(unsigned int);
        
    cipher = nla_data(nl_cipher);
    for (i = 0; i < num; i++) {
        //wifi_hal_dbg_print("%s:%d: supported cipher:%02x-%02x-%02x:%d\n", __func__, __LINE__, 
            //cipher[i] >> 24, (cipher[i] >> 16) & 0xff, 
            //(cipher[i] >> 8) & 0xff, cipher[i] & 0xff);

        switch (cipher[i]) {
        case RSN_CIPHER_SUITE_CCMP_256:
            radio->capab.cipherSupported |= WIFI_CIPHER_CAPA_ENC_CCMP_256;
            break;

        case RSN_CIPHER_SUITE_GCMP_256:
            radio->capab.cipherSupported |= WIFI_CIPHER_CAPA_ENC_GCMP_256;
            break;

        case RSN_CIPHER_SUITE_CCMP:
            radio->capab.cipherSupported |= WIFI_CIPHER_CAPA_ENC_CCMP;
            break;

        case RSN_CIPHER_SUITE_GCMP:
            radio->capab.cipherSupported |= WIFI_CIPHER_CAPA_ENC_GCMP;
            break;

        case RSN_CIPHER_SUITE_TKIP:
            radio->capab.cipherSupported |= WIFI_CIPHER_CAPA_ENC_TKIP;
            break;

        case RSN_CIPHER_SUITE_AES_128_CMAC:
            radio->capab.cipherSupported |= WIFI_CIPHER_CAPA_ENC_BIP;
            break;

        case RSN_CIPHER_SUITE_BIP_GMAC_128:
            radio->capab.cipherSupported |= WIFI_CIPHER_CAPA_ENC_BIP_GMAC_128;
            break;

        case RSN_CIPHER_SUITE_BIP_GMAC_256:
            radio->capab.cipherSupported |= WIFI_CIPHER_CAPA_ENC_BIP_GMAC_256;
            break;

        case RSN_CIPHER_SUITE_BIP_CMAC_256:
            radio->capab.cipherSupported |= WIFI_CIPHER_CAPA_ENC_BIP_CMAC_256;
            break;

        case RSN_CIPHER_SUITE_NO_GROUP_ADDRESSED:
            radio->capab.cipherSupported |= WIFI_CIPHER_CAPA_ENC_GTK_NOT_USED;
            break;

        }
    }

    return NL_OK;
}

static int wiphy_set_info_handler(struct nl_msg *msg, void *arg)
{
    return 0;
}

static int regulatory_domain_set_info_handler(struct nl_msg *msg, void *arg)
{
    return 0;
}

static int wiphy_dump_handler(struct nl_msg *msg, void *arg)
{
    wifi_radio_info_t *radio;
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh;
    //unsigned int *cmd;
    struct nlattr *nl_cmd;
    unsigned int i, j, phy_index;
    int rdk_radio_index;

    if (g_wifi_hal.num_radios >= MAX_NUM_RADIOS) {
        return NL_SKIP;
    }

    gnlh = nlmsg_data(nlmsg_hdr(msg));

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

    for (j = 0; j < g_wifi_hal.num_radios; j++)
    {
        if (strcmp(g_wifi_hal.radio_info[j].name, nla_get_string(tb[NL80211_ATTR_WIPHY_NAME])) == 0) {
            return NL_SKIP;
        }
    }

    phy_index = nla_get_u32(tb[NL80211_ATTR_WIPHY]);
    rdk_radio_index = get_rdk_radio_index(phy_index);

    if ( rdk_radio_index == -1 ) { 
        wifi_hal_error_print("%s:%d: Skipping for phy_index = %u, "
                   "since it is not present in the interface table\n",
                   __func__,__LINE__, phy_index);
        return NL_SKIP;
    }

    //print_attributes(__func__, tb);
    radio = &g_wifi_hal.radio_info[g_wifi_hal.num_radios];
    memset((unsigned char *)radio, 0, sizeof(wifi_radio_info_t));

    //radio->supported_cmds = queue_create();

    if (tb[NL80211_ATTR_SUPPORTED_COMMANDS]) {
        //print_supported_commands(__func__, tb[NL80211_ATTR_SUPPORTED_COMMANDS]); 
        nla_for_each_nested(nl_cmd, tb[NL80211_ATTR_SUPPORTED_COMMANDS], i) {
            //cmd = malloc(sizeof(unsigned int));
            //memcpy(cmd, nla_get_u32(nl_cmd), sizeof(unsigned int));
            //queue_push(radio->supported_cmds, cmd); 
        }
    }

    if (tb[NL80211_ATTR_WIPHY]) {
        radio->index = phy_index;
        radio->rdk_radio_index = rdk_radio_index;
        radio->capab.index = radio->index;
    }

    if (tb[NL80211_ATTR_WIPHY_NAME]) {
        strcpy(radio->name, nla_get_string(tb[NL80211_ATTR_WIPHY_NAME]));
    }

    if (tb[NL80211_ATTR_WDEV]) {
        radio->dev_id = nla_get_u64(tb[NL80211_ATTR_WDEV]);
    }
        
    g_wifi_hal.num_radios++;

    return NL_SKIP;

}

static int wiphy_get_info_handler(struct nl_msg *msg, void *arg)
{
    wifi_radio_info_t *radio;
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh;
    struct nlattr *nl_band;//, *nl_cmd;
    struct nlattr *nl_combi;
    struct nlattr *tb_comb[NUM_NL80211_IFACE_COMB];
    int rem_combi;
    int rem_band;
    gnlh = nlmsg_data(nlmsg_hdr(msg));
    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);
    if (tb[NL80211_ATTR_WIPHY]) {
        radio = get_radio_by_phy_index(nla_get_u32(tb[NL80211_ATTR_WIPHY]));
    } else {
        return NL_OK;
    }
    //wifi_hal_dbg_print("%s:%d: wiphy index:%d name:%s\n", __func__, __LINE__, radio->index, radio->name);
    radio->capab.cipherSupported = 0;
    if (tb[NL80211_ATTR_CIPHER_SUITES]) {
        phy_info_cipher(radio, tb[NL80211_ATTR_CIPHER_SUITES]);
    }
    radio->capab.numSupportedFreqBand = 0;
    memset((unsigned char *)radio->hw_modes, 0, NUM_NL80211_BANDS*sizeof(struct hostapd_hw_modes));
    if (tb[NL80211_ATTR_WIPHY_BANDS] != NULL) {
        nla_for_each_nested(nl_band, tb[NL80211_ATTR_WIPHY_BANDS], rem_band) {
            phy_info_band(radio, nl_band);
            radio->capab.numSupportedFreqBand++;
        }
    } else {
        wifi_hal_info_print("%s:%d: Bands attribute not present in radio index:%d\n", __func__, __LINE__, radio->index);
    }
    if (tb[NL80211_ATTR_INTERFACE_COMBINATIONS]) {
        nla_for_each_nested(nl_combi, tb[NL80211_ATTR_INTERFACE_COMBINATIONS], rem_combi) {
            static struct nla_policy iface_combination_policy[NUM_NL80211_IFACE_COMB] = {
              [NL80211_IFACE_COMB_LIMITS] = { .type = NLA_NESTED },
              [NL80211_IFACE_COMB_MAXNUM] = { .type = NLA_U32 },
              [NL80211_IFACE_COMB_STA_AP_BI_MATCH] = { .type = NLA_FLAG },
              [NL80211_IFACE_COMB_NUM_CHANNELS] = { .type = NLA_U32 },
              [NL80211_IFACE_COMB_RADAR_DETECT_WIDTHS] = { .type = NLA_U32 },
            };
            if ((nla_parse_nested(tb_comb, MAX_NL80211_IFACE_COMB, nl_combi, iface_combination_policy) != 0 ) || !tb_comb[NL80211_IFACE_COMB_MAXNUM])
                wifi_hal_info_print("%s:%d: Failed to parse interface combinations for radio index:%d\n", __func__, __LINE__, radio->index);
            else {
                radio->capab.maxNumberVAPs = nla_get_u32(tb_comb[NL80211_IFACE_COMB_MAXNUM]);
                //wifi_hal_dbg_print("%s:%d: Total number of interfaces for radio index:%d -> %d\n", __func__, __LINE__, radio->index, nla_get_u32(tb_comb[NL80211_IFACE_COMB_MAXNUM]));
            }
        }
    } else {
        wifi_hal_info_print("%s:%d: Interface combinations attribute not present in radio index:%d\n", __func__, __LINE__, radio->index);
    }
    return NL_OK;
}

static int interface_del_handler(struct nl_msg *msg, void *arg)
{
    return NL_SKIP;
}

static int mgmt_frame_register_handler(struct nl_msg *msg, void *arg)
{
    wifi_hal_dbg_print("%s:%d:Enter\n", __func__, __LINE__);

    return NL_SKIP;
}

static int interface_set_mtu(wifi_interface_info_t *interface, int mtu)
{
    int ret, nl_sock;
    struct rtattr  *rta;
    struct {
        struct nlmsghdr nh;
        struct ifinfomsg  ifinfo;
        char   attrbuf[512];
    } req;

    nl_sock = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);

    if (nl_sock < 0) {
        wifi_hal_error_print("%s:%d Failed to open socket\n", __func__, __LINE__);
        return -1;
    }

    memset(&req, 0, sizeof(req));
    req.nh.nlmsg_len   = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    req.nh.nlmsg_flags = NLM_F_REQUEST;
    req.nh.nlmsg_type  = RTM_NEWLINK;
    req.ifinfo.ifi_family = AF_UNSPEC;
    req.ifinfo.ifi_index  = if_nametoindex(interface->name);

    if (!req.ifinfo.ifi_index) {
        wifi_hal_error_print("%s:%d Failed to get ifindex for %s\n", __func__, __LINE__, interface->name);
        close(nl_sock);
        return -1;
    }

    req.ifinfo.ifi_change = 0xffffffff;
    rta = (struct rtattr *)(((char *) &req) + NLMSG_ALIGN(req.nh.nlmsg_len));
    rta->rta_type = IFLA_MTU;
    rta->rta_len = RTA_LENGTH(sizeof(unsigned int));
    req.nh.nlmsg_len = NLMSG_ALIGN(req.nh.nlmsg_len) + RTA_LENGTH(sizeof(mtu));
    memcpy(RTA_DATA(rta), &mtu, sizeof(mtu));

    ret = send(nl_sock, &req, req.nh.nlmsg_len, 0);

    if (ret < 0) {
        wifi_hal_error_print("%s:%d Failed to set MTU for %s\n", __func__, __LINE__, interface->name);
        close(nl_sock);
        return -1;
    }

    close(nl_sock);
    return 0;
}

static int interface_info_handler(struct nl_msg *msg, void *arg)
{
    //unsigned int radio_index;
    wifi_radio_info_t *radio;
    wifi_interface_info_t *interface = NULL;
    wifi_vap_info_t *vap;
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh;
    
    gnlh = nlmsg_data(nlmsg_hdr(msg));
    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

    //print_attributes(__func__, tb);
    if (tb[NL80211_ATTR_WIPHY]) {
        radio = get_radio_by_phy_index(nla_get_u32(tb[NL80211_ATTR_WIPHY]));
        
        if (radio != NULL && tb[NL80211_ATTR_IFNAME]) {
            interface = hash_map_get_first(radio->interface_map);
            while (interface != NULL) {
                if (strcmp(interface->name, nla_get_string(tb[NL80211_ATTR_IFNAME])) == 0) {
                    break;
                }
                interface = hash_map_get_next(radio->interface_map, interface);
            }
            if (interface == NULL) {
                interface = (wifi_interface_info_t *)malloc(sizeof(wifi_interface_info_t));
                memset(interface, 0, sizeof(wifi_interface_info_t));
            }
            else {
                hash_map_remove(radio->interface_map, interface->name);
            }
            interface->phy_index = radio->index;        

            vap = &interface->vap_info;

            if (tb[NL80211_ATTR_IFINDEX]) {
                interface->index = nla_get_u32(tb[NL80211_ATTR_IFINDEX]);
            }
            
            if (tb[NL80211_ATTR_IFTYPE]) {
                interface->type = nla_get_u32(tb[NL80211_ATTR_IFTYPE]);
            }
    
            if (tb[NL80211_ATTR_IFNAME]) {
                strcpy(interface->name, nla_get_string(tb[NL80211_ATTR_IFNAME]));
            }
            
            if (tb[NL80211_ATTR_MAC]) {
                memcpy(interface->mac, nla_data(tb[NL80211_ATTR_MAC]), nla_len(tb[NL80211_ATTR_MAC]));
            }
    
    
            if (set_interface_properties(nla_get_u32(tb[NL80211_ATTR_WIPHY]), interface) != 0) {
                wifi_hal_info_print("%s:%d: Could not map interface name to index:%d\n", __func__, __LINE__, nla_get_u32(tb[NL80211_ATTR_WIPHY]));
                free(interface);
                return NL_SKIP;
            }

            wifi_hal_dbg_print("%s:%d: phy index: %d\tradio index: %d\tinterface index: %d\nname: %s\ttype:%d, mac:%02x:%02x:%02x:%02x:%02x:%02x\nvap index: %d\tvap name: %s\n", 
                    __func__, __LINE__, 
                    radio->index, vap->radio_index, interface->index, interface->name, interface->type,
                    interface->mac[0], interface->mac[1], interface->mac[2],
                    interface->mac[3], interface->mac[4], interface->mac[5],
                    vap->vap_index, vap->vap_name);

            hash_map_put(radio->interface_map, strdup(interface->name), interface);

            if (is_backhaul_interface(interface)) {
                interface_set_mtu(interface, 1600);
            }
        }
    }

    return NL_SKIP;
}

static int phy_info_handler(struct nl_msg *msg, void *arg)
{
    wifi_radio_info_t *radio;
    struct nlattr *tb_msg[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *nl_band;
    int rem_band;
    enum nl80211_band band = 0;

    nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
        genlmsg_attrlen(gnlh, 0), NULL);

    if (tb_msg[NL80211_ATTR_WIPHY]) {
        radio = get_radio_by_phy_index(nla_get_u32(tb_msg[NL80211_ATTR_WIPHY]));
        if (radio == NULL) {
            return NL_SKIP;
        }
    } else {
        return NL_OK;
    }

    wifi_hal_dbg_print("%s:%d: wiphy index:%d name:%s\n", __func__, __LINE__, radio->index, radio->name);
    if (!tb_msg[NL80211_ATTR_WIPHY_BANDS])
        return NL_SKIP;

    nla_for_each_nested(nl_band, tb_msg[NL80211_ATTR_WIPHY_BANDS], rem_band) {
        nla_parse(tb_msg, NL80211_BAND_ATTR_MAX, nla_data(nl_band), nla_len(nl_band), NULL);

        if (tb_msg[NL80211_BAND_ATTR_FREQS] == NULL) {
            wifi_hal_dbg_print("%s:%d: Frequency attributes not present\n", __func__, __LINE__);
            return NL_OK;
        }

        if (phy_info_freqs(radio, tb_msg[NL80211_BAND_ATTR_FREQS], &band) == NULL) {
            return NL_OK;
        }
    }

    return NL_SKIP;
}

static int kick_device_handler(struct nl_msg *msg, void *arg)
{
    return NL_SKIP;
}

static int get_sta_handler(struct nl_msg *msg, void *arg)
{
    wifi_interface_info_t *interface;
    wifi_vap_info_t *vap;
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct nlattr *nl;
    struct nlattr *stats[NL80211_STA_INFO_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    static struct nla_policy stats_policy[NL80211_STA_INFO_MAX + 1] = {
        [NL80211_STA_INFO_CHAIN_SIGNAL] = { .type = NLA_NESTED },
    };
    int rem, signals_cnt = 0;
    int8_t rssi = 0;
    mac_address_t sta_mac;
    mac_addr_str_t sta_mac_str;
    wifi_device_callbacks_t *callbacks;
    wifi_associated_dev_t associated_dev;

    interface = (wifi_interface_info_t *)arg;
    vap = &interface->vap_info;

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
        genlmsg_attrlen(gnlh, 0), NULL);

    if (!tb[NL80211_ATTR_IFINDEX]) {
        wifi_hal_error_print("%s:%d: Interface index missing\n", __func__, __LINE__);
        return NL_SKIP;
    }

    if (interface->index != nla_get_u32(tb[NL80211_ATTR_IFINDEX])) {
        wifi_hal_error_print("%s:%d: Wrong interface index\n", __func__, __LINE__);
        return NL_SKIP;
    }

    if (!tb[NL80211_ATTR_MAC]) {
        wifi_hal_error_print("%s:%d: MAC addr missing!", __func__, __LINE__);
        return NL_SKIP;
    }

    memcpy(sta_mac, nla_data(tb[NL80211_ATTR_MAC]), nla_len(tb[NL80211_ATTR_MAC]));

    if (!tb[NL80211_ATTR_STA_INFO]) {
        wifi_hal_info_print("%s:%d: STA stats missing\n", __func__, __LINE__);
        return NL_SKIP;
    }

    wifi_hal_dbg_print("%s:%d: Received stats for %s\n", __func__, __LINE__, to_mac_str(sta_mac, sta_mac_str));

    if (nla_parse_nested(stats, NL80211_STA_INFO_MAX, tb[NL80211_ATTR_STA_INFO], stats_policy)) {
        wifi_hal_info_print("%s:%d: Failed to parse nested attributes\n", __func__, __LINE__);
        return NL_SKIP;
    }

    if (stats[NL80211_STA_INFO_CHAIN_SIGNAL]) {
        nla_for_each_nested(nl, stats[NL80211_STA_INFO_CHAIN_SIGNAL], rem) {
            rssi = (int8_t)nla_get_u8(nl);
            signals_cnt++;
        }
    }

    if (signals_cnt != 0)
        rssi = rssi/signals_cnt;

    wifi_hal_dbg_print("%s:%d: RSSI %d\n", __func__, __LINE__, rssi);

    callbacks = get_hal_device_callbacks();
    if (callbacks->num_assoc_cbs == 0) {
        return NL_SKIP;
    }

    memset(&associated_dev, 0, sizeof(associated_dev));
    memcpy(associated_dev.cli_MACAddress, &sta_mac, sizeof(mac_address_t));
    associated_dev.cli_RSSI = rssi;
    associated_dev.cli_Active = true;

    for (int i = 0; i < callbacks->num_assoc_cbs; i++) {
        if (callbacks->assoc_cb[i] != NULL) {
            callbacks->assoc_cb[i](vap->vap_index, &associated_dev);
        }
    }

    return NL_SKIP;
}

int nl80211_kick_device(wifi_interface_info_t *interface, mac_address_t addr)
{
    struct nl_msg *msg;

    msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, NL80211_CMD_DEL_STATION);
    if (msg == NULL) {
        return -1;
    }

    nla_put(msg, NL80211_ATTR_MAC, sizeof(mac_address_t), addr);

    if (send_and_recv(g_wifi_hal.nl_cb, g_wifi_hal.nl, msg, kick_device_handler, interface, NULL, NULL)) {
        wifi_hal_error_print("%s:%d: Error getting sta info\n", __func__, __LINE__);
        return -1;
    }

    return 0;
}

int nl80211_read_sta_data(wifi_interface_info_t *interface, const u8 *addr)
{
    struct nl_msg *msg;

    msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, NL80211_CMD_GET_STATION);
    if (msg == NULL) {
        return -1;
    }

    nla_put(msg, NL80211_ATTR_MAC, ETH_ALEN, addr);

    if (send_and_recv(g_wifi_hal.nl_cb, g_wifi_hal.nl, msg, get_sta_handler, interface, NULL, NULL)) {
        wifi_hal_error_print("%s:%d: Error getting sta info\n", __func__, __LINE__);
        return -1;
    }

    return 0;
}

int update_channel_flags()
{
    struct nl_msg *msg;

    msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, NULL, NLM_F_DUMP, NL80211_CMD_GET_WIPHY);
    nla_put_flag(msg, NL80211_ATTR_SPLIT_WIPHY_DUMP);
    if (msg == NULL) {
        nlmsg_free(msg);
        return -1;
    }

    if (send_and_recv(g_wifi_hal.nl_cb, g_wifi_hal.nl, msg, phy_info_handler, &g_wifi_hal, NULL, NULL)) {
        return -1;
    }

    return 0;
}

int init_nl80211()
{
    int ret;
    unsigned int i;
    struct nl_msg *msg;
    wifi_radio_info_t *radio;

    g_wifi_hal.nl_cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (g_wifi_hal.nl_cb == NULL) {
        wifi_hal_error_print("%s:%d: Failed to allocate netlink callbacks\n", __func__, __LINE__);
        return -1;
    }

    g_wifi_hal.nl = nl_create_handle(g_wifi_hal.nl_cb, "nl");
    if (g_wifi_hal.nl == NULL) {
        nl_cb_put(g_wifi_hal.nl_cb);
        return -1;
    }

    g_wifi_hal.nl80211_id = genl_ctrl_resolve((struct nl_sock *)g_wifi_hal.nl, "nl80211");
    if (g_wifi_hal.nl80211_id < 0) {
        wifi_hal_error_print("%s:%d: generic netlink not found\n", __func__, __LINE__);
        nl_cb_put(g_wifi_hal.nl_cb);
        return -1;
    }

    g_wifi_hal.nl_event = nl_create_handle(g_wifi_hal.nl_cb, "event");
    if (g_wifi_hal.nl_event == NULL) {
        nl_cb_put(g_wifi_hal.nl_cb);
        return -1;
    }


    ret = nl_get_multicast_id("nl80211", "scan");
    if (ret >= 0) {
        ret = nl_socket_add_membership((struct nl_sock *)g_wifi_hal.nl_event, ret);
    }

    if (ret < 0) {
        wifi_hal_error_print("%s:%d: Could not add multicast membership for scan events: %d (%s)\n", __func__, __LINE__,           
               ret, strerror(-ret));
        nl_destroy_handles(&g_wifi_hal.nl);
        nl_cb_put(g_wifi_hal.nl_cb);
        return -1;
    }

    ret = nl_get_multicast_id("nl80211", "mlme");
    if (ret >= 0) {
        ret = nl_socket_add_membership((struct nl_sock *)g_wifi_hal.nl_event, ret);
    }

    if (ret < 0) {
        wifi_hal_error_print("%s:%d: Could not add multicast membership for mlme events: %d (%s)\n", __func__, __LINE__,
               ret, strerror(-ret));
        nl_destroy_handles(&g_wifi_hal.nl);
        nl_cb_put(g_wifi_hal.nl_cb);
        return -1;
    }

    ret = nl_get_multicast_id("nl80211", "regulatory");
    if (ret >= 0) {
        ret = nl_socket_add_membership((struct nl_sock *)g_wifi_hal.nl_event, ret);
    }

    if (ret < 0) {
        wifi_hal_info_print("%s:%d: Could not add multicast membership for regulatory events: %d (%s)\n", 
                __func__, __LINE__, ret, strerror(-ret));
    }

    ret = nl_get_multicast_id("nl80211", "vendor");
    if (ret >= 0) {
        ret = nl_socket_add_membership((struct nl_sock *)g_wifi_hal.nl_event, ret);
    }

    if (ret < 0) {
        wifi_hal_info_print("%s:%d: Could not add multicast membership for vendor events: %d (%s)\n", 
                __func__, __LINE__, ret, strerror(-ret));
    }

    nl_cb_set(g_wifi_hal.nl_cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, no_seq_check, NULL);
    nl_cb_set(g_wifi_hal.nl_cb, NL_CB_VALID, NL_CB_CUSTOM, process_global_nl80211_event, &g_wifi_hal);


    g_wifi_hal.nl_event_fd = nl_socket_get_fd((struct nl_sock *)g_wifi_hal.nl_event);

    // dump all phy info
    g_wifi_hal.num_radios = 0;
    memset((unsigned char *)g_wifi_hal.radio_info, 0, MAX_NUM_RADIOS*sizeof(wifi_radio_info_t));

    msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, NULL, NLM_F_DUMP, NL80211_CMD_GET_WIPHY);
    if (msg == NULL) {
        nlmsg_free(msg);
        return -1;
    }

    if (send_and_recv(g_wifi_hal.nl_cb, g_wifi_hal.nl, msg, wiphy_dump_handler, &g_wifi_hal, NULL, NULL)) {
        return -1;
    }

    //wifi_hal_dbg_print("%s:%d: Number of radios: %d\n", __func__, __LINE__, g_wifi_hal.num_radios);

    g_wifi_hal.link_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (g_wifi_hal.link_fd  > 0) {
        struct sockaddr_nl local;
        memset(&local, 0, sizeof(local));
        local.nl_family = AF_NETLINK;
        local.nl_groups = RTMGRP_LINK;
        local.nl_pid = getpid();

        if (bind(g_wifi_hal.link_fd, (struct sockaddr*)&local, sizeof(local)) <0) {
            wifi_hal_error_print("%s:%d: Socket bind failed \n", __func__, __LINE__);
            close(g_wifi_hal.link_fd);
            return -1;
        }
    } else {
        wifi_hal_error_print("%s:%d: socket creation failed for link_fd\n", __func__, __LINE__);
        return -1;
    }

    for (i = 0; i < g_wifi_hal.num_radios; i++) {
        radio = &g_wifi_hal.radio_info[i];

        // initialize the interface map
        radio->interface_map = hash_map_create();

        // get the interface information
        msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, NULL, NLM_F_DUMP, NL80211_CMD_GET_INTERFACE);
        if (msg == NULL) {
            return -1;
        }
        nla_put_u32(msg, NL80211_ATTR_WIPHY, radio->index);
    
        if (send_and_recv(g_wifi_hal.nl_cb, g_wifi_hal.nl, msg, interface_info_handler, &g_wifi_hal, NULL, NULL)) {
            return -1;
        }

        //wifi_hal_dbg_print("%s:%d: Found %d interfaces on radio index:%d\n", __func__, __LINE__, 
        //    hash_map_count(radio->interface_map), radio->index);
    }

    return 0;

}

static int ap_enable_handler(struct nl_msg *msg, void *arg)
{
    return NL_SKIP;
}

void wifi_hal_nl80211_wps_pbc(unsigned int ap_index)
{
    union wpa_event_data event;
    wifi_interface_info_t *interface;

    interface = get_interface_by_vap_index(ap_index);

    if (interface->u.ap.conf.wps_state == 0) {
        wifi_hal_error_print("%s:%d: WPS is not enabled for interface %s\n", __func__, __LINE__, interface->name);
        return;
    }

    os_memset(&event, 0, sizeof(event));
    wpa_supplicant_event(&interface->u.ap.hapd, EVENT_WPS_BUTTON_PUSHED, &event);
}

int nl80211_enable_ap(wifi_interface_info_t *interface, bool enable)
{
    struct nl_msg *msg;
    int ret;

    if (enable) {
        ieee802_11_update_beacons(interface->u.ap.hapd.iface);
        return RETURN_OK;
    } else {
        interface->beacon_set = 0;
        msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, NULL, 0, NL80211_CMD_STOP_AP);
    }

    if (msg == NULL) {
        return -1;
    }


    if (nla_put_u32(msg, NL80211_ATTR_IFINDEX, interface->index) < 0) {
        nlmsg_free(msg);
        return -1;
    }


    wifi_hal_dbg_print("%s:%d: %s ap on interface: %d\n", __func__, __LINE__,
        enable ? "Starting" : "Stopping", interface->index);
    if ((ret = send_and_recv(g_wifi_hal.nl_cb, g_wifi_hal.nl, msg, ap_enable_handler, &g_wifi_hal, NULL, NULL))) {
        wifi_hal_error_print("%s:%d: Error stopping/starting ap: %s\n", __func__, __LINE__, strerror(-ret));
        return RETURN_ERR;
    }

    return RETURN_OK;
}

int nl80211_delete_interface(wifi_radio_info_t *radio, wifi_interface_info_t *interface)
{
    struct nl_msg *msg;
    int ret;

#if 0
    msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, NL80211_CMD_STOP_AP);
    if (msg == NULL) {
        return -1;
    }
        
    wifi_hal_dbg_print("%s:%d: Sopping ap on interface: %d\n", __func__, __LINE__, interface->index);
    if ((ret = send_and_recv(g_wifi_hal.nl_cb, g_wifi_hal.nl, msg, ap_stop_handler, &g_wifi_hal, NULL, NULL))) {
        wifi_hal_dbg_print("%s:%d: Error stopping ap: %s\n", __func__, __LINE__, strerror(-ret));
    }
#endif
        

    msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, NULL, 0, NL80211_CMD_DEL_INTERFACE);
    if (msg == NULL) {
        return -1;
    }
    if (nla_put_u32(msg, NL80211_ATTR_IFINDEX, interface->index) < 0) {
        nlmsg_free(msg);
        return -1;
    }

    wifi_hal_dbg_print("%s:%d: Deleting interface:%s (%d) on radio:%d\n", __func__, __LINE__,
            interface->name, interface->index, radio->index);

    if ((ret = send_and_recv(g_wifi_hal.nl_cb, g_wifi_hal.nl, msg, interface_del_handler, &g_wifi_hal, NULL, NULL))) {
        wifi_hal_dbg_print("%s:%d: Error in deleting interface: %s\n", __func__, __LINE__, strerror(-ret));
        return -1;
    }

    hash_map_remove(radio->interface_map, interface->name);
    free(interface);

    return 0;
}

int nl80211_delete_interfaces(wifi_radio_info_t *radio)
{
    wifi_interface_info_t *interface, *tmp;

    // now delete all interfaces on radios so that we are ready for rdkb
    interface = hash_map_get_first(radio->interface_map);

    while (interface != NULL) {
        tmp = interface;
        interface = hash_map_get_next(radio->interface_map, interface);

        nl80211_delete_interface(radio, tmp);
    }

    return 0;    
}

int nl80211_init_primary_interfaces()
{
    unsigned int i, ret;
    struct nl_msg *msg;
    wifi_radio_info_t *radio;
    wifi_interface_info_t *primary_interface;
    wifi_interface_info_t *interface;

    for (i = 0; i < g_wifi_hal.num_radios; i++) {
        radio = get_radio_by_rdk_index(i);

        primary_interface = get_primary_interface(radio);
        if (primary_interface == NULL) {
            wifi_hal_error_print("%s:%d: Error updating dev:%d no primary interfaces exist\n", __func__, __LINE__, radio->index);
            return -1;
        }
        nl80211_interface_enable(primary_interface->name, true);

        interface = get_private_vap_interface(radio);
        if (interface == NULL) {
            wifi_hal_error_print("%s:%d: Error updating dev:%d no private vap interfaces exist\n", __func__, __LINE__, radio->index);
            return -1;
        }

        msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, NL80211_CMD_SET_INTERFACE);
        if (msg == NULL) {
            return -1;
        }

        nla_put_u32(msg, NL80211_ATTR_IFTYPE, NL80211_IFTYPE_AP);

        if ((ret = send_and_recv(g_wifi_hal.nl_cb, g_wifi_hal.nl, msg, interface_info_handler, &g_wifi_hal, NULL, NULL))) {
            wifi_hal_error_print("%s:%d: Error updating %s interface on dev:%d error: %s\n",
                __func__, __LINE__, interface->name, radio->index, strerror(-ret));
            return -1;
        }
    }

    return 0;
}

int nl80211_init_radio_info()
{
    unsigned int i;
    wifi_radio_info_t *radio;
    struct nl_msg *msg;

    for (i = 0; i < g_wifi_hal.num_radios; i++) {
        radio = &g_wifi_hal.radio_info[i];

        // get information about phy
        msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, NULL, 0, NL80211_CMD_GET_WIPHY);
        if (msg == NULL) {
            wifi_hal_dbg_print("%s:%d: Error creating nl80211 message\n", __func__, __LINE__);
            nlmsg_free(msg);
            return -1;
        }

        if (nla_put_u32(msg, NL80211_ATTR_WIPHY, radio->index) < 0) {
            wifi_hal_dbg_print("%s:%d: Error adding nl80211 message data\n", __func__, __LINE__);
            nlmsg_free(msg);
            return -1;
        }

        if (send_and_recv(g_wifi_hal.nl_cb, g_wifi_hal.nl, msg, wiphy_get_info_handler,
            &g_wifi_hal, NULL, NULL)) {
            return -1;
        }
    }

    return 0;
}

static int get_sec_channel_offset(wifi_radio_info_t *radio, int freq)
{
    int i;
    enum nl80211_band band;

    if ((freq >= MIN_FREQ_MHZ_2G) && (freq <= MAX_FREQ_MHZ_2G)) {
        band = NL80211_BAND_2GHZ;
    } else if ((freq >= MIN_FREQ_MHZ_5G) && (freq <= MAX_FREQ_MHZ_5G)) {
        band = NL80211_BAND_5GHZ;
    } else if ((freq >= MIN_FREQ_MHZ_6G) && (freq <= MAX_FREQ_MHZ_6G)) {
#ifndef LINUX_VM_PORT
        band = NL80211_BAND_6GHZ;
#endif
    } else {
        wifi_hal_info_print("%s:%d: Unknown frequency: %d in attribute of phy index: %d\n", __func__, __LINE__, 
            freq, radio->index);
        return 0;
    }

    for (i = 0; i < radio->hw_modes[band].num_channels; i++) {
        if (freq == radio->channel_data[band][i].freq) {
            if (radio->channel_data[band][i].allowed_bw & HOSTAPD_CHAN_WIDTH_40P)
                return 1;
            if (radio->channel_data[band][i].allowed_bw & HOSTAPD_CHAN_WIDTH_40M)
                return -1;
        }
    }

    return 0;
}

static int set_beacon_data(struct nl_msg *msg, struct beacon_data *settings)
{
    if ((settings->head && nla_put(msg, NL80211_ATTR_BEACON_HEAD,
        settings->head_len, settings->head)) || (settings->tail &&
            nla_put(msg, NL80211_ATTR_BEACON_TAIL, settings->tail_len, settings->tail)) ||
        (settings->beacon_ies && nla_put(msg, NL80211_ATTR_IE,
        settings->beacon_ies_len, settings->beacon_ies)) ||
        (settings->proberesp_ies && nla_put(msg, NL80211_ATTR_IE_PROBE_RESP,
        settings->proberesp_ies_len, settings->proberesp_ies)) ||
        (settings->assocresp_ies && nla_put(msg, NL80211_ATTR_IE_ASSOC_RESP,
        settings->assocresp_ies_len, settings->assocresp_ies)) ||
        (settings->probe_resp && nla_put(msg, NL80211_ATTR_PROBE_RESP,
        settings->probe_resp_len, settings->probe_resp))) {
        return -1;
    }

    return 0;
}

static int nl80211_put_freq_params(struct nl_msg *msg, const struct hostapd_freq_params *freq)
{
    wifi_hal_dbg_print("%s:%d: freq=%d\n", __func__, __LINE__, freq->freq);
    if (nla_put_u32(msg, NL80211_ATTR_WIPHY_FREQ, freq->freq))
        return -1;

    wifi_hal_dbg_print("  * he_enabled=%d\n", freq->he_enabled);
    wifi_hal_dbg_print("  * vht_enabled=%d\n", freq->vht_enabled);
    wifi_hal_dbg_print("  * ht_enabled=%d\n", freq->ht_enabled);

    if (freq->vht_enabled || freq->he_enabled) {
        enum nl80211_chan_width cw;

        wifi_hal_dbg_print("  * bandwidth=%d\n", freq->bandwidth);
        switch (freq->bandwidth) {
        case 20:
            cw = NL80211_CHAN_WIDTH_20;
            break;
        case 40:
            cw = NL80211_CHAN_WIDTH_40;
            break;
        case 80:
            if (freq->center_freq2)
                cw = NL80211_CHAN_WIDTH_80P80;
            else
                cw = NL80211_CHAN_WIDTH_80;
            break;
        case 160:
            cw = NL80211_CHAN_WIDTH_160;
            break;
        default:
            return -1;
        }

        wifi_hal_dbg_print("  * channel_width=%d\n", cw);
        wifi_hal_dbg_print("  * center_freq1=%d\n", freq->center_freq1);
        wifi_hal_dbg_print("  * center_freq2=%d\n", freq->center_freq2);
        if (nla_put_u32(msg, NL80211_ATTR_CHANNEL_WIDTH, cw) ||
            nla_put_u32(msg, NL80211_ATTR_CENTER_FREQ1, freq->center_freq1) ||
            (freq->center_freq2 && nla_put_u32(msg, NL80211_ATTR_CENTER_FREQ2, freq->center_freq2))) {
            return -1;
        }
    } else if (freq->ht_enabled) {
        enum nl80211_channel_type ct;

        wifi_hal_dbg_print("  * sec_channel_offset=%d\n", freq->sec_channel_offset);
        switch (freq->sec_channel_offset) {
        case -1:
            ct = NL80211_CHAN_HT40MINUS;
            break;
        case 1:
            ct = NL80211_CHAN_HT40PLUS;
            break;
        default:
            ct = NL80211_CHAN_HT20;
            break;
        }

        wifi_hal_dbg_print("  * channel_type=%d\n", ct);
        if (nla_put_u32(msg, NL80211_ATTR_WIPHY_CHANNEL_TYPE, ct))
            return -1;
    } else {
        wifi_hal_dbg_print("  * channel_type=%d\n", NL80211_CHAN_NO_HT);
        if (nla_put_u32(msg, NL80211_ATTR_WIPHY_CHANNEL_TYPE, NL80211_CHAN_NO_HT)) {
            return -1;
        }
    }

    return 0;
}

static int get_bw80_center_freq(wifi_radio_operationParam_t *param, const char *country)
{
    int i, freq = 0, num_channels;
    int *channels;
    unsigned int center_channels_5g[] = {42, 58, 106, 122, 138, 155};
    unsigned int center_channels_6g[] = {7, 23, 39, 55, 71, 87, 103, 119, 135, 151, 167, 183, 199, 215};

    if (param->band == WIFI_FREQUENCY_6_BAND) {
        channels = &center_channels_6g[0];
        num_channels = ARRAY_SZ(center_channels_6g);
    } else {
        channels = &center_channels_5g[0];
        num_channels = ARRAY_SZ(center_channels_5g);
    }

    for (i = 0; i < num_channels; i++) {
        if (param->channel <= (channels[i]+6)) {
            freq = ieee80211_chan_to_freq(country, param->op_class, channels[i]);
            break;
        }
    }

    return freq;
}

static int get_bw160_center_freq(wifi_radio_operationParam_t *param, const char *country)
{
    int i, freq = 0, num_channels;
    int *channels;
    int center_channels_5g[] = {50, 114, 163};
    int center_channels_6g[] = {15, 47, 79, 111, 143, 175, 207};

    if (param->band == WIFI_FREQUENCY_6_BAND) {
        channels = &center_channels_6g[0];
        num_channels = ARRAY_SZ(center_channels_6g);
    } else {
        channels = &center_channels_5g[0];
        num_channels = ARRAY_SZ(center_channels_5g);
    }

    for (i = 0; i < num_channels; i++) {
        if (param->channel <= (channels[i]+14)) {
            freq = ieee80211_chan_to_freq(country, param->op_class, channels[i]);
            break;
        }
    }

    return freq;
}

static void nl80211_fill_chandef(struct nl_msg *msg, wifi_radio_info_t *radio, wifi_interface_info_t *interface)
{
    int freq, freq1;
    unsigned int width;
    char country[8];
    int sec_chan_offset;
    wifi_radio_operationParam_t *param;

    param = &radio->oper_param;

    get_coutry_str_from_code(param->countryCode, country);
    freq = ieee80211_chan_to_freq(country, param->op_class, param->channel);
    freq1 = freq;

    switch (param->channelWidth) {
        case WIFI_CHANNELBANDWIDTH_20MHZ:
            width = NL80211_CHAN_WIDTH_20;
            break;

        case WIFI_CHANNELBANDWIDTH_40MHZ:
            width = NL80211_CHAN_WIDTH_40;
            if ((sec_chan_offset = get_sec_channel_offset(radio, freq)) == 0) {
                wifi_hal_info_print("%s:%d: Failed to get sec channel offset for dev:%d\n", __func__, __LINE__, radio->index);
            }

            freq1 = freq + sec_chan_offset*10;
            break;

        case WIFI_CHANNELBANDWIDTH_80MHZ:
            width = NL80211_CHAN_WIDTH_80;
            freq1 = get_bw80_center_freq(param, country);
            break;

        case WIFI_CHANNELBANDWIDTH_160MHZ:
            width = NL80211_CHAN_WIDTH_160;
            freq1 = get_bw160_center_freq(param, country);
            break;
    
        case WIFI_CHANNELBANDWIDTH_80_80MHZ:
            width = NL80211_CHAN_WIDTH_80P80;
            break;
    
        default:
            width = NL80211_CHAN_WIDTH_20;
            break;
    }

    nla_put_u32(msg, NL80211_ATTR_WIPHY_FREQ, freq);
    nla_put_u32(msg, NL80211_ATTR_CENTER_FREQ1, freq1);
    nla_put_u32(msg, NL80211_ATTR_CENTER_FREQ2, 0);
    nla_put_u32(msg, NL80211_ATTR_CHANNEL_WIDTH, width);

    wifi_hal_dbg_print("%s:%d Setting channel freq:%d freq1:%d width:%d on interface:%d\n", __func__, __LINE__, freq, freq1, width, interface->index);
}

int nl80211_switch_channel(wifi_radio_info_t *radio)
{
    wifi_interface_info_t *interface;
    wifi_radio_operationParam_t *param;
    struct csa_settings csa_settings;
    int sec_chan_offset, freq, freq1, bandwidth;
    char country[8];

    param = &radio->oper_param;
    get_coutry_str_from_code(param->countryCode, country);
    freq = ieee80211_chan_to_freq(country, param->op_class, param->channel);
    freq1 = freq;
    sec_chan_offset = get_sec_channel_offset(radio, freq);

    wifi_hal_dbg_print("%s:%d Switch channel to %d in radio %d\n", __func__, __LINE__, param->channel, radio->index);

    switch (param->channelWidth) {
    case WIFI_CHANNELBANDWIDTH_20MHZ:
        bandwidth = 20;
        break;

    case WIFI_CHANNELBANDWIDTH_40MHZ:
        bandwidth = 40;
        freq1 = freq + sec_chan_offset*10;
        break;

    case WIFI_CHANNELBANDWIDTH_80MHZ:
        bandwidth = 80;
        freq1 = get_bw80_center_freq(param, country);
        break;

    case WIFI_CHANNELBANDWIDTH_160MHZ:
        bandwidth = 160;
        freq1 = get_bw160_center_freq(param, country);
        break;

    default:
        bandwidth = 20;
        break;
    }

    /* Setup CSA request */
    os_memset(&csa_settings, 0, sizeof(csa_settings));
    csa_settings.cs_count = 5;

    os_memset(&csa_settings.freq_params, 0, sizeof(struct hostapd_freq_params));

    csa_settings.freq_params.mode = radio->iconf.hw_mode;
    csa_settings.freq_params.freq = ieee80211_chan_to_freq(country, param->op_class, param->channel);
    csa_settings.freq_params.channel = param->channel;
    csa_settings.freq_params.ht_enabled = radio->iconf.ieee80211n;
    csa_settings.freq_params.vht_enabled = radio->iconf.ieee80211ac;
    csa_settings.freq_params.he_enabled = radio->iconf.ieee80211ax;
    csa_settings.freq_params.sec_channel_offset = sec_chan_offset;
    csa_settings.freq_params.center_freq1 = freq1;
    csa_settings.freq_params.center_freq2 = 0;
    csa_settings.freq_params.bandwidth = bandwidth;


    interface = hash_map_get_first(radio->interface_map);

    while (interface != NULL) {
        if (interface->bss_started) {
            wifi_hal_dbg_print("Switch channel on %s\n", interface->name);
            hostapd_set_oper_centr_freq_seg1_idx(interface->u.ap.hapd.iconf, 0);
            hostapd_set_oper_centr_freq_seg0_idx(interface->u.ap.hapd.iconf, 0);

            switch (param->channelWidth) {
            case WIFI_CHANNELBANDWIDTH_20MHZ:
            case WIFI_CHANNELBANDWIDTH_40MHZ:
                hostapd_set_oper_chwidth(interface->u.ap.hapd.iconf, CHANWIDTH_USE_HT);
                break;

            case WIFI_CHANNELBANDWIDTH_80MHZ:
                hostapd_set_oper_chwidth(interface->u.ap.hapd.iconf, CHANWIDTH_80MHZ);
                break;

            case WIFI_CHANNELBANDWIDTH_160MHZ:
                hostapd_set_oper_chwidth(interface->u.ap.hapd.iconf, CHANWIDTH_160MHZ);
                break;

            default:
                hostapd_set_oper_chwidth(interface->u.ap.hapd.iconf, CHANWIDTH_USE_HT);
                break;
            }

            hostapd_switch_channel(&interface->u.ap.hapd, &csa_settings);
        }
        interface = hash_map_get_next(radio->interface_map, interface);
    }

    return 0;
}

int nl80211_update_wiphy(wifi_radio_info_t *radio)
{
    struct nl_msg *msg;
    int ret;
    wifi_interface_info_t *interface;
    bool reconfigure = false;
    
    interface = hash_map_get_first(radio->interface_map);

    while (interface != NULL) {
        if (interface->bss_started) {
                reconfigure = true;
                nl80211_enable_ap(interface, false);
                nl80211_interface_enable(interface->name, false);
        }
        interface = hash_map_get_next(radio->interface_map, interface);
    }

    interface = get_private_vap_interface(radio);

    if (interface == NULL) {
        wifi_hal_error_print("%s:%d: Error updating dev:%d no interfaces exist\n", __func__, __LINE__, radio->index);
        return -1;
    }

    msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, NULL, 0, NL80211_CMD_SET_WIPHY);
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, interface->index);
    nl80211_fill_chandef(msg, radio, interface);

    if ((ret = send_and_recv(g_wifi_hal.nl_cb, g_wifi_hal.nl, msg, wiphy_set_info_handler, &g_wifi_hal, NULL, NULL))) {
        wifi_hal_info_print("%s:%d: Error updating dev:%d error: %s\n",
            __func__, __LINE__, radio->index, strerror(-ret));

        if(!reconfigure) {
            interface = hash_map_get_first(radio->interface_map);

            while (interface != NULL) {
                if(is_wifi_hal_vap_mesh_sta(interface->vap_info.vap_index) == false) {
                    nl80211_enable_ap(interface, false);
                    nl80211_interface_enable(interface->name, false);
                }
                interface = hash_map_get_next(radio->interface_map, interface);
            }

           interface = get_private_vap_interface(radio);

           if (interface == NULL) {
               wifi_hal_error_print("%s:%d: reconfig error, updating dev:%d no interfaces exist\n", __func__, __LINE__, radio->index);
               return -1;
           }

           msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, NULL, 0, NL80211_CMD_SET_WIPHY);
           nla_put_u32(msg, NL80211_ATTR_IFINDEX, interface->index);
           nl80211_fill_chandef(msg, radio, interface);

           if ((ret = send_and_recv(g_wifi_hal.nl_cb, g_wifi_hal.nl, msg, wiphy_set_info_handler, &g_wifi_hal, NULL, NULL))) {
               wifi_hal_error_print("%s:%d: reconfig error, updating dev:%d error: %s ret:%d\n",
                                  __func__, __LINE__, radio->index, strerror(-ret), ret);
               return -1;
           }
           wifi_hal_info_print("%s:%d: reconfig success\n", __func__, __LINE__);
           goto Exit;
       }
        return -1;
    }

Exit:
    if(reconfigure) {
        interface = hash_map_get_first(radio->interface_map);
        while (interface != NULL) {
            if (interface->bss_started) {
                nl80211_interface_enable(interface->name, true);
                ieee802_11_update_beacons(interface->u.ap.hapd.iface);
            }
            interface = hash_map_get_next(radio->interface_map, interface);
        }
    }

    wifi_hal_info_print("%s:%d: Updating dev:%d successful\n",
            __func__, __LINE__, radio->index);

    return 0;
}

int nl80211_set_regulatory_domain(wifi_countrycode_type_t country_code)
{
    struct nl_msg *msg;
    int ret;
    char alpha2[3];
    memset(alpha2, 0, sizeof(alpha2));

    get_coutry_str_from_code(country_code, alpha2);

    msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, NULL, 0, NL80211_CMD_REQ_SET_REG);
    nla_put_string(msg, NL80211_ATTR_REG_ALPHA2, alpha2);
    if ((ret = send_and_recv(g_wifi_hal.nl_cb, g_wifi_hal.nl, msg, regulatory_domain_set_info_handler, &g_wifi_hal, NULL, NULL))) {
        wifi_hal_dbg_print("%s:%d: Error updating regulatory_domain error: %s\n",
            __func__, __LINE__, strerror(-ret));
        return RETURN_ERR;
    }
    return RETURN_OK;
}

int nl80211_register_mgmt_frames(wifi_interface_info_t *interface)
{
    struct nl_msg *msg;
    unsigned int i;
    int ret;
    //wifi_vap_info_t *vap;
    //wifi_radio_info_t *radio;
    static const int stypes[] = {
        WLAN_FC_STYPE_AUTH,
        WLAN_FC_STYPE_ASSOC_REQ,
        WLAN_FC_STYPE_REASSOC_REQ,
        WLAN_FC_STYPE_DISASSOC,
        WLAN_FC_STYPE_DEAUTH,
        WLAN_FC_STYPE_PROBE_REQ,
        WLAN_FC_STYPE_ACTION,
        /*WLAN_FC_STYPE_BEACON,*/ 
    };
    unsigned short frame_type;

    if (interface->mgmt_frames_registered == 1) {
        wifi_hal_dbg_print("%s:%d: Mgmt frames already registered for %s\n", __func__, __LINE__, interface->name);
        return 0;
    }

   // vap = &interface->vap_info;
   // radio = get_radio_by_index(vap->radio_index);

    interface->nl_cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (!interface->nl_cb) {
        return -1;
    }

    nl_cb_set(interface->nl_cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, no_seq_check, NULL);
    nl_cb_set(interface->nl_cb, NL_CB_VALID, NL_CB_CUSTOM, process_mgmt_frame, interface);
    
    interface->nl_event = nl_create_handle(g_wifi_hal.nl_cb, "mgmt");
    if (interface->nl_event == NULL) {
        nl_cb_put(interface->nl_cb);
        return -1;
    }

    interface->nl_event_fd = nl_socket_get_fd((struct nl_sock *)interface->nl_event);
    wifi_hal_dbg_print("%s:%d:nl80211 mgmt socket descriptor:%d\n", __func__, __LINE__, interface->nl_event_fd);

    for (i = 0; i < sizeof(stypes)/sizeof(int); i++) {
        msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, NULL, 0, NL80211_CMD_REGISTER_FRAME);
        if (msg == NULL) {
            return -1;
        }
    
        if (nla_put_u32(msg, NL80211_ATTR_IFINDEX, interface->index) < 0) {
            nlmsg_free(msg);
            return -1;
        }

        frame_type = (WLAN_FC_TYPE_MGMT << 2) | (stypes[i] << 4);

        if (nla_put_u16(msg, NL80211_ATTR_FRAME_TYPE, frame_type) < 0) {
            nlmsg_free(msg);
            return -1;
        }
    
        if (nla_put(msg, NL80211_ATTR_FRAME_MATCH, 0, NULL) < 0) {
            nlmsg_free(msg);
            return -1;
        }

        if ((ret = send_and_recv(interface->nl_cb, interface->nl_event, msg, mgmt_frame_register_handler, interface, NULL, NULL))) {
            if ((-ret) == EALREADY) {
                wifi_hal_dbg_print("%s:%d: Mgmt frames already registered\n", __func__, __LINE__);
            } else {
                wifi_hal_error_print("%s:%d: Error registering for management frames on interface %s error: %s\n",
                    __func__, __LINE__, interface->name, strerror(-ret));
                return -1;
            }
        }
    }

    interface->mgmt_frames_registered = 1;

    return 0;
}

int nl80211_update_interface(wifi_interface_info_t *interface)
{
    struct nl_msg *msg;
    int ret;
    wifi_vap_info_t *vap;
    wifi_radio_info_t *radio;

    vap = &interface->vap_info;

    radio = get_radio_by_rdk_index(vap->radio_index);

    msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, NL80211_CMD_SET_INTERFACE);
    if (msg == NULL) {
        wifi_hal_error_print("%s:%d: nl80211 driver command msg failure for %s interface on dev:%d \n",
                    __func__, __LINE__, interface->name, radio->index);
        return -1;
    }

    if (vap->vap_mode == wifi_vap_mode_ap) {
        nla_put_u32(msg, NL80211_ATTR_IFTYPE, NL80211_IFTYPE_AP);
    } else {

        nla_put_u32(msg, NL80211_ATTR_IFTYPE, NL80211_IFTYPE_AP);

        if ((ret = send_and_recv(g_wifi_hal.nl_cb, g_wifi_hal.nl, msg, interface_info_handler, &g_wifi_hal, NULL, NULL))) {
            wifi_hal_error_print("%s:%d: Error updating %s interface on dev:%d error: %s\n",
                        __func__, __LINE__, interface->name, radio->index, strerror(-ret));
            return -1;
        }

        wifi_hal_dbg_print("%s:%d: Updating %s interface on dev:%d to type: NL80211_IFTYPE_AP successful\n",
                    __func__, __LINE__, interface->name, radio->index);

        if (interface->vap_info.u.sta_info.enabled != true) {
            return 0;
        }

        msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, NL80211_CMD_SET_INTERFACE);
        nla_put_u32(msg, NL80211_ATTR_IFTYPE, NL80211_IFTYPE_STATION);
    }

    if ((ret = send_and_recv(g_wifi_hal.nl_cb, g_wifi_hal.nl, msg, interface_info_handler, &g_wifi_hal, NULL, NULL))) {
        wifi_hal_error_print("%s:%d: Error updating %s interface on dev:%d error: %s\n",
            __func__, __LINE__, interface->name, radio->index, strerror(-ret));
        return -1;
    }
        
    wifi_hal_dbg_print("%s:%d: Updating %s interface on dev:%d to type:%s successful\n",
            __func__, __LINE__, interface->name, radio->index, 
            (vap->vap_mode == wifi_vap_mode_ap) ? "NL80211_IFTYPE_AP":"NL80211_IFTYPE_STATION");

    return 0;
}

int nl80211_create_interface(wifi_radio_info_t *radio, wifi_vap_info_t *vap, wifi_interface_info_t **interface)
{
    struct nl_msg *msg;
    wifi_interface_info_t *intf;
    char ifname[32];
    int ret;

    msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, NULL, 0, NL80211_CMD_NEW_INTERFACE);
    if (msg == NULL) {
        return -1;
    }

    if (nla_put_u32(msg, NL80211_ATTR_WIPHY, radio->index) < 0) {
        nlmsg_free(msg);
        return -1;
    }

    if ((vap->vap_index == 0) || (vap->vap_index == 1)) {
        sprintf(ifname, "wl%d", radio->index);
    } else {
        sprintf(ifname, "wl%d.%d", radio->index, vap->vap_index/2);
    }

    if (nla_put_string(msg, NL80211_ATTR_IFNAME, ifname) < 0) {
        nlmsg_free(msg);
        return -1;
    }

    if (nla_put_u32(msg, NL80211_ATTR_IFTYPE, NL80211_IFTYPE_AP) < 0) {
        nlmsg_free(msg);
        return -1;
    }

    if (nla_put(msg, NL80211_ATTR_MAC, sizeof(mac_address_t), vap->u.bss_info.bssid) < 0) {
        nlmsg_free(msg);
        return -1;
    }

    if ((ret = send_and_recv(g_wifi_hal.nl_cb, g_wifi_hal.nl, msg, interface_info_handler, &g_wifi_hal, NULL, NULL))) {
        wifi_hal_error_print("%s:%d: Error creating %s interface on dev:%d error: %s\n", __func__, __LINE__, 
            ifname, radio->index, strerror(-ret));
        return -1;
    }

    if ((intf = get_interface_by_vap_index(vap->vap_index)) != NULL) {
        wifi_hal_dbg_print("%s:%d:interface for vap index:%d already exists\n", __func__, __LINE__, 
            vap->vap_index);

        memcpy(&intf->vap_info, vap, sizeof(wifi_vap_info_t));
        nl80211_interface_enable(intf->name, true);
    }

    *interface = intf;

    return 0;
}

int nl80211_create_interfaces(wifi_radio_info_t *radio, wifi_vap_info_map_t *map)
{
    unsigned int i;
    wifi_interface_info_t *interface;
    wifi_vap_info_t *vap;

    wifi_hal_dbg_print("%s:%d: Number of VAP(s) to create: %d\n", __func__, __LINE__, map->num_vaps);

    for (i = 0; i < map->num_vaps; i++) {

        vap = &map->vap_array[i];

        if ((interface = get_interface_by_vap_index(vap->vap_index)) != NULL) {
            wifi_hal_dbg_print("%s:%d:interface for vap index:%d already exists\n",
            __func__, __LINE__, vap->vap_index);

            memcpy(&interface->vap_info, vap, sizeof(wifi_vap_info_t));
            nl80211_interface_enable(interface->name, true);
            continue;
        } 

        interface = NULL;

        wifi_hal_dbg_print("%s:%d:interface for vap index:%d not found ... creating with mac:%02x:%02x:%02x:%02x:%02x:%02x\n", 
            __func__, __LINE__, vap->vap_index, 
            vap->u.bss_info.bssid[0], vap->u.bss_info.bssid[1], vap->u.bss_info.bssid[2],
            vap->u.bss_info.bssid[3], vap->u.bss_info.bssid[4], vap->u.bss_info.bssid[5]);

        if (nl80211_create_interface(radio, vap, &interface) != 0) {
            wifi_hal_error_print("%s:%d:interface for vap index:%d create failed\n", 
                __func__, __LINE__, vap->vap_index);
            return -1;
        }
    }

    return 0;
}

int scan_results_handler(struct nl_msg *msg, void *arg)
{
//    int *ret = arg;
    unsigned int count;
    wifi_bss_info_t *bss, *scan_info, *tmp_bss;
//    struct genlmsghdr *gnlh;
    wifi_sta_priv_t *sta;
    wifi_device_callbacks_t *callbacks;
    wifi_finish_data_t *finish_data = (wifi_finish_data_t *)arg;
    wifi_interface_info_t   *interface = (wifi_interface_info_t *)finish_data->arg;
   
    *finish_data->err = 0; 
//    gnlh = nlmsg_data(nlmsg_hdr(msg));


    callbacks = get_hal_device_callbacks();
    if (callbacks == NULL) {
        return NL_SKIP;
    }

    if (callbacks->scan_result_callback == NULL) {
        wifi_hal_error_print("%s:%d: Scan results call back not registered\n", __func__, __LINE__);
        return NL_SKIP;
    }
       
    sta = &interface->u.sta;
    count = hash_map_count(sta->scan_info_map);
    if (count == 0) {
        wifi_hal_error_print("%s:%d: No Scan results...\n", __func__, __LINE__);
        bss = NULL;
        callbacks->scan_result_callback(interface->vap_info.radio_index, &bss, &count);
        return NL_SKIP;
    }
    bss = malloc(count*sizeof(wifi_bss_info_t));
    tmp_bss = bss;
     
    scan_info = hash_map_get_first(sta->scan_info_map);
    while (scan_info != NULL) {
        memcpy(tmp_bss, scan_info, sizeof(wifi_bss_info_t));
        tmp_bss++;
        //wifi_hal_dbg_print("%s:%d: ssid: %s\trssi: %d\tfrequency:%d\n", __func__, __LINE__, 
        //    scan_info->ssid, scan_info->rssi, scan_info->freq);
        scan_info = hash_map_get_next(sta->scan_info_map, scan_info);
    }

    callbacks->scan_result_callback(interface->vap_info.radio_index, &bss, &count);

    return NL_SKIP;

}

int nl80211_get_scan_results(wifi_interface_info_t *interface)
{
    struct nl_msg *msg;
    int ret;
    wifi_finish_data_t scan_results_data;
    
    wifi_hal_dbg_print("%s:%d: Getting scan results\n", __func__, __LINE__);

    if ((msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, NLM_F_DUMP, NL80211_CMD_GET_SCAN)) == NULL) {
        return -1;
    }

    scan_results_data.arg = interface;

    ret = send_and_recv(g_wifi_hal.nl_cb, g_wifi_hal.nl, msg, scan_info_handler, interface, scan_results_handler, &scan_results_data);
    if (ret == 0) {
        return 0;
    }

    wifi_hal_error_print("%s:%d: Scan command failed: ret=%d (%s)\n", __func__, __LINE__,
                            ret, strerror(-ret));

    return -1;
}

int nl80211_disconnect_sta(wifi_interface_info_t *interface)
{
    struct nl_msg *msg;
    int ret;

    if ((msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, NL80211_CMD_DISCONNECT)) == NULL) {
        return -1;
    }
    ret = send_and_recv(g_wifi_hal.nl_cb, g_wifi_hal.nl, msg, NULL, &g_wifi_hal, NULL, NULL);
    if (ret == 0) {
        return 0;
    }

    wifi_hal_error_print("%s:%d: disconnect command failed: ret=%d (%s)\n", __func__, __LINE__,
                      ret, strerror(-ret));

    return -1;
}

int nl80211_connect_sta(wifi_interface_info_t *interface)
{
    struct nl_msg *msg;
    int ret;
    u8 *pos, rsn_ie[128];
    struct wpa_auth_config wpa_conf = {0};
    struct wpa_ie_data data;
    wifi_vap_info_t *vap;
    wifi_bss_info_t *backhaul;
    wifi_vap_security_t *security;
    mac_addr_str_t bssid_str;
    //unsigned int rsn_ie_len;
    u32 ver = 0;

    vap = &interface->vap_info;
    backhaul = &interface->u.sta.backhaul;
    security = &vap->u.sta_info.security; 

    if ((msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, NL80211_CMD_CONNECT)) == NULL) {
        return -1;
    }

    wifi_hal_dbg_print("%s:%d:bssid:%s frequency:%d ssid:%s\n", __func__, __LINE__,
                       to_mac_str(backhaul->bssid, bssid_str), backhaul->freq, backhaul->ssid);

    nla_put(msg, NL80211_ATTR_SSID, strlen(backhaul->ssid), backhaul->ssid);
    nla_put(msg, NL80211_ATTR_MAC, sizeof(backhaul->bssid), backhaul->bssid);
    nla_put_u32(msg, NL80211_ATTR_WIPHY_FREQ, backhaul->freq);

    pos = rsn_ie;


    if (backhaul->ie_len && (wpa_parse_wpa_ie_rsn(backhaul->ie, backhaul->ie_len, &data) == 0)) {
	wpa_conf.wpa_group = data.group_cipher;
	wpa_conf.rsn_pairwise = WPA_CIPHER_CCMP;
	wpa_conf.wpa_key_mgmt = data.key_mgmt;
	wifi_hal_dbg_print("\nnl80211_connect_sta %x %x %x\n", wpa_conf.wpa_group, wpa_conf.rsn_pairwise,
	    wpa_conf.wpa_key_mgmt);
    } else {
        if (security->encr == wifi_encryption_aes) {
            wpa_conf.wpa_group = WPA_CIPHER_CCMP;
            wpa_conf.rsn_pairwise = WPA_CIPHER_CCMP;
        } else if (security->encr == wifi_encryption_tkip) {
            wpa_conf.wpa_group = WPA_CIPHER_TKIP;
            wpa_conf.rsn_pairwise = WPA_CIPHER_TKIP;
        } else if (security->encr == wifi_encryption_aes_tkip) {
    	    wpa_conf.wpa_group = WPA_CIPHER_TKIP;
            wpa_conf.rsn_pairwise = WPA_CIPHER_CCMP;
        } else if (security->encr == wifi_encryption_none) {
            wpa_conf.wpa_group = WPA_CIPHER_NONE;
            wpa_conf.rsn_pairwise = WPA_CIPHER_NONE;
        } else {
            wifi_hal_info_print("%s:%d:Invalid encryption mode:%d in wifi_hal_connect\n", __func__, __LINE__, security->encr);
        }
    
        switch (security->mode) {
            case wifi_security_mode_none:
                wpa_conf.wpa_key_mgmt = WPA_KEY_MGMT_NONE;
                break;
    
            case wifi_security_mode_wpa_personal:
            case wifi_security_mode_wpa2_personal:
            case wifi_security_mode_wpa_wpa2_personal:
                wpa_conf.wpa_key_mgmt = WPA_KEY_MGMT_PSK;
                break;
    
            case wifi_security_mode_wpa_enterprise:
            case wifi_security_mode_wpa2_enterprise:
            case wifi_security_mode_wpa_wpa2_enterprise:
                wpa_conf.wpa_key_mgmt = WPA_KEY_MGMT_IEEE8021X;
                break;
            case wifi_security_mode_wpa3_personal:
            case wifi_security_mode_wpa3_enterprise:
                wpa_conf.wpa_key_mgmt = WPA_KEY_MGMT_SAE;
                break;
            case wifi_security_mode_wpa3_transition:
                wpa_conf.wpa_key_mgmt = WPA_KEY_MGMT_PSK | WPA_KEY_MGMT_SAE;
                break;
            default:
                 wifi_hal_info_print("%s:%d:Invalid security mode: %d in wifi_hal_connect\r\n", __func__, __LINE__, security->mode);
                wpa_conf.wpa_key_mgmt = -1;
                break;
        }
    }

    wpa_conf.ieee80211w = 0;

    if (security->mode != wifi_security_mode_none) {
        if ((ret = wpa_write_rsn_ie(&wpa_conf, pos, rsn_ie + sizeof(rsn_ie) - pos, NULL)) < 0) {
            wifi_hal_error_print("%s:%d Failed to build RSN %d\r\n", __func__, __LINE__, ret);
            return ret;
        }
        else {
            pos += ret;
            nla_put(msg, NL80211_ATTR_IE, pos - rsn_ie, rsn_ie);
        }

        if (security->mode == wifi_security_mode_wpa2_enterprise || security->mode == wifi_security_mode_wpa2_personal)
            ver |= NL80211_WPA_VERSION_2;
        else
            ver |= NL80211_WPA_VERSION_1;
        nla_put_u32(msg, NL80211_ATTR_WPA_VERSIONS, ver);

        nla_put_u32(msg, NL80211_ATTR_CIPHER_SUITES_PAIRWISE, RSN_CIPHER_SUITE_CCMP);
        nla_put_u32(msg, NL80211_ATTR_CIPHER_SUITE_GROUP, RSN_CIPHER_SUITE_CCMP);

        if (security->mode == wifi_security_mode_wpa2_enterprise)
            nla_put_u32(msg, NL80211_ATTR_AKM_SUITES, RSN_AUTH_KEY_MGMT_UNSPEC_802_1X);
        else if (security->mode == wifi_security_mode_wpa2_personal)
            nla_put_u32(msg, NL80211_ATTR_AKM_SUITES, RSN_AUTH_KEY_MGMT_PSK_OVER_802_1X);

        nla_put_u32(msg, NL80211_ATTR_AUTH_TYPE, NL80211_AUTHTYPE_OPEN_SYSTEM);
        nla_put_flag(msg, NL80211_ATTR_PRIVACY);
    } else {
        nla_put_u32(msg, NL80211_ATTR_AUTH_TYPE, NL80211_AUTHTYPE_OPEN_SYSTEM);
        wifi_hal_dbg_print("security mode open:%d encr:%d\n", security->mode, security->encr);
    }

    ret = send_and_recv(g_wifi_hal.nl_cb, g_wifi_hal.nl, msg, NULL, &g_wifi_hal, NULL, NULL);
    if (ret == 0) {
        return 0;
    }

    wifi_hal_error_print("%s:%d: connect command failed: ret=%d (%s)\n", __func__, __LINE__,
                      ret, strerror(-ret));

    return -1;
}

static int conn_get_interface_handler(struct nl_msg *msg, void *arg)
{
    wifi_interface_info_t *interface  = (wifi_interface_info_t*)arg;
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh;
    wifi_bss_info_t bss;
    unsigned int channel_width = 0;
    wifi_vap_info_t *vap;
    int bw = NL80211_CHAN_WIDTH_20_NOHT;
    wifi_device_callbacks_t *callbacks;
    wifi_station_stats_t sta;
    wifi_radio_info_t *radio =  NULL;
    wifi_radio_operationParam_t *radio_param = NULL;
    int op_class;
    u8 channel;


    gnlh = nlmsg_data(nlmsg_hdr(msg));
    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);
    vap = &interface->vap_info;
    memcpy(&bss, &interface->u.sta.backhaul, sizeof(wifi_bss_info_t));
    
    if (tb[NL80211_ATTR_IFINDEX]) {
        if (interface->index == nla_get_u32(tb[NL80211_ATTR_IFINDEX]))
        {
            if (tb[NL80211_ATTR_WIPHY_FREQ])
            {
                ieee80211_freq_to_chan(nla_get_u32(tb[NL80211_ATTR_WIPHY_FREQ]), &channel);
            }

            if (tb[NL80211_ATTR_CHANNEL_WIDTH])
            {
                bw = nla_get_u32(tb[NL80211_ATTR_CHANNEL_WIDTH]);
            }
        }
    }
    switch (bw) {
    case NL80211_CHAN_WIDTH_20:
        channel_width = WIFI_CHANNELBANDWIDTH_20MHZ;
        break;
    case NL80211_CHAN_WIDTH_40:
        channel_width = WIFI_CHANNELBANDWIDTH_40MHZ;
        break;
    case NL80211_CHAN_WIDTH_80:
        channel_width = WIFI_CHANNELBANDWIDTH_80MHZ;
        break;
    case NL80211_CHAN_WIDTH_160:
        channel_width = WIFI_CHANNELBANDWIDTH_160MHZ;
        break;
    case NL80211_CHAN_WIDTH_80P80:
        channel_width = WIFI_CHANNELBANDWIDTH_80_80MHZ;
        break;
    default:
        break;
    }

    radio = get_radio_by_rdk_index(interface->vap_info.radio_index);
    if (radio == NULL) {
        wifi_hal_error_print("%s:%d: Unable to get radio_info for radio index %d\n", __func__, __LINE__, interface->vap_info.radio_index);
        return NL_SKIP;
    }

    radio_param = &radio->oper_param;
    if (radio_param == NULL) {
        wifi_hal_error_print("%s:%d: Unable to get radio params\n", __func__, __LINE__);
        return NL_SKIP;
    }

    if ((op_class = get_op_class_from_radio_params(radio_param)) == -1) {
        wifi_hal_error_print("%s:%d: could not find op_class for radio index:%d\n", __func__, __LINE__, interface->vap_info.radio_index);
        return NL_SKIP;
    }

    sta.channel = channel;
    sta.op_class = op_class;
    sta.channelWidth = channel_width;

    sta.vap_index = vap->vap_index;
    sta.connect_status = wifi_connection_status_connected;

    callbacks = get_hal_device_callbacks();

    if (callbacks->sta_conn_status_callback) {
        callbacks->sta_conn_status_callback(vap->vap_index, &bss, &sta);
    }

    return NL_SKIP;
}

int nl80211_get_channel_bw_conn(wifi_interface_info_t *interface)
{
    struct nl_msg *msg;
    msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, NULL, 0, NL80211_CMD_GET_INTERFACE);
    if (msg == NULL){
        return -1;
    }
    
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, interface->index);
    if (send_and_recv(g_wifi_hal.nl_cb, g_wifi_hal.nl, msg, conn_get_interface_handler, interface, NULL, NULL)) {
        return -1;
    }

    return 0;

}
int nl80211_start_scan(wifi_interface_info_t *interface, unsigned int num_freq, unsigned int  *freq_list, unsigned int num_ssid, ssid_t *ssid_list)
{
    struct nl_msg *msg;
    struct nlattr *ssids;
    int ret;
    struct nlattr *freqs; 
    unsigned int i;

    if ((msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, NL80211_CMD_TRIGGER_SCAN)) == NULL) {
        return -1;
    }

    //nla_put_u32(msg, NL80211_ATTR_SCHED_SCAN_INTERVAL, scan_params->period);

    ssids = nla_nest_start(msg, NL80211_ATTR_SCAN_SSIDS);
    nla_put(msg, 1, strlen(ssid_list[0]), ssid_list[0]); 
    nla_nest_end(msg, ssids);

    freqs = nla_nest_start(msg, NL80211_ATTR_SCAN_FREQUENCIES);
    for (i = 0; i < num_freq; i++) {
        nla_put_u32(msg, i + 1, freq_list[i]); 
    }
    nla_nest_end(msg, freqs);

    ret = send_and_recv(g_wifi_hal.nl_cb, g_wifi_hal.nl, msg, NULL, &g_wifi_hal, NULL, NULL);
    if (ret == 0) {
        return 0;
    }

    wifi_hal_error_print("%s:%d: Scan command failed: ret=%d (%s)\n", __func__, __LINE__,
                      ret, strerror(-ret));

    return -1;
}
#if 0
static int bss_info_handler(struct nl_msg *msg, void *arg)
{
    return NL_SKIP;
}
#endif
static int scan_info_handler(struct nl_msg *msg, void *arg)
{
    wifi_interface_info_t *interface;
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh;
    struct nlattr *bss[NL80211_BSS_MAX + 1];
    static struct nla_policy bss_policy[NL80211_BSS_MAX + 1] = {
        [NL80211_BSS_BSSID] = { .type = NLA_UNSPEC },
        [NL80211_BSS_FREQUENCY] = { .type = NLA_U32 },
        [NL80211_BSS_TSF] = { .type = NLA_U64 },
        [NL80211_BSS_BEACON_INTERVAL] = { .type = NLA_U16 },
        [NL80211_BSS_CAPABILITY] = { .type = NLA_U16 },
        [NL80211_BSS_INFORMATION_ELEMENTS] = { .type = NLA_UNSPEC },
        [NL80211_BSS_SIGNAL_MBM] = { .type = NLA_U32 },
        [NL80211_BSS_SIGNAL_UNSPEC] = { .type = NLA_U8 },
        [NL80211_BSS_STATUS] = { .type = NLA_U32 },
        [NL80211_BSS_SEEN_MS_AGO] = { .type = NLA_U32 },
        [NL80211_BSS_BEACON_IES] = { .type = NLA_UNSPEC },
        [NL80211_BSS_PARENT_TSF] = { .type = NLA_U64 },
        [NL80211_BSS_PARENT_BSSID] = { .type = NLA_UNSPEC },
        [NL80211_BSS_LAST_SEEN_BOOTTIME] = { .type = NLA_U64 },
    };
    mac_address_t   bssid;
    mac_addr_str_t bssid_str;
    wifi_vap_info_t *vap;
    ieee80211_tlv_t *rsn_ie = NULL;
    ieee80211_tlv_t *ie = NULL, *ie_ssid = NULL;
    signed int len;
    unsigned short ie_ssid_len;
    wifi_sta_priv_t *sta;
    wifi_bss_info_t *scan_info = NULL;
    const char *key;
    wifi_bss_info_t l_scan_info;
    ssid_t          l_ssid;
    memset(l_ssid, 0, sizeof(l_ssid));

    interface = (wifi_interface_info_t *)arg;
    vap = &interface->vap_info;

    if (vap->vap_mode != wifi_vap_mode_sta) {
        wifi_hal_error_print("%s:%d:not sta mode\n", __func__, __LINE__);
        return NL_SKIP;
    }

    sta = &interface->u.sta;

    gnlh = nlmsg_data(nlmsg_hdr(msg));
    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

    if (tb[NL80211_ATTR_BSS] == NULL) {
        wifi_hal_error_print("%s:%d:bss attribute not present\n", __func__, __LINE__);
        return NL_SKIP;
    }

    if (nla_parse_nested(bss, NL80211_BSS_MAX, tb[NL80211_ATTR_BSS], bss_policy) != 0) {
        wifi_hal_error_print("%s:%d:nested bss attribute not present\n", __func__, __LINE__);
        return NL_SKIP;
    }

    if (bss[NL80211_BSS_BSSID] != NULL) {
        memcpy(bssid, nla_data(bss[NL80211_BSS_BSSID]), sizeof(mac_address_t));
        key = to_mac_str(bssid, bssid_str);
    } else {
        //wifi_hal_dbg_print("%s:%d:ssid for BSSID:%s not found\n", __func__, __LINE__, 
            //to_mac_str(bssid, bssid_str));
        return NL_SKIP;
    }

    if (bss[NL80211_BSS_INFORMATION_ELEMENTS]) {
        ie = nla_data(bss[NL80211_BSS_INFORMATION_ELEMENTS]);
        len = nla_len(bss[NL80211_BSS_INFORMATION_ELEMENTS]);
	wifi_hal_dbg_print("IE LEN %d\n", len);
    } else {
        ie = NULL;
        len = 0;
        //wifi_hal_dbg_print("%s:%d:ssid for BSSID:%s not found\n", __func__, __LINE__, 
            //to_mac_str(bssid, bssid_str));
        return NL_SKIP;
    }

    if (get_ie_by_eid(WLAN_EID_SSID, (unsigned char *)ie, len, (unsigned char **)&ie_ssid, &ie_ssid_len) == true) {
        memcpy(l_ssid, ie_ssid->value, ie_ssid_len - sizeof(ieee80211_tlv_t));
    }

    if (strlen(l_ssid) != 0) {
        // create or update the scan info
        scan_info = hash_map_get(sta->scan_info_map, key);
        if (scan_info == NULL) {
            scan_info = (wifi_bss_info_t *)malloc(sizeof(wifi_bss_info_t));
            memset(scan_info, 0, sizeof(wifi_bss_info_t));
            memcpy(scan_info->bssid, bssid, sizeof(bssid_t));
            memcpy(scan_info->ssid, l_ssid, sizeof(ssid_t));
            hash_map_put(sta->scan_info_map, strdup(key), scan_info);
        } else {
            memcpy(scan_info->ssid, l_ssid, sizeof(ssid_t));
        }
    } else {
        scan_info = &l_scan_info;
    }

    if (bss[NL80211_BSS_FREQUENCY]) {
        scan_info->freq = nla_get_u32(bss[NL80211_BSS_FREQUENCY]);
    }

    if (bss[NL80211_BSS_BEACON_INTERVAL]) {
        scan_info->beacon_int = nla_get_u16(bss[NL80211_BSS_BEACON_INTERVAL]);
    }

    if (bss[NL80211_BSS_CAPABILITY]) {
        scan_info->caps = nla_get_u16(bss[NL80211_BSS_CAPABILITY]);
    }
     
    if (bss[NL80211_BSS_SIGNAL_MBM]) {
        scan_info->rssi = nla_get_u32(bss[NL80211_BSS_SIGNAL_MBM]);
        scan_info->rssi /= 100;
    } else if (bss[NL80211_BSS_SIGNAL_UNSPEC]) {
        scan_info->rssi = nla_get_u8(bss[NL80211_BSS_SIGNAL_UNSPEC]);
    }

    if (strcmp(scan_info->ssid, vap->u.sta_info.ssid) == 0) {
	wifi_hal_dbg_print("%s:%d: found backhaul bssid:%s rssi:%d on freq:%d for ssid:%s\n", __func__, __LINE__,
	                   to_mac_str(bssid, bssid_str), scan_info->rssi, scan_info->freq, scan_info->ssid);
        memcpy(vap->u.sta_info.bssid, bssid, sizeof(bssid_t));
    }

    if (ie != NULL) {
        wifi_hal_dbg_print("RSN FOUND\n");
        rsn_ie = (ieee80211_tlv_t *)get_ie((unsigned char*)ie, len, WLAN_EID_RSN);
   
        if (rsn_ie != NULL) {
            scan_info->ie_len = rsn_ie->length + 2;
            os_memcpy(scan_info->ie, rsn_ie, scan_info->ie_len);
        } else {
	    wifi_hal_dbg_print("RSN NOT FOUND\n");
	}
    }

    return NL_SKIP;
}


static int beacon_info_handler(struct nl_msg *msg, void *arg)
{
    wifi_hal_dbg_print("%s:%d:Enter\n", __func__, __LINE__);

    return NL_SKIP;
}

int nl80211_update_beacon_params(wifi_interface_info_t *interface)
{
    struct nl_msg *msg;
    int ret;

    if ((msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, NLM_F_DUMP, NL80211_CMD_GET_BEACON)) == NULL) {
        return -1;
    }

    ret = send_and_recv(g_wifi_hal.nl_cb, g_wifi_hal.nl, msg, beacon_info_handler, &g_wifi_hal, NULL, NULL);
    if (ret == 0) {
        return 0;
    }

    wifi_hal_error_print("%s:%d: bacon get command failed:%s\n", __func__, __LINE__, strerror(-ret));

    return -1;
}

static int nl80211_send_frame_cmd(wifi_interface_info_t *interface,
                                  unsigned int freq,
                                  const u8 *buf, size_t buf_len,
                                  int save_cookie, int no_ack,
                                  const u16 *csa_offs,
                                  size_t csa_offs_len)
{
    struct nl_msg *msg;
    u64 cookie;
    int ret = -1;

    wpa_printf(MSG_MSGDUMP, "nl80211: CMD_FRAME freq=%u no_ack=%d \n", freq, no_ack);
    wpa_hexdump(MSG_MSGDUMP, "CMD_FRAME", buf, buf_len);

    if (!(msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, NL80211_CMD_FRAME)) ||
        (freq && nla_put_u32(msg, NL80211_ATTR_WIPHY_FREQ, freq)) ||
        (no_ack && nla_put_flag(msg, NL80211_ATTR_DONT_WAIT_FOR_ACK)) ||
        (csa_offs && nla_put(msg, NL80211_ATTR_CSA_C_OFFSETS_TX,
                             csa_offs_len * sizeof(u16), csa_offs)) ||
        nla_put(msg, NL80211_ATTR_FRAME, buf_len, buf)) {
        goto fail;
    }

    cookie = 0;
    ret = send_and_recv(g_wifi_hal.nl_cb, g_wifi_hal.nl, msg, cookie_handler, &cookie, NULL, NULL);
    msg = NULL;
    if (ret) {
        wifi_hal_info_print("nl80211: Frame command failed: ret=%d (%s) (freq=%u )\n",
                           ret, strerror(-ret), freq);
    } else {
        //wifi_hal_dbg_print("nl80211: Frame TX command accepted%s; "
        //"cookie 0x%llx\n", no_ack ? " (no ACK)" : "",
        //(long long unsigned int) cookie);
    }

    fail:
    nlmsg_free(msg);
    return ret;
}

static int wifi_sta_remove(wifi_interface_info_t *interface,
    const u8 *addr, int deauth, u16 reason_code)
{
    struct nl_msg *msg;
    mac_addr_str_t mac_str;
    int ret;

    if (!(msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, 0,
            NL80211_CMD_DEL_STATION)) ||
            nla_put(msg, NL80211_ATTR_MAC, ETH_ALEN, addr) ||
            (deauth == 0 &&
            nla_put_u8(msg, NL80211_ATTR_MGMT_SUBTYPE,
            WLAN_FC_STYPE_DISASSOC)) ||
            (deauth == 1 &&
            nla_put_u8(msg, NL80211_ATTR_MGMT_SUBTYPE,
            WLAN_FC_STYPE_DEAUTH)) ||
            (reason_code &&
            nla_put_u16(msg, NL80211_ATTR_REASON_CODE, reason_code))) {
        nlmsg_free(msg);
        return -ENOBUFS;
    }

    ret = send_and_recv(g_wifi_hal.nl_cb, g_wifi_hal.nl, msg, NULL, NULL, NULL, NULL);

    wifi_hal_info_print("nl80211: sta_remove -> DEL_STATION %s %s --> %d (%s)\n",
          interface->name, to_mac_str(addr, mac_str), ret, strerror(-ret));

    if (ret == -ENOENT) {
        return 0;
    }
    return ret;
}

int wifi_drv_set_4addr_mode(void *priv, const char *bridge_ifname, int val)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_send_external_auth_status(void *priv, struct external_auth *params)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_update_connection_params(
    void *priv, struct wpa_driver_associate_params *params,
    enum wpa_drv_update_connect_params_mask mask)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_get_ext_capab(void *priv, enum wpa_driver_if_type type,
                 const u8 **ext_capa, const u8 **ext_capa_mask,
                 unsigned int *ext_capa_len)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_configure_data_frame_filters(void *priv, u32 filter_flags)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_ignore_assoc_disallow(void *priv, int ignore_disallow)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_get_bss_transition_status_handler(struct nl_msg *msg, void *arg)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

unsigned int wifi_drv_get_ifindex(void *priv)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_del_ts(void *priv, u8 tsid, const u8 *addr)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_add_ts(void *priv, u8 tsid, const u8 *addr, u8 user_priority, u16 admitted_time)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_br_set_net_param(void *priv, enum drv_br_net_param param, unsigned int val)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_br_port_set_attr(void *priv, enum drv_br_port_attr attr, unsigned int val)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_br_delete_ip_neigh(void *priv, u8 version, const u8 *ipaddr)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_br_add_ip_neigh(void *priv, u8 version,
                      const u8 *ipaddr, int prefixlen,
                      const u8 *addr)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_set_mac_addr(void *priv, const u8 *addr)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_set_wowlan(void *priv, const struct wowlan_triggers *triggers)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_set_qos_map(void *priv, const u8 *qos_map_set, u8 qos_map_set_len)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}
#if HOSTAPD_VERSION >= 210 //2.10
int wifi_drv_vendor_cmd(void *priv, unsigned int vendor_id,
                  unsigned int subcmd, const u8 *data,
                  size_t data_len, enum nested_attr nested_attr_flag, struct wpabuf *buf)
#else
int wifi_drv_vendor_cmd(void *priv, unsigned int vendor_id,
                  unsigned int subcmd, const u8 *data,
                  size_t data_len, struct wpabuf *buf)
#endif
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_switch_channel(void *priv, struct csa_settings *settings)
{
    struct nl_msg *msg;
    struct nlattr *beacon_csa;
    int ret = -1;
    int csa_off_len = 0;
    int i;
    wifi_interface_info_t *interface;

    interface = (wifi_interface_info_t *)priv;

    wifi_hal_dbg_print( "%s:%d: Channel switch request (cs_count=%u block_tx=%u freq=%d width=%d cf1=%d cf2=%d)\n",
        __func__, __LINE__, settings->cs_count, settings->block_tx, settings->freq_params.freq,
        settings->freq_params.bandwidth, settings->freq_params.center_freq1, settings->freq_params.center_freq2);

    if (settings->counter_offset_beacon[0] && !settings->counter_offset_beacon[1]) {
        csa_off_len = 1;
    } else if (settings->counter_offset_beacon[1] && !settings->counter_offset_beacon[0]) {
        csa_off_len = 1;
        settings->counter_offset_beacon[0] = settings->counter_offset_beacon[1];
        settings->counter_offset_presp[0] = settings->counter_offset_presp[1];
    } else if (settings->counter_offset_beacon[1] && settings->counter_offset_beacon[0]) {
        csa_off_len = 2;
    } else {
        wifi_hal_error_print("%s:%d: No CSA counters provided", __func__, __LINE__);
        return -1;
    }

    if (!settings->beacon_csa.tail) {
        return -1;
    }

    for (i = 0; i < csa_off_len; i++) {
        u16 csa_c_off_bcn = settings->counter_offset_beacon[i];
        u16 csa_c_off_presp = settings->counter_offset_presp[i];

        if ((settings->beacon_csa.tail_len <= csa_c_off_bcn) || (settings->beacon_csa.tail[csa_c_off_bcn] !=
            settings->cs_count)) {
            return -1;
        }

        if (settings->beacon_csa.probe_resp && ((settings->beacon_csa.probe_resp_len <=
            csa_c_off_presp) || (settings->beacon_csa.probe_resp[csa_c_off_presp] != settings->cs_count))) {
            return -1;
        }
    }

    if (!(msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, NL80211_CMD_CHANNEL_SWITCH)) ||
        nla_put_u32(msg, NL80211_ATTR_CH_SWITCH_COUNT, settings->cs_count) ||
        (ret = nl80211_put_freq_params(msg, &settings->freq_params)) ||
        (settings->block_tx && nla_put_flag(msg, NL80211_ATTR_CH_SWITCH_BLOCK_TX))) {
        goto error;
    }

    /* beacon_after params */
    ret = set_beacon_data(msg, &settings->beacon_after);
    if (ret) {
        goto error;
    }

    /* beacon_csa params */
    beacon_csa = nla_nest_start(msg, NL80211_ATTR_CSA_IES);
    if (!beacon_csa) {
        goto fail;
    }

    ret = set_beacon_data(msg, &settings->beacon_csa);
    if (ret) {
        goto error;
    }

    if (nla_put(msg, NL80211_ATTR_CSA_C_OFF_BEACON, csa_off_len * sizeof(u16),
        settings->counter_offset_beacon) || (settings->beacon_csa.probe_resp &&
            nla_put(msg, NL80211_ATTR_CSA_C_OFF_PRESP, csa_off_len * sizeof(u16),
            settings->counter_offset_presp))) {
        goto fail;
    }

    nla_nest_end(msg, beacon_csa);
    ret = send_and_recv(g_wifi_hal.nl_cb, g_wifi_hal.nl, msg, NULL, NULL, NULL, NULL);
    if (ret) {
        wifi_hal_info_print("nl80211: switch_channel failed err=%d (%s)", ret, strerror(-ret));
    }
    return ret;

fail:
    ret = -1;
error:
    nlmsg_free(msg);
    wifi_hal_error_print("nl80211: Could not build channel switch request");
    return ret;
}

int wifi_drv_status(void *priv, char *buf, size_t buflen)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_get_survey(void *priv, unsigned int freq)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

const u8 * wifi_drv_get_macaddr(void *priv)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return NULL;
}

int wifi_drv_update_dh_ie(void *priv, const u8 *peer_mac,
                u16 reason_code, const u8 *ie, size_t ie_len)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_update_ft_ies(void *priv, const u8 *md,
                        const u8 *ies, size_t ies_len)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_stop_ap(void *priv)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_start_radar_detection(void *priv, struct hostapd_freq_params *freq)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_set_p2p_powersave(void *priv, int legacy_ps, int opp_ps, int ctwindow)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

void wifi_drv_poll_client(void *priv, const u8 *own_addr, const u8 *addr, int qos)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
}


void wifi_drv_set_rekey_info(void *priv, const u8 *kek, size_t kek_len,
                   const u8 *kck, size_t kck_len,
                   const u8 *replay_ctr)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
}

int wifi_drv_flush_pmkid(void *priv)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_remove_pmkid(void *priv, struct wpa_pmkid_params *params)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_add_pmkid(void *priv, struct wpa_pmkid_params *params)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

const char * wifi_drv_get_radio_name(void *priv)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_set_param(void *priv, const char *param)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_send_frame(void *priv, const u8 *data, size_t data_len, int encrypt)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_channel_info(void *priv, struct wpa_channel_info *ci)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_signal_poll(void *priv, struct wpa_signal_info *si)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_signal_monitor(void *priv, int threshold, int hysteresis)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

void wifi_drv_resume(void *priv)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
}

int wifi_drv_deinit_p2p_cli(void *priv)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_deinit_ap(void *priv)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_probe_req_report(void *priv, int report)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_cancel_remain_on_channel(void *priv)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_remain_on_channel(void *priv, unsigned int freq, unsigned int duration)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

void wifi_drv_send_action_cancel_wait(void *priv)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
}

int wifi_drv_send_action(void *priv,
                      unsigned int freq,
                      unsigned int wait_time,
                      const u8 *dst, const u8 *src,
                      const u8 *bssid,
                      const u8 *data, size_t data_len,
                      int no_cck)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_set_freq(void *priv, struct hostapd_freq_params *freq)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_read_sta_data(void *priv,
                    struct hostap_sta_driver_data *data,
                    const u8 *addr)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}
#if HOSTAPD_VERSION >= 210 //2.10
static int wifi_drv_send_mlme(void *priv, const u8 *data,
                                          size_t data_len,int noack,
					  unsigned int freq, const u16 *csa_offs,
					  size_t csa_offs_len, int no_encrypt,
					  unsigned int wait)
#else
static int wifi_drv_send_mlme(void *priv, const u8 *data,
                                          size_t data_len, int noack,
                                          unsigned int freq,
                                          const u16 *csa_offs,
                                          size_t csa_offs_len)
#endif
{
    wifi_interface_info_t *interface;
    wifi_vap_info_t *vap;
    wifi_radio_info_t *radio;
    wifi_radio_operationParam_t *radio_param;
    wifi_driver_data_t *drv;
    struct ieee80211_mgmt *mgmt;
    u16 fc;
    int use_cookie = 1;
    int res, interface_freq;
    //mac_addr_str_t mac_str;
    char country[8];

    interface = (wifi_interface_info_t *)priv;
    vap = &interface->vap_info;
    radio = get_radio_by_rdk_index(vap->radio_index);
    radio_param = &radio->oper_param;
    drv = &radio->driver_data;

    get_coutry_str_from_code(radio_param->countryCode, country);

    interface_freq = ieee80211_chan_to_freq(country, radio_param->op_class,
          radio_param->channel);


    mgmt = (struct ieee80211_mgmt *) data;
    fc = le_to_host16(mgmt->frame_control);
    //wifi_hal_dbg_print("nl80211: send_mlme - da= %s noack=%d freq=%u fc=0x%x\n",
    //to_mac_str(mgmt->da, mac_str), noack, freq, fc);

    if (drv->device_ap_sme) {
        if (freq == 0) {
            //wifi_hal_dbg_print("nl80211: Use interface freq=%d\n", interface_freq);
            freq = interface_freq;
        }
        goto send_frame_cmd;
    }
#if 0
    if (WLAN_FC_GET_TYPE(fc) == WLAN_FC_TYPE_MGMT &&
          WLAN_FC_GET_STYPE(fc) == WLAN_FC_STYPE_AUTH) {
        /*
         * Only one of the authentication frame types is encrypted.
         * In order for static WEP encryption to work properly (i.e.,
         * to not encrypt the frame), we need to tell mac80211 about
         * the frames that must not be encrypted.
         */
        u16 auth_alg = le_to_host16(mgmt->u.auth.auth_alg);
        u16 auth_trans = le_to_host16(mgmt->u.auth.auth_transaction);
    }
#endif
    if (freq == 0) {
        //wifi_hal_dbg_print("nl80211: send_mlme - Use interface freq=%u\n", interface_freq);
        freq = interface_freq;
    }

    if (noack || WLAN_FC_GET_TYPE(fc) != WLAN_FC_TYPE_MGMT ||
            WLAN_FC_GET_STYPE(fc) != WLAN_FC_STYPE_ACTION)
          use_cookie = 0;
send_frame_cmd:

    //wifi_hal_dbg_print("nl80211: send_mlme -> send_frame_cmd\n");
    res = nl80211_send_frame_cmd(interface, freq, data, data_len,
              use_cookie, noack, csa_offs, csa_offs_len);

    return res;
}

int wifi_drv_sta_disassoc(void *priv, const u8 *own_addr, const u8 *addr, u16 reason)
{
    wifi_interface_info_t *interface;
    wifi_vap_info_t *vap;
    wifi_radio_info_t *radio;
    //wifi_radio_operationParam_t *radio_param;
    wifi_driver_data_t *drv;
    struct ieee80211_mgmt mgmt;

    interface = (wifi_interface_info_t *)priv;
    vap = &interface->vap_info;
    radio = get_radio_by_rdk_index(vap->radio_index);
    //radio_param = &radio->oper_param;
    drv = &radio->driver_data;
    mac_addr_str_t mac_str;

    wifi_hal_dbg_print("%s:%d: Enter %s %d\n", __func__, __LINE__, to_mac_str(addr, mac_str), reason);

#if 0
    wifi_device_callbacks_t *callbacks;

    callbacks = get_hal_device_callbacks();

    for (int i = 0; i < callbacks->num_disassoc_cbs; i++) {
        if (callbacks->disassoc_cb[i] != NULL) {
            callbacks->disassoc_cb[i](vap->vap_index, to_mac_str(addr, mac_str), 0);
        }
    }
#endif
    if (drv->device_ap_sme) {
        return wifi_sta_remove(interface, addr, 0, reason);
    }

    memset(&mgmt, 0, sizeof(mgmt));
    mgmt.frame_control = IEEE80211_FC(WLAN_FC_TYPE_MGMT,
                                        WLAN_FC_STYPE_DISASSOC);
    memcpy(mgmt.da, addr, ETH_ALEN);
    memcpy(mgmt.sa, own_addr, ETH_ALEN);
    memcpy(mgmt.bssid, own_addr, ETH_ALEN);
    mgmt.u.disassoc.reason_code = host_to_le16(reason);
#if HOSTAPD_VERSION >= 210 //2.10
    return wifi_drv_send_mlme(priv, (u8 *) &mgmt,
                                IEEE80211_HDRLEN + sizeof(mgmt.u.disassoc), 0, 0, NULL, 0, 0, 0);
#else
    return wifi_drv_send_mlme(priv, (u8 *) &mgmt,
                                IEEE80211_HDRLEN + sizeof(mgmt.u.disassoc), 0, 0, NULL, 0);
#endif
}



int wifi_drv_sta_notify_deauth(void *priv, const u8 *own_addr, const u8 *addr, u16 reason)
{
    wifi_interface_info_t *interface;
    wifi_vap_info_t *vap;
    wifi_device_callbacks_t *callbacks;
    mac_addr_str_t mac_str;

    wifi_hal_dbg_print("%s:%d: Enter %s %d\n", __func__, __LINE__, to_mac_str(addr, mac_str), reason);

    interface = (wifi_interface_info_t *)priv;
    vap = &interface->vap_info;

    callbacks = get_hal_device_callbacks();

    for (int i = 0; i < callbacks->num_apDeAuthEvent_cbs; i++) {
        if (callbacks->apDeAuthEvent_cb[i] != NULL) {
            callbacks->apDeAuthEvent_cb[i](vap->vap_index, to_mac_str(addr, mac_str), reason);
        }
    }

    return 0;
}

int wifi_drv_sta_deauth(void *priv, const u8 *own_addr, const u8 *addr, u16 reason)
{
    wifi_interface_info_t *interface;
    wifi_vap_info_t *vap;
    wifi_radio_info_t *radio;
    wifi_radio_operationParam_t *radio_param;
    wifi_driver_data_t *drv;
    struct ieee80211_mgmt mgmt;
    u8 channel;
    int freq;
    char country[8];
    mac_addr_str_t mac_str;

    wifi_hal_dbg_print("%s:%d: Enter %s %d\n", __func__, __LINE__, to_mac_str(addr, mac_str), reason);

    interface = (wifi_interface_info_t *)priv;
    vap = &interface->vap_info;
    radio = get_radio_by_rdk_index(vap->radio_index);
    radio_param = &radio->oper_param;
    drv = &radio->driver_data;

    get_coutry_str_from_code(radio_param->countryCode, country);

    freq = ieee80211_chan_to_freq(country, radio_param->op_class, radio_param->channel);

    if (ieee80211_freq_to_chan(freq, &channel) ==
          HOSTAPD_MODE_IEEE80211AD) {
        /* Deauthentication is not used in DMG/IEEE 802.11ad;
           * disassociate the STA instead. */
        return wifi_drv_sta_disassoc(priv, own_addr, addr, reason);
    }
#if 0
    //TODO: check if mesh, return
    wifi_device_callbacks_t *callbacks;

    callbacks = get_hal_device_callbacks();

    for (int i = 0; i < callbacks->num_apDeAuthEvent_cbs; i++) {
        if (callbacks->apDeAuthEvent_cb[i] != NULL) {
            callbacks->apDeAuthEvent_cb[i](vap->vap_index, to_mac_str(addr, mac_str), reason);
        }
    }
#endif
    if (drv->device_ap_sme) {
        return wifi_sta_remove(interface, addr, 1, reason);
    }

    memset(&mgmt, 0, sizeof(mgmt));
    mgmt.frame_control = IEEE80211_FC(WLAN_FC_TYPE_MGMT,
                                        WLAN_FC_STYPE_DEAUTH);
    memcpy(mgmt.da, addr, ETH_ALEN);
    memcpy(mgmt.sa, own_addr, ETH_ALEN);
    memcpy(mgmt.bssid, own_addr, ETH_ALEN);
    mgmt.u.deauth.reason_code = host_to_le16(reason);
#if HOSTAPD_VERSION >= 210 //2.10
    return wifi_drv_send_mlme(priv, (u8 *) &mgmt,
                                IEEE80211_HDRLEN + sizeof(mgmt.u.disassoc), 0, 0, NULL, 0, 0, 0);
#else
    return wifi_drv_send_mlme(priv, (u8 *) &mgmt,
                              IEEE80211_HDRLEN + sizeof(mgmt.u.deauth), 0, 0, NULL, 0);
#endif
    return 0;
}

int wifi_drv_set_sta_vlan(void *priv, const u8 *addr,
                       const char *ifname, int vlan_id)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_set_tx_queue_params(void *priv, int queue, int aifs,
                    int cw_min, int cw_max, int burst_time)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_set_frag(void *priv, int frag)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_set_rts(void *priv, int rts)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_sta_clear_stats(void *priv, const u8 *addr)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_get_inact_sec(void *priv, const u8 *addr)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_flush(void *priv)
{
    wifi_interface_info_t *interface; 
    struct nl_msg *msg;
    int ret;

    interface = (wifi_interface_info_t *)priv;

    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    wifi_hal_dbg_print("nl80211: flush -> DEL_STATION %s (all)", interface->name);

    if ((msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, 0,
                                    NL80211_CMD_DEL_STATION)) == NULL) {
        wifi_hal_error_print("%s:%d: Failed to create message\n", __func__, __LINE__);
        return -1;
    }

    ret = send_and_recv(g_wifi_hal.nl_cb, g_wifi_hal.nl, msg, NULL, NULL, NULL, NULL);
    if (ret) {
        wifi_hal_error_print("nl80211: Station flush failed: ret=%d (%s)", ret, strerror(-ret));
    }
    return ret;
}

int wifi_drv_get_seqnum(const char *iface, void *priv, const u8 *addr, int idx, u8 *seq)
{
    wifi_interface_info_t *interface;
    struct nl_msg *msg;

    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);

    interface = (wifi_interface_info_t *)priv;

    msg = nl80211_ifindex_msg(g_wifi_hal.nl80211_id, interface, 0,
                                NL80211_CMD_GET_KEY, if_nametoindex(iface));
    if (!msg ||
        (addr && nla_put(msg, NL80211_ATTR_MAC, ETH_ALEN, addr)) ||
        nla_put_u8(msg, NL80211_ATTR_KEY_IDX, idx)) {

        nlmsg_free(msg);
        return -ENOBUFS;
    }

    memset(seq, 0, 6);

    return send_and_recv(g_wifi_hal.nl_cb, g_wifi_hal.nl, msg, get_key_handler, seq, NULL, NULL);
}

int wifi_drv_set_wds_sta(void *priv, const u8 *addr, int aid, int val,
                const char *bridge_ifname, char *ifname_wds)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_sta_set_airtime_weight(void *priv, const u8 *addr, unsigned int weight)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_sta_set_flags(void *priv, const u8 *addr,
                        unsigned int total_flags,
                        unsigned int flags_or,
                        unsigned int flags_and)
{
    wifi_interface_info_t *interface;
    struct nl_msg *msg;
    struct nlattr *flags;
    struct nl80211_sta_flag_update upd;
    mac_addr_str_t mac_str;

    interface = (wifi_interface_info_t *)priv;

    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);

    wifi_hal_info_print("nl80211: Set STA flags - ifname=%s addr=%s" 
          " total_flags=0x%x flags_or=0x%x flags_and=0x%x authorized=%d\n",
          interface->name, to_mac_str(addr, mac_str), total_flags, flags_or, flags_and,
          !!(total_flags & WPA_STA_AUTHORIZED));

    if (!!(total_flags & WPA_STA_AUTHORIZED)) {
        nl80211_read_sta_data(interface, addr);
    }

    if (!(msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, NL80211_CMD_SET_STATION)) ||
          nla_put(msg, NL80211_ATTR_MAC, ETH_ALEN, addr))
    {
        goto fail;
    }

    /*
     * Backwards compatibility version using NL80211_ATTR_STA_FLAGS. This
     * can be removed eventually.
     */
    flags = nla_nest_start(msg, NL80211_ATTR_STA_FLAGS);
    if (!flags ||
        ((total_flags & WPA_STA_AUTHORIZED) &&
         nla_put_flag(msg, NL80211_STA_FLAG_AUTHORIZED)) ||
        ((total_flags & WPA_STA_WMM) &&
         nla_put_flag(msg, NL80211_STA_FLAG_WME)) ||
        ((total_flags & WPA_STA_SHORT_PREAMBLE) &&
         nla_put_flag(msg, NL80211_STA_FLAG_SHORT_PREAMBLE)) ||
        ((total_flags & WPA_STA_MFP) &&
         nla_put_flag(msg, NL80211_STA_FLAG_MFP)) ||
        ((total_flags & WPA_STA_TDLS_PEER) &&
         nla_put_flag(msg, NL80211_STA_FLAG_TDLS_PEER))) {
        goto fail;
    }

    nla_nest_end(msg, flags);

    os_memset(&upd, 0, sizeof(upd));
    upd.mask = sta_flags_nl80211(flags_or | ~flags_and);
    upd.set = sta_flags_nl80211(flags_or);
    if (nla_put(msg, NL80211_ATTR_STA_FLAGS2, sizeof(upd), &upd)) {
        goto fail;
    }

    return send_and_recv(g_wifi_hal.nl_cb, g_wifi_hal.nl, msg, NULL, NULL, NULL, NULL);
fail:
    nlmsg_free(msg);
    return -ENOBUFS;
}

int wifi_drv_hapd_send_eapol(
    void *priv, const u8 *addr, const u8 *data,
    size_t data_len, int encrypt, const u8 *own_addr, u32 flags)
{
    unsigned char buff[2048];
    struct ieee8023_hdr *eth_hdr;
    wifi_interface_info_t *interface;
    wifi_vap_info_t *vap;
    mac_addr_str_t mac_str;

    interface = (wifi_interface_info_t *)priv;
    vap = &interface->vap_info;

    wifi_hal_info_print("%s:%d: Sending eapol to sta:%s on interface:%s\n", __func__, __LINE__, 
        to_mac_str(addr, mac_str), interface->name);

    eth_hdr = (struct ieee8023_hdr *)buff;
    memcpy(eth_hdr->src, own_addr, sizeof(mac_address_t));
    memcpy(eth_hdr->dest, addr, sizeof(mac_address_t));
    eth_hdr->ethertype = host_to_be16(ETH_P_EAPOL);
    memcpy(buff + sizeof(struct ieee8023_hdr), data, data_len);
    
    //my_print_hex_dump(data_len + sizeof(struct ieee8023_hdr), buff);
    if (send((vap->vap_mode == wifi_vap_mode_ap) ? interface->u.ap.br_sock_fd:interface->u.sta.sta_sock_fd, 
            buff, data_len + sizeof(struct ieee8023_hdr), flags) < 0) {
        wifi_hal_error_print("%s:%d: eapol send failed\n", __func__, __LINE__);
        return -1;
    }

    return 0;
}

int wifi_drv_sta_remove(void *priv, const u8 *addr)
{
    wifi_interface_info_t *interface;

    interface = (wifi_interface_info_t *)priv;

    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);

    return wifi_sta_remove(interface, addr, -1, 0);
}

int wifi_drv_sta_add(void *priv, struct hostapd_sta_add_params *params)
{
    wifi_interface_info_t *interface;
    wifi_vap_info_t *vap;
    wifi_radio_info_t *radio;
    //wifi_radio_operationParam_t *radio_param;
    wifi_driver_data_t *drv;
    struct nl_msg *msg;
    struct nl80211_sta_flag_update upd;
    mac_addr_str_t mac_str;
    int ret = -ENOBUFS;

    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);

    interface = (wifi_interface_info_t *)priv;
    vap = &interface->vap_info;
    radio = get_radio_by_rdk_index(vap->radio_index);
    //radio_param = &radio->oper_param;
    drv = &radio->driver_data;

    if ((params->flags & WPA_STA_TDLS_PEER) &&
          !(drv->capa.flags & WPA_DRIVER_FLAGS_TDLS_SUPPORT)) {
        return -EOPNOTSUPP;
    }

    wifi_hal_info_print("nl80211: %s STA %s" , params->set ? "Set" : "Add", to_mac_str(params->addr, mac_str));
    msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, params->set ? NL80211_CMD_SET_STATION :
          NL80211_CMD_NEW_STATION);
    if (!msg || nla_put(msg, NL80211_ATTR_MAC, ETH_ALEN, params->addr)) {
        goto fail;
    }

    /*
     * Set the below properties only in one of the following cases:
     * 1. New station is added, already associated.
     * 2. Set WPA_STA_TDLS_PEER station.
     * 3. Set an already added unassociated station, if driver supports
     * full AP client state. (Set these properties after station became
     * associated will be rejected by the driver).
     */
    if (!params->set || (params->flags & WPA_STA_TDLS_PEER) ||
          (params->set && FULL_AP_CLIENT_STATE_SUPP(drv->capa.flags) &&
           (params->flags & WPA_STA_ASSOCIATED))) {

        wpa_hexdump(MSG_DEBUG, "  * supported rates",
                    params->supp_rates, params->supp_rates_len);
        wifi_hal_dbg_print("  * capability=0x%x", params->capability);
        if (nla_put(msg, NL80211_ATTR_STA_SUPPORTED_RATES,
                    params->supp_rates_len, params->supp_rates) ||
            nla_put_u16(msg, NL80211_ATTR_STA_CAPABILITY,
                        params->capability)) {
            goto fail;
        }

        if (params->ht_capabilities) {
            wpa_hexdump(MSG_DEBUG, "  * ht_capabilities",
                        (u8 *) params->ht_capabilities,
                        sizeof(*params->ht_capabilities));
            if (nla_put(msg, NL80211_ATTR_HT_CAPABILITY,
                        sizeof(*params->ht_capabilities),
                        params->ht_capabilities)) {
                goto fail;
            }
        }

        if (params->vht_capabilities) {
            wpa_hexdump(MSG_DEBUG, "  * vht_capabilities",
                        (u8 *) params->vht_capabilities,
                        sizeof(*params->vht_capabilities));
            if (nla_put(msg, NL80211_ATTR_VHT_CAPABILITY,
                        sizeof(*params->vht_capabilities),
                        params->vht_capabilities)) {
                goto fail;
            }
        }
#if 0
        if (params->he_capab) {
            wpa_hexdump(MSG_DEBUG, "  * he_capab",
                        params->he_capab, params->he_capab_len);
            if (nla_put(msg, NL80211_ATTR_HE_CAPABILITY,
                        params->he_capab_len, params->he_capab)) {
                goto fail;
            }
        }
#endif
        if (params->ext_capab) {
            wpa_hexdump(MSG_DEBUG, "  * ext_capab",
                        params->ext_capab, params->ext_capab_len);
            if (nla_put(msg, NL80211_ATTR_STA_EXT_CAPABILITY,
                        params->ext_capab_len, params->ext_capab)) {
                goto fail;
            }
        }

        if ( nla_put_u8(msg, NL80211_ATTR_STA_SUPPORT_P2P_PS,
                        params->support_p2p_ps ?
                        NL80211_P2P_PS_SUPPORTED :
                        NL80211_P2P_PS_UNSUPPORTED)) {
            goto fail;
        }
    }
    if (!params->set) {
        if (params->aid) {
            wifi_hal_dbg_print("  * aid=%u", params->aid);
            if (nla_put_u16(msg, NL80211_ATTR_STA_AID, params->aid)) {
                goto fail;
            }
        } else {
            /*
                   * cfg80211 validates that AID is non-zero, so we have
                   * to make this a non-zero value for the TDLS case where
                   * a dummy STA entry is used for now and for a station
                   * that is still not associated.
                   */
            wifi_hal_dbg_print("  * aid=1 (%s workaround)",
                               (params->flags & WPA_STA_TDLS_PEER) ?
                               "TDLS" : "UNASSOC_STA");
            if (nla_put_u16(msg, NL80211_ATTR_STA_AID, 1)) {
                goto fail;
            }
        }
        wifi_hal_dbg_print("  * listen_interval=%u",
                           params->listen_interval);
        if (nla_put_u16(msg, NL80211_ATTR_STA_LISTEN_INTERVAL,
                        params->listen_interval)) {
            goto fail;
        }
    } else if (params->aid && (params->flags & WPA_STA_TDLS_PEER)) {
        wifi_hal_dbg_print("  * peer_aid=%u", params->aid);
        if (nla_put_u16(msg, NL80211_ATTR_PEER_AID, params->aid)) {
            goto fail;
        }
    } else if (FULL_AP_CLIENT_STATE_SUPP(drv->capa.flags) &&
               (params->flags & WPA_STA_ASSOCIATED)) {
        wifi_hal_dbg_print("  * aid=%u", params->aid);
        wifi_hal_dbg_print("  * listen_interval=%u",
                           params->listen_interval);
        if (nla_put_u16(msg, NL80211_ATTR_STA_AID, params->aid) ||
            nla_put_u16(msg, NL80211_ATTR_STA_LISTEN_INTERVAL,
                        params->listen_interval)) {
            goto fail;
        }
    }

    if (params->vht_opmode_enabled) {
        wifi_hal_dbg_print("  * opmode=%u", params->vht_opmode);
        if (nla_put_u8(msg, NL80211_ATTR_OPMODE_NOTIF,
                       params->vht_opmode)) {
            goto fail;
        }
    }

    if (params->supp_channels) {
        wpa_hexdump(MSG_DEBUG, "  * supported channels",
                    params->supp_channels, params->supp_channels_len);
        if (nla_put(msg, NL80211_ATTR_STA_SUPPORTED_CHANNELS,
                    params->supp_channels_len, params->supp_channels)) {
            goto fail;
        }
    }

    if (params->supp_oper_classes) {
        wpa_hexdump(MSG_DEBUG, "  * supported operating classes",
                    params->supp_oper_classes,
                    params->supp_oper_classes_len);
        if (nla_put(msg, NL80211_ATTR_STA_SUPPORTED_OPER_CLASSES,
                    params->supp_oper_classes_len,
                    params->supp_oper_classes)) {
            goto fail;
        }
    }

    os_memset(&upd, 0, sizeof(upd));
    upd.set = sta_flags_nl80211(params->flags);
    upd.mask = upd.set | sta_flags_nl80211(params->flags_mask);

    /*
     * If the driver doesn't support full AP client state, ignore ASSOC/AUTH
     * flags, as nl80211 driver moves a new station, by default, into
     * associated state.
     *
     * On the other hand, if the driver supports that feature and the
     * station is added in unauthenticated state, set the
     * authenticated/associated bits in the mask to prevent moving this
     * station to associated state before it is actually associated.
     *
     * This is irrelevant for mesh mode where the station is added to the
     * driver as authenticated already, and ASSOCIATED isn't part of the
     * nl80211 API.
     */
    if (!FULL_AP_CLIENT_STATE_SUPP(drv->capa.flags)) {
        wifi_hal_dbg_print( "nl80211: Ignore ASSOC/AUTH flags since driver doesn't support full AP client state");
        upd.mask &= ~(BIT(NL80211_STA_FLAG_ASSOCIATED) |
                      BIT(NL80211_STA_FLAG_AUTHENTICATED));
    } else if (!params->set &&
               !(params->flags & WPA_STA_TDLS_PEER)) {
        if (!(params->flags & WPA_STA_AUTHENTICATED))
          upd.mask |= BIT(NL80211_STA_FLAG_AUTHENTICATED);
        if (!(params->flags & WPA_STA_ASSOCIATED))
          upd.mask |= BIT(NL80211_STA_FLAG_ASSOCIATED);
    }

    wifi_hal_dbg_print("  * flags set=0x%x mask=0x%x",
          upd.set, upd.mask);
    if (nla_put(msg, NL80211_ATTR_STA_FLAGS2, sizeof(upd), &upd)) {
        goto fail;
    }

    if ((!params->set || (params->flags & WPA_STA_TDLS_PEER) ||
          FULL_AP_CLIENT_STATE_SUPP(drv->capa.flags)) &&
          (params->flags & WPA_STA_WMM)) {
        struct nlattr *wme = nla_nest_start(msg, NL80211_ATTR_STA_WME);

        wifi_hal_dbg_print("  * qosinfo=0x%x", params->qosinfo);
        if (!wme ||
            nla_put_u8(msg, NL80211_STA_WME_UAPSD_QUEUES,
                       params->qosinfo & WMM_QOSINFO_STA_AC_MASK) ||
            nla_put_u8(msg, NL80211_STA_WME_MAX_SP,
                       (params->qosinfo >> WMM_QOSINFO_STA_SP_SHIFT) &
                       WMM_QOSINFO_STA_SP_MASK)) {
            goto fail;
        }
        nla_nest_end(msg, wme);
    }

    ret = send_and_recv(g_wifi_hal.nl_cb, g_wifi_hal.nl, msg, NULL, NULL, NULL, NULL);
    msg = NULL;
    if (ret) {
        wifi_hal_info_print("nl80211: NL80211_CMD_%s_STATION "
                           "result: %d (%s)", params->set ? "SET" : "NEW", ret,
                           strerror(-ret));
    }
    if (ret == -EEXIST) {
        ret = 0;
    }
fail:
    nlmsg_free(msg);
    return ret;
}

struct hostapd_hw_modes *
wifi_drv_get_hw_feature_data(void *priv, u16 *num_modes, u16 *flags, u8 *dfs_domain)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return NULL;
}

int wifi_drv_if_remove(void *priv, enum wpa_driver_if_type type, const char *ifname)
{
    wifi_interface_info_t *interface;
    wifi_vap_info_t *vap;

    interface = (wifi_interface_info_t *)priv; 
    vap = &interface->vap_info;

    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);

    if ((interface->vap_configured == true)) {
        if (vap->vap_mode == wifi_vap_mode_ap) {
            close(interface->u.ap.br_sock_fd);
        } else if (vap->vap_mode == wifi_vap_mode_sta) {
            close(interface->u.sta.sta_sock_fd);
        }

        interface->vap_configured = false;
    }

    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_if_add(void *priv, enum wpa_driver_if_type type,
                     const char *ifname, const u8 *addr,
                     void *bss_ctx, void **drv_priv,
                     char *force_ifname, u8 *if_addr,
                     const char *bridge, int use_existing,
                     int setup_ap)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_set_acl(void *priv, struct hostapd_acl_params *params)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);

    wifi_interface_info_t *interface;
    struct nl_msg *msg;
    struct nl_msg *acl;
    unsigned int i;
    int ret;
    size_t acl_nla_sz, acl_nlmsg_sz, nla_sz, nlmsg_sz;

    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);

    interface = (wifi_interface_info_t *)priv;
    acl_nla_sz = nla_total_size(ETH_ALEN) * params->num_mac_acl;
    acl_nlmsg_sz = nlmsg_total_size(acl_nla_sz);
    acl = nlmsg_alloc_size(acl_nlmsg_sz);
    if (!acl) {
        return -ENOMEM;
    }
    for (i = 0; i < params->num_mac_acl; i++) {
        if (nla_put(acl, i + 1, ETH_ALEN, params->mac_acl[i].addr)) {
            nlmsg_free(acl);
            return -ENOMEM;
        }
    }

    /*
     * genetlink message header (Length of user header is 0) +
     * u32 attr: NL80211_ATTR_IFINDEX +
     * u32 attr: NL80211_ATTR_ACL_POLICY +
     * nested acl attr
     */
    nla_sz = GENL_HDRLEN +
          nla_total_size(4) * 2 +
          nla_total_size(acl_nla_sz);
    nlmsg_sz = nlmsg_total_size(nla_sz);
    if (!(msg = nl80211_cmd_msg_build(g_wifi_hal.nl80211_id, interface, 0,
                                      NL80211_CMD_SET_MAC_ACL, nlmsg_alloc_size(nlmsg_sz))) ||
        nla_put_u32(msg, NL80211_ATTR_ACL_POLICY, params->acl_policy ?
                    NL80211_ACL_POLICY_DENY_UNLESS_LISTED :
                    NL80211_ACL_POLICY_ACCEPT_UNLESS_LISTED) ||
        nla_put_nested(msg, NL80211_ATTR_MAC_ADDRS, acl)) {

        nlmsg_free(msg);
        nlmsg_free(acl);
        return -ENOMEM;
    }
    nlmsg_free(acl);

    ret = send_and_recv(g_wifi_hal.nl_cb, g_wifi_hal.nl, msg, NULL, NULL, NULL, NULL);
    if (ret) {
        wifi_hal_error_print("nl80211: Failed to set MAC ACL: %d (%s)",
                           ret, strerror(-ret));
    }

    return ret;
}

static int nl80211_put_beacon_rate(struct nl_msg *msg, const u64 flags,
                   struct wpa_driver_ap_params *params)
{
    struct nlattr *bands, *band;
    struct nl80211_txrate_vht vht_rate;

    if (!params->freq ||
        (params->beacon_rate == 0 &&
         params->rate_type == BEACON_RATE_LEGACY))
        return 0;

    bands = nla_nest_start(msg, NL80211_ATTR_TX_RATES);
    if (!bands)
        return -1;

    switch (params->freq->mode) {
    case HOSTAPD_MODE_IEEE80211B:
    case HOSTAPD_MODE_IEEE80211G:
        band = nla_nest_start(msg, NL80211_BAND_2GHZ);
        break;
    case HOSTAPD_MODE_IEEE80211A:
        band = nla_nest_start(msg, NL80211_BAND_5GHZ);
        break;
    case HOSTAPD_MODE_IEEE80211AD:
        band = nla_nest_start(msg, NL80211_BAND_60GHZ);
        break;
    default:
        return 0;
    }

    if (!band)
        return -1;

    memset(&vht_rate, 0, sizeof(vht_rate));
    switch (params->rate_type) {
    case BEACON_RATE_LEGACY:
        if (!(flags & WPA_DRIVER_FLAGS_BEACON_RATE_LEGACY)) {
            wifi_hal_error_print("nl80211: Driver does not support setting Beacon frame rate (legacy)\n");
            return -1;
        }

        if (nla_put_u8(msg, NL80211_TXRATE_LEGACY,
                   (u8) params->beacon_rate / 5) ||
            nla_put(msg, NL80211_TXRATE_HT, 0, NULL) ||
            (params->freq->vht_enabled &&
             nla_put(msg, NL80211_TXRATE_VHT, sizeof(vht_rate),
                 &vht_rate)))
            return -1;

        wifi_hal_dbg_print(" * beacon_rate = legacy:%u (* 100 kbps)\n", params->beacon_rate);
        break;
    case BEACON_RATE_HT:
        if (!(flags & WPA_DRIVER_FLAGS_BEACON_RATE_HT)) {
            wifi_hal_error_print("nl80211: Driver does not support setting Beacon frame rate (HT)\n");
            return -1;
        }
        if (nla_put(msg, NL80211_TXRATE_LEGACY, 0, NULL) ||
            nla_put_u8(msg, NL80211_TXRATE_HT, params->beacon_rate) ||
            (params->freq->vht_enabled &&
             nla_put(msg, NL80211_TXRATE_VHT, sizeof(vht_rate),
                 &vht_rate)))
            return -1;
        wifi_hal_dbg_print(" * beacon_rate = HT-MCS %u\n", params->beacon_rate);
        break;
    case BEACON_RATE_VHT:
        if (!(flags & WPA_DRIVER_FLAGS_BEACON_RATE_VHT)) {
            wifi_hal_error_print("nl80211: Driver does not support setting Beacon frame rate (VHT)\n");
            return -1;
        }
        vht_rate.mcs[0] = BIT(params->beacon_rate);
        if (nla_put(msg, NL80211_TXRATE_LEGACY, 0, NULL))
            return -1;
        if (nla_put(msg, NL80211_TXRATE_HT, 0, NULL))
            return -1;
        if (nla_put(msg, NL80211_TXRATE_VHT, sizeof(vht_rate),
                &vht_rate))
            return -1;
        wifi_hal_dbg_print(" * beacon_rate = VHT-MCS %u\n", params->beacon_rate);
        break;
#if HOSTAPD_VERSION >= 210
    case BEACON_RATE_HE:
        wifi_hal_dbg_print("nl80211: BEACON_RATE_HE received\n");
        break;
#endif
    default:
        wifi_hal_info_print("nl80211: case not handled %d \n", params->rate_type);
    }

    nla_nest_end(msg, band);
    nla_nest_end(msg, bands);

    return 0;
}

static u32 wpa_alg_to_cipher_suite(enum wpa_alg alg, size_t key_len)
{
    switch (alg) {
    case WPA_ALG_WEP:
        if (key_len == 5)
            return RSN_CIPHER_SUITE_WEP40;
        return RSN_CIPHER_SUITE_WEP104;
    case WPA_ALG_TKIP:
        return RSN_CIPHER_SUITE_TKIP;
    case WPA_ALG_CCMP:
        return RSN_CIPHER_SUITE_CCMP;
    case WPA_ALG_GCMP:
        return RSN_CIPHER_SUITE_GCMP;
    case WPA_ALG_CCMP_256:
        return RSN_CIPHER_SUITE_CCMP_256;
    case WPA_ALG_GCMP_256:
        return RSN_CIPHER_SUITE_GCMP_256;
#if HOSTAPD_VERSION >= 210 //2.10
    case WPA_ALG_BIP_CMAC_128:
#else
    case WPA_ALG_IGTK:
#endif
        return RSN_CIPHER_SUITE_AES_128_CMAC;
    case WPA_ALG_BIP_GMAC_128:
        return RSN_CIPHER_SUITE_BIP_GMAC_128;
    case WPA_ALG_BIP_GMAC_256:
        return RSN_CIPHER_SUITE_BIP_GMAC_256;
    case WPA_ALG_BIP_CMAC_256:
        return RSN_CIPHER_SUITE_BIP_CMAC_256;
    case WPA_ALG_SMS4:
        return RSN_CIPHER_SUITE_SMS4;
    case WPA_ALG_KRK:
        return RSN_CIPHER_SUITE_KRK;
#if HOSTAPD_VERSION < 210 //2.10
    case WPA_ALG_PMK:
#endif
    case WPA_ALG_NONE:
        wpa_printf(MSG_ERROR, "nl80211: Unexpected encryption algorithm %d",
               alg);
        return 0;
    }

    wpa_printf(MSG_ERROR, "nl80211: Unsupported encryption algorithm %d",
           alg);
    return 0;
}

static u32 wpa_cipher_to_cipher_suite(unsigned int cipher)
{
    switch (cipher) {
    case WPA_CIPHER_CCMP_256:
        return RSN_CIPHER_SUITE_CCMP_256;
    case WPA_CIPHER_GCMP_256:
        return RSN_CIPHER_SUITE_GCMP_256;
    case WPA_CIPHER_CCMP:
        return RSN_CIPHER_SUITE_CCMP;
    case WPA_CIPHER_GCMP:
        return RSN_CIPHER_SUITE_GCMP;
    case WPA_CIPHER_TKIP:
        return RSN_CIPHER_SUITE_TKIP;
    case WPA_CIPHER_WEP104:
        return RSN_CIPHER_SUITE_WEP104;
    case WPA_CIPHER_WEP40:
        return RSN_CIPHER_SUITE_WEP40;
    case WPA_CIPHER_GTK_NOT_USED:
        return RSN_CIPHER_SUITE_NO_GROUP_ADDRESSED;
    }

    return 0;
}


static int wpa_cipher_to_cipher_suites(unsigned int ciphers, u32 suites[],
                       int max_suites)
{
    int num_suites = 0;

    if (num_suites < max_suites && ciphers & WPA_CIPHER_CCMP_256)
        suites[num_suites++] = RSN_CIPHER_SUITE_CCMP_256;
    if (num_suites < max_suites && ciphers & WPA_CIPHER_GCMP_256)
        suites[num_suites++] = RSN_CIPHER_SUITE_GCMP_256;
    if (num_suites < max_suites && ciphers & WPA_CIPHER_CCMP)
        suites[num_suites++] = RSN_CIPHER_SUITE_CCMP;
    if (num_suites < max_suites && ciphers & WPA_CIPHER_GCMP)
        suites[num_suites++] = RSN_CIPHER_SUITE_GCMP;
    if (num_suites < max_suites && ciphers & WPA_CIPHER_TKIP)
        suites[num_suites++] = RSN_CIPHER_SUITE_TKIP;
    if (num_suites < max_suites && ciphers & WPA_CIPHER_WEP104)
        suites[num_suites++] = RSN_CIPHER_SUITE_WEP104;
    if (num_suites < max_suites && ciphers & WPA_CIPHER_WEP40)
        suites[num_suites++] = RSN_CIPHER_SUITE_WEP40;

    return num_suites;
}

int set_bss_param(void *priv, struct wpa_driver_ap_params *params)
{
    struct nl_msg *msg;
    int ret;
    wifi_interface_info_t *interface;
    interface = (wifi_interface_info_t *)priv;

    if ((msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, NL80211_CMD_SET_BSS)) == NULL) {
        wifi_hal_error_print("%s:%d: Failed to create message\n", __func__, __LINE__);
        return -1;
    }
    nla_put_u8(msg, NL80211_ATTR_AP_ISOLATE, params->isolate);
    wifi_hal_dbg_print("%s:%d: Set AP isolate:%d \r\n", __func__, __LINE__, params->isolate);
    ret = send_and_recv(g_wifi_hal.nl_cb, g_wifi_hal.nl, msg, NULL, NULL, NULL, NULL);
    if (ret != 0) {
        wifi_hal_error_print("%s:%d: Failed to set bss for interface: %s error: %s\n", __func__, __LINE__, interface->name, strerror(-ret));
        return -1;
    }

    return 0;
}

int wifi_drv_set_ap(void *priv, struct wpa_driver_ap_params *params)
{
    struct nl_msg *msg;
    int ret;
    int num_suites;
#ifndef HOSTAPD_2_10
    int smps_mode;
#endif
    u32 suites[10], suite;
    u32 ver;
    wifi_interface_info_t *interface;
    wifi_driver_data_t *drv;
    wifi_vap_info_t *vap;
    wifi_radio_info_t *radio;
    wifi_radio_operationParam_t *radio_param;
    char country[8];
    int beacon_set;
    u8 cmd = NL80211_CMD_NEW_BEACON;

    interface = (wifi_interface_info_t *)priv;
    vap = &interface->vap_info;
    radio = get_radio_by_rdk_index(vap->radio_index);
    radio_param = &radio->oper_param;

    drv = &radio->driver_data;

    beacon_set = params->reenable ? 0 : interface->beacon_set;

    wifi_hal_dbg_print("%s:%d:Enter, interface name:%s vap index:%d radio index:%d beascon_set %d\n", __func__, __LINE__,
        interface->name, vap->vap_index, radio->index, beacon_set);

    if (beacon_set) {
        cmd = NL80211_CMD_SET_BEACON;
    }

    if ((msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, cmd)) == NULL) {
        wifi_hal_error_print("%s:%d: Failed to create message\n", __func__, __LINE__);
        return -1;
    }

    //wifi_hal_dbg_print("%s:%d: beacon head\n", __func__, __LINE__);
    //my_print_hex_dump(params->head_len, params->head);
    //wifi_hal_dbg_print("%s:%d: beacon tail\n", __func__, __LINE__);
    //my_print_hex_dump(params->tail_len, params->tail);

    nla_put(msg, NL80211_ATTR_BEACON_HEAD, params->head_len, params->head);
    nla_put(msg, NL80211_ATTR_BEACON_TAIL, params->tail_len, params->tail);
    if (params->beacon_int > 0) {
        nla_put_u32(msg, NL80211_ATTR_BEACON_INTERVAL, params->beacon_int);
    }
    nl80211_put_beacon_rate(msg, drv->capa.flags, params);
    if (params->dtim_period > 0) {
        nla_put_u32(msg, NL80211_ATTR_DTIM_PERIOD, params->dtim_period);
    }
    nla_put(msg, NL80211_ATTR_SSID, params->ssid_len, params->ssid);
    if (params->proberesp && params->proberesp_len) {
        //wifi_hal_dbg_print("%s:%d: probe response (offload)\n", __func__, __LINE__);
        //my_print_hex_dump(params->proberesp_len, params->proberesp);
        nla_put(msg, NL80211_ATTR_PROBE_RESP, params->proberesp_len, params->proberesp);
    }

    switch (params->hide_ssid) {
        case NO_SSID_HIDING:
            nla_put_u32(msg, NL80211_ATTR_HIDDEN_SSID, NL80211_HIDDEN_SSID_NOT_IN_USE);
            break;

        case HIDDEN_SSID_ZERO_LEN:
            nla_put_u32(msg, NL80211_ATTR_HIDDEN_SSID, NL80211_HIDDEN_SSID_ZERO_LEN);
            break;
    
        case HIDDEN_SSID_ZERO_CONTENTS:
            nla_put_u32(msg, NL80211_ATTR_HIDDEN_SSID, NL80211_HIDDEN_SSID_ZERO_CONTENTS);
            break;
    }

    if (params->privacy) {
        nla_put_flag(msg, NL80211_ATTR_PRIVACY);
    }

    if ((params->auth_algs & (WPA_AUTH_ALG_OPEN | WPA_AUTH_ALG_SHARED)) ==
        (WPA_AUTH_ALG_OPEN | WPA_AUTH_ALG_SHARED)) {
        /* Leave out the attribute */
    } else if (params->auth_algs & WPA_AUTH_ALG_SHARED) {
        nla_put_u32(msg, NL80211_ATTR_AUTH_TYPE, NL80211_AUTHTYPE_SHARED_KEY);
    } else {
        nla_put_u32(msg, NL80211_ATTR_AUTH_TYPE, NL80211_AUTHTYPE_OPEN_SYSTEM);
    }

    ver = 0;
    if (params->wpa_version & WPA_PROTO_WPA)
        ver |= NL80211_WPA_VERSION_1;
    if (params->wpa_version & WPA_PROTO_RSN)
        ver |= NL80211_WPA_VERSION_2;
    if (ver) {
        nla_put_u32(msg, NL80211_ATTR_WPA_VERSIONS, ver);
    }
    
    num_suites = 0;
    if (params->key_mgmt_suites & WPA_KEY_MGMT_IEEE8021X)
        suites[num_suites++] = RSN_AUTH_KEY_MGMT_UNSPEC_802_1X;
    if (params->key_mgmt_suites & WPA_KEY_MGMT_PSK)
        suites[num_suites++] = RSN_AUTH_KEY_MGMT_PSK_OVER_802_1X;
    if (num_suites) {
        nla_put(msg, NL80211_ATTR_AKM_SUITES, num_suites * sizeof(u32), suites);
    }

    if (params->key_mgmt_suites & WPA_KEY_MGMT_IEEE8021X_NO_WPA &&
        (!params->pairwise_ciphers ||
         params->pairwise_ciphers & (WPA_CIPHER_WEP104 | WPA_CIPHER_WEP40))) {
        nla_put_u16(msg, NL80211_ATTR_CONTROL_PORT_ETHERTYPE, ETH_P_PAE);
        nla_put_flag(msg, NL80211_ATTR_CONTROL_PORT_NO_ENCRYPT);    
    }

    if (drv->device_ap_sme && (params->key_mgmt_suites & WPA_KEY_MGMT_SAE)) {
        nla_put_flag(msg, NL80211_ATTR_EXTERNAL_AUTH_SUPPORT);
    }
    
    num_suites = wpa_cipher_to_cipher_suites(params->pairwise_ciphers,
                         suites, ARRAY_SIZE(suites));
    if (num_suites) {
        nla_put(msg, NL80211_ATTR_CIPHER_SUITES_PAIRWISE, num_suites * sizeof(u32), suites);
    }

    suite = wpa_cipher_to_cipher_suite(params->group_cipher);
    if (suite) {
       nla_put_u32(msg, NL80211_ATTR_CIPHER_SUITE_GROUP, suite); 
    }

#if HOSTAPD_VERSION < 210 //2.10
    if (params->ht_opmode != -1) {
        switch (params->smps_mode) {
            case HT_CAP_INFO_SMPS_DYNAMIC:
                smps_mode = NL80211_SMPS_DYNAMIC;
                break;

            case HT_CAP_INFO_SMPS_STATIC:
                smps_mode = NL80211_SMPS_STATIC;
                break;

            default:
                /* invalid - fallback to smps off */
            case HT_CAP_INFO_SMPS_DISABLED:
                smps_mode = NL80211_SMPS_OFF;
                break;
        }
        nla_put_u8(msg, NL80211_ATTR_SMPS_MODE, smps_mode);
    }
#endif

    if (params->beacon_ies) {
        nla_put(msg, NL80211_ATTR_IE, wpabuf_len(params->beacon_ies), wpabuf_head(params->beacon_ies));
    }
    if (params->proberesp_ies) {
        nla_put(msg, NL80211_ATTR_IE_PROBE_RESP, wpabuf_len(params->proberesp_ies), wpabuf_head(params->proberesp_ies));
    }

    if (params->assocresp_ies) {
        nla_put(msg, NL80211_ATTR_IE_ASSOC_RESP, wpabuf_len(params->assocresp_ies), wpabuf_head(params->assocresp_ies));
    }

    if (drv->capa.flags & WPA_DRIVER_FLAGS_INACTIVITY_TIMER)  {
        nla_put_u16(msg, NL80211_ATTR_INACTIVITY_TIMEOUT, params->ap_max_inactivity);
    }

    get_coutry_str_from_code(radio_param->countryCode, country);

    if (beacon_set == 0) {
        nl80211_fill_chandef(msg, radio, interface);
    }

    ret = send_and_recv(g_wifi_hal.nl_cb, g_wifi_hal.nl, msg, beacon_info_handler, &g_wifi_hal, NULL, NULL);
    if (ret != 0) {
        wifi_hal_error_print("%s:%d: Failed to set beacon parameter for interface: %s error: %s\n", __func__, __LINE__, interface->name, strerror(-ret));
        return -1;
    }

    interface->beacon_set = 1;

    set_bss_param(priv, params);

    return 0;
}

int wifi_drv_get_country(void *priv, char *alpha2)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_set_country(void *priv, const char *alpha2_arg)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_set_supp_port(void *priv, int authorized)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);

    wifi_interface_info_t *interface;
    wifi_bss_info_t *backhaul;
    struct nl_msg *msg;
    struct nl80211_sta_flag_update upd;
    int ret;

    interface = (wifi_interface_info_t *)priv;
    backhaul = &interface->u.sta.backhaul;

    os_memset(&upd, 0, sizeof(upd));
    upd.mask = BIT(NL80211_STA_FLAG_AUTHORIZED);
    if (authorized)
        upd.set = BIT(NL80211_STA_FLAG_AUTHORIZED);

    if (!(msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, NL80211_CMD_SET_STATION)) ||
        nla_put(msg, NL80211_ATTR_MAC, ETH_ALEN, backhaul->bssid) || nla_put(msg, NL80211_ATTR_STA_FLAGS2, sizeof(upd), &upd))
    {
        wifi_hal_error_print("Failed to create command SET_STATION\n");
        nlmsg_free(msg);
        return -ENOBUFS;
    }

    ret = send_and_recv(g_wifi_hal.nl_cb, g_wifi_hal.nl, msg, NULL, NULL, NULL, NULL); 

    if (ret == 0) {
        return 0;
    }

    wifi_hal_error_print("%s:%d: set supp port command failed: ret=%d (%s)\n", __func__, __LINE__,
        ret, strerror(-ret));

    return ret;
}

int wifi_hal_purgeScanResult(unsigned int vap_index, unsigned char *sta_mac)
{
    wifi_radio_info_t *radio;
    wifi_interface_info_t *interface = NULL;
    unsigned char radio_index = 0;
    char *key = NULL;
    mac_addr_str_t sta_mac_str;

    if ((vap_index % 2) == 0) {
        radio_index = 0;
    } else {
        radio_index = 1;
    }

    if((radio_index >= MAX_NUM_RADIOS) || (vap_index >= MAX_VAP) || sta_mac == NULL)
    {
        return RETURN_ERR;
    }

    radio = get_radio_by_phy_index(radio_index);

    if (radio != NULL) {
        interface = hash_map_get_first(radio->interface_map);
        while (interface != NULL) {
            if (interface->vap_info.vap_index == vap_index) {
                break;
            }
            interface = hash_map_get_next(radio->interface_map, interface);
        }
        if ((interface != NULL) && (interface->vap_info.vap_mode == wifi_vap_mode_sta) && (interface->u.sta.scan_info_map != NULL)) {
            key = to_mac_str(sta_mac, sta_mac_str);
            wifi_hal_dbg_print("%s:%d: clear old ssid entry %s\r\n", __func__, __LINE__, key);
            hash_map_remove(interface->u.sta.scan_info_map, key);
        } else {
            return RETURN_ERR;
        }
    } else {
        return RETURN_ERR;
    }

    return RETURN_OK;
}

int wifi_drv_set_operstate(void *priv, int state)
{
    wifi_interface_info_t *interface;
    struct sockaddr_ll sockaddr;
    wifi_vap_info_t *vap;
    int sock_fd;
    const char *ifname;

    interface = (wifi_interface_info_t *)priv;
    vap = &interface->vap_info;

    wifi_hal_info_print("%s:%d: Enter, interface:%s bridge:%s driver operation state:%d\n", 
            __func__, __LINE__, interface->name, vap->bridge_name, state);

    if (interface->vap_configured == true) {
        if (state == 1) {
            wifi_hal_dbg_print("%s:%d: VAP already configured\n", __func__, __LINE__);
            return 0;
        }
        else {
            wifi_hal_dbg_print("%s:%d: Configured VAP is being disabled\n", __func__, __LINE__);
            return 0;
        }
    } else {
        if (state == 0) {
            wifi_hal_dbg_print("%s:%d: VAP is not configured\n", __func__, __LINE__);
            return 0;
        }
    }

    if (vap->u.bss_info.enabled == false && vap->u.sta_info.enabled == false) {
        wifi_hal_dbg_print("%s:%d: VAP not enabled\n", __func__, __LINE__);
        return 0;
    }
        
    if ((vap->vap_mode == wifi_vap_mode_ap) && (nl80211_register_mgmt_frames(interface) != 0)) {
        wifi_hal_error_print("%s:%d: Failed to register for management frames\n", __func__, __LINE__);
        return -1;
    }

    if (vap->vap_mode == wifi_vap_mode_sta) {
        if (interface->u.sta.scan_info_map == NULL) {
            interface->u.sta.scan_info_map = hash_map_create();
        }
    }

    sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_fd < 0) {
        wifi_hal_error_print("%s:%d: Failed to open raw socket on bridge: %s\n", __func__, __LINE__, vap->bridge_name);
        return -1;
    }

    ifname = (vap->vap_mode == wifi_vap_mode_ap) ? vap->bridge_name:interface->name;

    memset(&sockaddr, 0, sizeof(struct sockaddr_ll));
    sockaddr.sll_family   = AF_PACKET;
    sockaddr.sll_protocol = htons(ETH_P_ALL);
    sockaddr.sll_ifindex  = if_nametoindex(ifname);

    if (bind(sock_fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) < 0) {
        wifi_hal_error_print("%s:%d: Error binding to interface, err:%d\n", __func__, __LINE__, errno);
        close(sock_fd);
        return -1;
    }

    if (vap->vap_mode == wifi_vap_mode_ap) {
        interface->u.ap.br_sock_fd = sock_fd;
    } else if (vap->vap_mode == wifi_vap_mode_sta) {
        interface->u.sta.sta_sock_fd = sock_fd;
    }

    interface->vap_configured = true;
    wifi_hal_info_print("%s:%d: Exit, interface:%s bridge:%s driver configured for 802.11\n", 
            __func__, __LINE__, interface->name, vap->bridge_name);

    return 0;
}

int wifi_drv_get_capa(void *priv, struct wpa_driver_capa *capa)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

void wifi_drv_deinit(void *priv)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);

}

void wifi_drv_global_deinit(void *priv)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
}

void *wifi_drv_global_init(void *ctx)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return NULL;
}

int wifi_drv_associate(void *priv, struct wpa_driver_associate_params *params)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_authenticate(void *priv, struct wpa_driver_auth_params *params)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_deauthenticate(void *priv, const u8 *addr, u16 reason_code)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_abort_scan(void *priv, u64 scan_cookie)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

struct wpa_scan_results * wifi_drv_get_scan_results(void *priv)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return NULL;
}

int wifi_drv_stop_sched_scan(void *priv)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_sched_scan(void *priv, struct wpa_driver_scan_params *params)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_scan2(void *priv,
                struct wpa_driver_scan_params *params)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_get_bssid(void *priv, u8 *bssid)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_get_ssid(void *priv, u8 *ssid)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int     wifi_drv_send_eapol(void *priv, const u8 *addr, const u8 *data,
                    size_t data_len, int encrypt,
                    const u8 *own_addr, u32 flags)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

static void * wifi_driver_nl80211_init(void *ctx, const char *ifname,
                                       void *global_priv)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return NULL;
}

void* wifi_drv_init(struct hostapd_data *hapd, struct wpa_init_params *params)
{
    wifi_interface_info_t *interface;
    //wifi_driver_data_t *drv;
    wifi_vap_info_t *vap;
    wifi_radio_info_t *radio;

    interface = (wifi_interface_info_t *)params->global_priv;
    vap = &interface->vap_info;

    radio = get_radio_by_rdk_index(vap->radio_index);
    //XXX check wiphy info? wpa_driver_nl80211_get_info hostapd
    
    wifi_hal_dbg_print("%s:%d: Enter radio index: %d interface: %s vap index: %d\n", __func__, __LINE__, 
        radio->index, interface->name, vap->vap_index);

    //drv = (wifi_driver_data_t *)&radio->driver_data;

    return params->global_priv;
}

int     wifi_drv_set_privacy(void *priv, int enabled)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int     wifi_drv_set_ssid(void *priv, const u8 *buf, int len)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int     wifi_sta_deauth(void *priv, const u8 *own_addr, const u8 *addr, int reason_code)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}
#if HOSTAPD_VERSION >= 210 //2.10
int 	wifi_drv_set_key(void *priv, struct wpa_driver_set_key_params *params)
#else
int     wifi_drv_set_key(const char *ifname, void *priv, enum wpa_alg alg,
                    const u8 *addr, int key_idx, int set_tx, const u8 *seq,
                    size_t seq_len, const u8 *key, size_t key_len)
#endif
{
    wifi_interface_info_t *interface;
    struct nl_msg *msg = NULL;
    unsigned int suite;
    int ret;
    wifi_vap_info_t *vap;

    interface = (wifi_interface_info_t *)priv;
    vap = &interface->vap_info;

    //wifi_hal_dbg_print("%s:%d: ifname: %s\n", __func__, __LINE__, interface->name);
    //wifi_hal_dbg_print("%s:%d: key Info: index:%d length:%d alg:%s\n", __func__, __LINE__, key_idx, key_len, wpa_alg_to_string(alg));
    //my_print_hex_dump(key_len, key);

#if HOSTAPD_VERSION < 210 //2.10
    if (alg == WPA_ALG_NONE) {
        return -1;
    } 
    suite = wpa_alg_to_cipher_suite(alg, key_len);
    if (suite == 0) {
        wifi_hal_error_print("%s:%d: Failed to get cipher suite for alg:%s\n", __func__, __LINE__, wpa_alg_to_string(alg));
        return -1;
    }
    msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, NL80211_CMD_NEW_KEY);
    if (msg == NULL) {
        wifi_hal_error_print("%s:%d:Failed to allocate nl80211 message\n", __func__, __LINE__);
        return -1;
    }

    nla_put(msg, NL80211_ATTR_KEY_DATA, key_len, key);
    nla_put_u32(msg, NL80211_ATTR_KEY_CIPHER, suite);
    if (seq && seq_len) {
        nla_put(msg, NL80211_ATTR_KEY_SEQ, seq_len, seq);
    }

    if (addr && !is_broadcast_ether_addr(addr)) {
        nla_put(msg, NL80211_ATTR_MAC, ETH_ALEN, addr);
        if (alg != WPA_ALG_WEP && key_idx && !set_tx) {
            nla_put_u32(msg, NL80211_ATTR_KEY_TYPE, NL80211_KEYTYPE_GROUP);
        }
    } else if (addr && is_broadcast_ether_addr(addr)) {
        struct nlattr *types;

        types = nla_nest_start(msg, NL80211_ATTR_KEY_DEFAULT_TYPES);
        if (!types) {
            nla_put_flag(msg, NL80211_KEY_DEFAULT_TYPE_MULTICAST);
        }
        nla_nest_end(msg, types);
    }

    nla_put_u8(msg, NL80211_ATTR_KEY_IDX, key_idx);

    if ((ret = send_and_recv(g_wifi_hal.nl_cb, g_wifi_hal.nl, msg, NULL, (void *)-1, NULL, NULL))) {
        wifi_hal_error_print("%s:%d: Failed new key: %s\n", __func__, __LINE__, strerror(-ret));
        return -1;
    }

    wifi_hal_dbg_print("%s:%d: new key success\n", __func__, __LINE__);

    if (vap->vap_mode != wifi_vap_mode_sta)
        return 0;

    msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, NL80211_CMD_SET_KEY);

    nla_put_u8(msg, NL80211_ATTR_KEY_IDX, key_idx);
    nla_put_flag(msg, NL80211_ATTR_KEY_DEFAULT);

    if (addr && is_broadcast_ether_addr(addr)) {
        struct nlattr *types;

        types = nla_nest_start(msg, NL80211_ATTR_KEY_DEFAULT_TYPES);
        nla_put_flag(msg, NL80211_KEY_DEFAULT_TYPE_MULTICAST);
        nla_nest_end(msg, types);
    } else if (addr) {
#else //hostapd 2.10
    if (params->alg == WPA_ALG_NONE) {
        return -1;
    }
    suite = wpa_alg_to_cipher_suite(params->alg, params->key_len);
    if (suite == 0) {
        wifi_hal_dbg_print("%s:%d: Failed to get cipher suite for alg:%s\n", __func__, __LINE__, wpa_alg_to_string(params->alg));
        return -1;
    }
    msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, NL80211_CMD_NEW_KEY);
    if (msg == NULL) {
        wifi_hal_dbg_print("%s:%d:Failed to allocate nl80211 message\n", __func__, __LINE__);
        return -1;
    }

    nla_put(msg, NL80211_ATTR_KEY_DATA, params->key_len, params->key);
    nla_put_u32(msg, NL80211_ATTR_KEY_CIPHER, suite);
    if (params->seq && params->seq_len) {
        nla_put(msg, NL80211_ATTR_KEY_SEQ, params->seq_len, params->seq);
    }

    if (params->addr && !is_broadcast_ether_addr(params->addr)) {
        nla_put(msg, NL80211_ATTR_MAC, ETH_ALEN, params->addr);
        if (params->alg != WPA_ALG_WEP && params->key_idx && !params->set_tx) {
            nla_put_u32(msg, NL80211_ATTR_KEY_TYPE, NL80211_KEYTYPE_GROUP);
        }
    } else if (params->addr && is_broadcast_ether_addr(params->addr)) {
        struct nlattr *types;

        types = nla_nest_start(msg, NL80211_ATTR_KEY_DEFAULT_TYPES);
        if (!types) {
            nla_put_flag(msg, NL80211_KEY_DEFAULT_TYPE_MULTICAST);
        }
        nla_nest_end(msg, types);
    }

    nla_put_u8(msg, NL80211_ATTR_KEY_IDX, params->key_idx);

    if ((ret = send_and_recv(g_wifi_hal.nl_cb, g_wifi_hal.nl, msg, NULL, (void *)-1, NULL, NULL))) {
        wifi_hal_dbg_print("%s:%d: Failed new key: %s\n", __func__, __LINE__, strerror(-ret));
        return -1;
    }

    wifi_hal_dbg_print("%s:%d: new key success\n", __func__, __LINE__);

    if (vap->vap_mode != wifi_vap_mode_sta)
        return 0;

    msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, NL80211_CMD_SET_KEY);

    nla_put_u8(msg, NL80211_ATTR_KEY_IDX, params->key_idx);
    nla_put_flag(msg, NL80211_ATTR_KEY_DEFAULT);

    if (params->addr && is_broadcast_ether_addr(params->addr)) {
        struct nlattr *types;

        types = nla_nest_start(msg, NL80211_ATTR_KEY_DEFAULT_TYPES);
        nla_put_flag(msg, NL80211_KEY_DEFAULT_TYPE_MULTICAST);
        nla_nest_end(msg, types);
    } else if (params->addr) {
#endif
        struct nlattr *types;

        types = nla_nest_start(msg, NL80211_ATTR_KEY_DEFAULT_TYPES);

        nla_put_flag(msg, NL80211_KEY_DEFAULT_TYPE_UNICAST);
        nla_nest_end(msg, types);
    }

    if ((ret = send_and_recv(g_wifi_hal.nl_cb, g_wifi_hal.nl, msg, NULL, (void *)-1, NULL, NULL))) {
        wifi_hal_error_print("%s:%d: Failed to set key: %s\n", __func__, __LINE__, strerror(-ret));
        return -1;
    }

    wifi_hal_info_print("%s:%d:key set success\n", __func__, __LINE__);

    return 0;
}

int wifi_drv_set_authmode(void *priv, int auth_algs)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_set_ieee8021x(void *priv, struct wpa_bss_params *params)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_set_opt_ie(void *priv, const u8 *ie, size_t ie_len)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_sta_assoc(void *priv, const u8 *own_addr, const u8 *addr,
                int reassoc, u16 status_code, const u8 *ie, size_t len)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_set_ap_wps_ie(void *priv, const struct wpabuf *beacon,
                      const struct wpabuf *proberesp,
                      const struct wpabuf *assocresp)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_sta_get_seqnum(const char *ifname, void *priv, const u8 *addr, int idx, u8 *seq)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_commit(void *priv)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

const struct wpa_driver_ops g_wpa_driver_nl80211_ops = {
    .name = "nl80211",
    .desc = "Linux nl80211/cfg80211",
    .get_bssid = wifi_drv_get_bssid,
    .get_ssid = wifi_drv_get_ssid,
    .set_key = wifi_drv_set_key,
    .scan2 = wifi_drv_scan2,
    .sched_scan = wifi_drv_sched_scan,
    .stop_sched_scan = wifi_drv_stop_sched_scan,
    .get_scan_results2 = wifi_drv_get_scan_results,
    .abort_scan = wifi_drv_abort_scan,
    .deauthenticate = wifi_drv_deauthenticate,
    .authenticate = wifi_drv_authenticate,
    .associate = wifi_drv_associate,
    .global_init = wifi_drv_global_init,
    .global_deinit = wifi_drv_global_deinit,
    .init2 = wifi_driver_nl80211_init,
    .deinit = wifi_drv_deinit,
    .get_capa = wifi_drv_get_capa,
    .set_operstate = wifi_drv_set_operstate,
    .set_supp_port = wifi_drv_set_supp_port,
    .set_country = wifi_drv_set_country,
    .get_country = wifi_drv_get_country,
    .set_ap = wifi_drv_set_ap,
    .set_acl = wifi_drv_set_acl,
    .if_add = wifi_drv_if_add,
    .if_remove = wifi_drv_if_remove,
    .send_mlme = wifi_drv_send_mlme,
    .get_hw_feature_data = wifi_drv_get_hw_feature_data,
    .sta_add = wifi_drv_sta_add,
    .sta_remove = wifi_drv_sta_remove,
    .hapd_send_eapol = wifi_drv_hapd_send_eapol,
    .sta_set_flags = wifi_drv_sta_set_flags,
    .sta_set_airtime_weight = wifi_drv_sta_set_airtime_weight,
    .hapd_init = wifi_drv_init,
    .hapd_deinit = wifi_drv_deinit,
    .set_wds_sta = wifi_drv_set_wds_sta,
    .get_seqnum = wifi_drv_get_seqnum,
    .flush = wifi_drv_flush,
    .get_inact_sec = wifi_drv_get_inact_sec,
    .sta_clear_stats = wifi_drv_sta_clear_stats,
    .set_rts = wifi_drv_set_rts,
    .set_frag = wifi_drv_set_frag,
    .set_tx_queue_params = wifi_drv_set_tx_queue_params,
    .set_sta_vlan = wifi_drv_set_sta_vlan,
    .sta_deauth = wifi_drv_sta_deauth,
    .sta_notify_deauth = wifi_drv_sta_notify_deauth,
    .sta_disassoc = wifi_drv_sta_disassoc,
    .read_sta_data = wifi_drv_read_sta_data,
    .set_freq = wifi_drv_set_freq,
    .send_action = wifi_drv_send_action,
    .send_action_cancel_wait = wifi_drv_send_action_cancel_wait,
    .remain_on_channel = wifi_drv_remain_on_channel,
    .cancel_remain_on_channel = wifi_drv_cancel_remain_on_channel,
    .probe_req_report = wifi_drv_probe_req_report,
    .deinit_ap = wifi_drv_deinit_ap,
    .deinit_p2p_cli = wifi_drv_deinit_p2p_cli,
    .resume = wifi_drv_resume,
    .signal_monitor = wifi_drv_signal_monitor,
    .signal_poll = wifi_drv_signal_poll,
#if HOSTAPD_VERSION < 210 //2.10
    .channel_info = wifi_drv_channel_info,
#endif
    .set_param = wifi_drv_set_param,
    .get_radio_name = wifi_drv_get_radio_name,
    .add_pmkid = wifi_drv_add_pmkid,
    .remove_pmkid = wifi_drv_remove_pmkid,
    .flush_pmkid = wifi_drv_flush_pmkid,
    .set_rekey_info = wifi_drv_set_rekey_info,
    .poll_client = wifi_drv_poll_client,
    .set_p2p_powersave = wifi_drv_set_p2p_powersave,
    .start_dfs_cac = wifi_drv_start_radar_detection,
    .stop_ap = wifi_drv_stop_ap,
#ifdef CONFIG_TDLS
    .send_tdls_mgmt = wifi_drv_send_tdls_mgmt,
    .tdls_oper = wifi_drv_tdls_oper,
    .tdls_enable_channel_switch = wifi_drv_tdls_enable_channel_switch,
    .tdls_disable_channel_switch = wifi_drv_tdls_disable_channel_switch,
#endif /* CONFIG_TDLS */
    .update_ft_ies = wifi_drv_update_ft_ies,
    .update_dh_ie = wifi_drv_update_dh_ie,
    .get_mac_addr = wifi_drv_get_macaddr,
    .get_survey = wifi_drv_get_survey,
    .status = wifi_drv_status,
    .switch_channel = wifi_drv_switch_channel,
#ifdef ANDROID_P2P
    .set_noa = wifi_drv_set_p2p_noa,
    .get_noa = wifi_drv_get_p2p_noa,
    .set_ap_wps_ie = wifi_drv_set_ap_wps_p2p_ie,
#endif /* ANDROID_P2P */
#ifdef ANDROID
#ifndef ANDROID_LIB_STUB
    .driver_cmd = wifi_drv_driver_cmd,
#endif /* !ANDROID_LIB_STUB */
#endif /* ANDROID */
    .vendor_cmd = wifi_drv_vendor_cmd,
    .set_qos_map = wifi_drv_set_qos_map,
    .set_wowlan = wifi_drv_set_wowlan,
    .set_mac_addr = wifi_drv_set_mac_addr,
#ifdef CONFIG_MESH
    .init_mesh = wifi_drv_init_mesh,
    .join_mesh = wifi_drv_join_mesh,
    .leave_mesh = wifi_drv_leave_mesh,
    .probe_mesh_link = wifi_drv_probe_mesh_link,
#endif /* CONFIG_MESH */
    .br_add_ip_neigh = wifi_drv_br_add_ip_neigh,
    .br_delete_ip_neigh = wifi_drv_br_delete_ip_neigh,
    .br_port_set_attr = wifi_drv_br_port_set_attr,
    .br_set_net_param = wifi_drv_br_set_net_param,
    .add_tx_ts = wifi_drv_add_ts,
    .del_tx_ts = wifi_drv_del_ts,
    .get_ifindex = wifi_drv_get_ifindex,
#ifdef CONFIG_DRIVER_NL80211_QCA
    .roaming = wifi_drv_roaming,
    .disable_fils = wifi_drv_disable_fils,
    .do_acs = wifi_drv_do_acs,
    .set_band = wifi_drv_set_band,
    .get_pref_freq_list = wifi_drv_get_pref_freq_list,
    .set_prob_oper_freq = wifi_drv_set_prob_oper_freq,
    .p2p_lo_start = wifi_drv_p2p_lo_start,
    .p2p_lo_stop = wifi_drv_p2p_lo_stop,
    .set_default_scan_ies = wifi_drv_set_default_scan_ies,
    .set_tdls_mode = wifi_drv_set_tdls_mode,
#ifdef CONFIG_MBO
    .get_bss_transition_status = wifi_drv_get_bss_transition_status,
    .ignore_assoc_disallow = wifi_drv_ignore_assoc_disallow,
#endif /* CONFIG_MBO */
    .set_bssid_blacklist = wifi_drv_set_bssid_blacklist,
#endif /* CONFIG_DRIVER_NL80211_QCA */
    .configure_data_frame_filters = wifi_drv_configure_data_frame_filters,
    .get_ext_capab = wifi_drv_get_ext_capab,
    .update_connect_params = wifi_drv_update_connection_params,
    .send_external_auth_status = wifi_drv_send_external_auth_status,
    .set_4addr_mode = wifi_drv_set_4addr_mode,
};

