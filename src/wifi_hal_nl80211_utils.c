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

wifi_interface_name_idex_map_t interface_index_map[] = {
#ifdef RASPBERRY_PI_PORT
    {1, 0,  "wlan1",   "brlan1",    true,   14,     "mesh_sta_2g"},
    {2, 1,  "wlan2",   "brlan0",    true,   0,      "private_ssid_2g"},
    {3, 2,  "wlan3",   "brlan112",  true,   12,      "mesh_backhaul_2g"},
#endif

#ifdef TCXB7_PORT // for Broadcom based platforms
    {0, 0,  "wl0",     "brlan1",   true,   14,     "mesh_sta_2g"},
    {0, 0,  "wl0.1",   "brlan0",   false,  0,      "private_ssid_2g"},
    {0, 0,  "wl0.2",   "brlan1",   false,  2,      "iot_ssid_2g"},
    {0, 0,  "wl0.3",   "brlan2",   false,  4,      "hotspot_open_2g"},
    {0, 0,  "wl0.4",   "br106",    false,  6,      "lnf_psk_2g"},
    {0, 0,  "wl0.5",   "brlan4",   false,  8,      "hotspot_secure_2g"},
    {0, 0,  "wl0.6",   "br106",    false,  10,     "lnf_radius_2g"},
    {0, 0,  "wl0.7",   "brlan112", false,  12,     "mesh_backhaul_2g"},
    {1, 1,  "wl1",     "brlan1",   true,   15,     "mesh_sta_5g"},
    {1, 1,  "wl1.1",   "brlan0",   false,  1,      "private_ssid_5g"},
    {1, 1,  "wl1.2",   "brlan1",   false,  3,      "iot_ssid_5g"},
    {1, 1,  "wl1.3",   "brlan3",   false,  5,      "hotspot_open_5g"},
    {1, 1,  "wl1.4",   "br106",    false,  7,      "lnf_psk_5g"},
    {1, 1,  "wl1.5",   "brlan5",   false,  9,      "hotspot_secure_5g"},
    {1, 1,  "wl1.6",   "br106",    false,  11,     "lnf_radius_5g"},
    {1, 1,  "wl1.7",   "brlan113", false,  13,     "mesh_backhaul_5g"},
#endif

    // for Intel based platforms
};

const wifi_driver_info_t  driver_info[] = {
#ifdef RASPBERRY_PI_PORT
        {"pi4",    "cfg80211"},
#endif

#ifdef TCXB7_PORT // for Broadcom based platforms
        {"tcxb7",       "dhd"},
#endif
};

void get_wifi_interface_info_map(wifi_interface_name_idex_map_t *interface_map)
{
    memcpy(interface_map, interface_index_map, sizeof(interface_index_map));
}

wifi_interface_info_t* get_primary_interface(wifi_radio_info_t *radio)
{
    wifi_interface_info_t *interface;
    interface = hash_map_get_first(radio->interface_map);

    while (interface != NULL) {
        if (interface->primary == true) {
            return interface;
        }

        interface = hash_map_get_next(radio->interface_map, interface);
    }

    return NULL;
}

wifi_interface_info_t* get_private_vap_interface(wifi_radio_info_t *radio)
{
    wifi_interface_info_t *interface;
    wifi_vap_info_t *vap;
    interface = hash_map_get_first(radio->interface_map);

    while (interface != NULL) {
        vap = &interface->vap_info;
        if(vap->vap_index == 1 || vap->vap_index == 0) {
            return interface;
        }

        interface = hash_map_get_next(radio->interface_map, interface);
    }
    return NULL;
}


int set_interface_properties(unsigned int phy_index, wifi_interface_info_t *interface)
{
    wifi_interface_name_idex_map_t *map;
    wifi_vap_info_t *vap;
    unsigned int i;
    bool found = false;

    vap = &interface->vap_info;

    vap->vap_index = 0;

    for (i = 0; i < sizeof(interface_index_map)/sizeof(wifi_interface_name_idex_map_t); i++) {
        map = &interface_index_map[i];

        if ((strcmp(interface->name, map->interface_name) == 0) &&
            (phy_index == map->phy_index)) {
            vap->radio_index = map->rdk_radio_index;
            vap->vap_index = map->index;
            strcpy(vap->vap_name, map->vap_name);
            interface->primary = map->primary;
            found = true;
            break;
        }
    }

    //wifi_hal_dbg_print("%s:%d ifname:%s radio index:%d vap index:%d\n",
    //    __func__, __LINE__, interface->name, interface->phy_index, vap->vap_index);

    return (found == true) ? 0 : -1;
}

wifi_radio_info_t *get_radio_by_rdk_index(wifi_radio_index_t index)
{
    wifi_radio_info_t *radio;
    wifi_interface_info_t *interface;
    wifi_vap_info_t *vap;
    unsigned int i;

    for (i = 0; i < g_wifi_hal.num_radios; i++) {
        radio = &g_wifi_hal.radio_info[i];
        interface = hash_map_get_first(radio->interface_map);
        if (interface == NULL) {
            continue;
        }
        vap = &interface->vap_info;
        if (vap->radio_index == index) {
            return radio;
        }
    }

    return NULL;
}


wifi_radio_info_t *get_radio_by_phy_index(wifi_radio_index_t index)
{
    wifi_radio_info_t *radio;
    unsigned int i;

    for (i = 0; i < g_wifi_hal.num_radios; i++) {
        radio = &g_wifi_hal.radio_info[i];
        if (radio->index == index) {
            return radio;
        }
    }

    return NULL;
}

wifi_interface_info_t *get_interface_by_vap_index(unsigned int vap_index)
{
    wifi_radio_info_t *radio;
    wifi_interface_info_t *interface;
    unsigned int i;

    wifi_hal_dbg_print("%s:%d:{ vap_index:[%d] } g_wifi_hal.num_radios:[%d]\r\n",__func__, __LINE__, vap_index, g_wifi_hal.num_radios);
    for (i = 0; i < g_wifi_hal.num_radios; i++) {

        radio = &g_wifi_hal.radio_info[i];
        interface = hash_map_get_first(radio->interface_map);

        while (interface != NULL) {
            wifi_hal_dbg_print("%s:%d:interface vap_index:[%d] vap_index:[%d]\r\n",__func__, __LINE__, interface->vap_info.vap_index, vap_index);
            if (interface->vap_info.vap_index == vap_index) {
                return interface;
            }
            interface = hash_map_get_next(radio->interface_map, interface);
        }
    }

    return NULL;
}

BOOL get_ie_by_eid(unsigned int eid, unsigned char *buff, unsigned int buff_len, unsigned char **ie_out, unsigned short *ie_out_len)
{
    ieee80211_tlv_t *ie = NULL;
    signed int len;

    ie = (ieee80211_tlv_t *)buff;
    len = buff_len;

    while ((ie != NULL) && (len > 0)) {
        if ((ie->type == eid) && (ie->length != 0)) {
            //wifi_hal_dbg_print("%s:%d: Found ssid ie, ie length:%d\n", __func__, __LINE__,
            //    ie->length);
            *ie_out = (unsigned char *)ie;
            *ie_out_len = ie->length + sizeof(ieee80211_tlv_t);
            return true;
        }

        len = len - (ie->length + sizeof(ieee80211_tlv_t));
        ie = (ieee80211_tlv_t *)((unsigned char *)ie + (ie->length + sizeof(ieee80211_tlv_t)));
    }

    return false;
}

INT get_coutry_str_from_code(wifi_countrycode_type_t code, char *country)
{
    switch (code) {
    case wifi_countrycode_US:
        strcpy(country, "US");
        break;

    default:
        strcpy(country, "US");
        break;
    }

    return RETURN_OK;
}

int get_op_class_from_radio_params(wifi_radio_operationParam_t *param)
{
    unsigned int i, j;
    bool found = false;
    wifi_country_radio_op_class_t *cc_op_class;
    wifi_radio_op_class_t   *op_class;

    wifi_country_radio_op_class_t   cc_op_classes[] = {
        {
            wifi_countrycode_US, {
                { 1, 115, 4, {36, 40, 44, 48, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
                { 2, 118, 4, {52, 56, 60, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
                { 3, 124, 4, {149, 153, 157, 161, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
                { 4, 121, 12, {100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 0, 0, 0, 0} },
                { 5, 125, 5, {149, 153, 157, 161, 165, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} },
                { 12, 81, 11, {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0, 0, 0, 0, 0} }
            }
        }
    };

    // country code match
    for (i = 0; i < ARRAY_SZ(cc_op_classes); i++) {
        cc_op_class = &cc_op_classes[i];
        if (cc_op_class->cc == param->countryCode) {
            found = true;
            break;
        }
    }

    if (found == false) {
        wifi_hal_dbg_print("%s:%d:Could not find country code\n", __func__, __LINE__);
        return -1;
    }

    // channel match
    for (i = 0; i < ARRAY_SZ(cc_op_class->op_class); i++) {
        op_class = &cc_op_class->op_class[i];
        for (j = 0; j < op_class->num; j++) {
            if (op_class->ch_list[j] == param->channel) {
                return op_class->op_class;
            }
        }
    }

    wifi_hal_dbg_print("%s:%d:Could not find channel is list for country\n", __func__, __LINE__);

    return -1;
}



void wifi_hal_dbg_print(char *format, ...)
{
    char buff[4096] = {0};
    va_list list;
    static FILE *fpg = NULL;

    get_formatted_time(buff);
    strcat(buff, " ");

    va_start(list, format);
    vsprintf(&buff[strlen(buff)], format, list);
    va_end(list);

#ifdef LINUX_VM_PORT
    printf("%s", buff);
#else
    if ((access("/nvram/wifiHalDbg", R_OK)) != 0) {
        return;
    }

    if (fpg == NULL) {
        fpg = fopen("/tmp/wifiHal", "a+");
        if (fpg == NULL) {
            return;
        } else {
            fputs(buff, fpg);
        }
    } else {
        fputs(buff, fpg);
    }

    fflush(fpg);
#endif
}

const char *wpa_alg_to_string(enum wpa_alg alg)
{
#define ALG2S(x) case x: return #x;
    switch (alg) {
    ALG2S(WPA_ALG_NONE)
    ALG2S(WPA_ALG_WEP)
    ALG2S(WPA_ALG_TKIP)
    ALG2S(WPA_ALG_CCMP)
    ALG2S(WPA_ALG_IGTK)
    ALG2S(WPA_ALG_PMK)
    ALG2S(WPA_ALG_GCMP)
    ALG2S(WPA_ALG_SMS4)
    ALG2S(WPA_ALG_KRK)
    ALG2S(WPA_ALG_GCMP_256)
    ALG2S(WPA_ALG_CCMP_256)
    ALG2S(WPA_ALG_BIP_GMAC_128)
    ALG2S(WPA_ALG_BIP_GMAC_256)
    ALG2S(WPA_ALG_BIP_CMAC_256)
    }

    return "WPA_ALG_UNKNOWN";
}

const char *nl80211_attribute_to_string(enum nl80211_attrs attrib)
{
#define A2S(x) case x: return #x;
    switch (attrib) {
    A2S(NL80211_ATTR_UNSPEC)

    A2S(NL80211_ATTR_WIPHY)
    A2S(NL80211_ATTR_WIPHY_NAME)

    A2S(NL80211_ATTR_IFINDEX)
    A2S(NL80211_ATTR_IFNAME)
    A2S(NL80211_ATTR_IFTYPE)

    A2S(NL80211_ATTR_MAC)

    A2S(NL80211_ATTR_KEY_DATA)
    A2S(NL80211_ATTR_KEY_IDX)
    A2S(NL80211_ATTR_KEY_CIPHER)
    A2S(NL80211_ATTR_KEY_SEQ)
    A2S(NL80211_ATTR_KEY_DEFAULT)

    A2S(NL80211_ATTR_BEACON_INTERVAL)
    A2S(NL80211_ATTR_DTIM_PERIOD)
    A2S(NL80211_ATTR_BEACON_HEAD)
    A2S(NL80211_ATTR_BEACON_TAIL)

    A2S(NL80211_ATTR_STA_AID)
    A2S(NL80211_ATTR_STA_FLAGS)
    A2S(NL80211_ATTR_STA_LISTEN_INTERVAL)
    A2S(NL80211_ATTR_STA_SUPPORTED_RATES)
    A2S(NL80211_ATTR_STA_VLAN)
    A2S(NL80211_ATTR_STA_INFO)

    A2S(NL80211_ATTR_WIPHY_BANDS)

    A2S(NL80211_ATTR_MNTR_FLAGS)

    A2S(NL80211_ATTR_MESH_ID)
    A2S(NL80211_ATTR_STA_PLINK_ACTION)
    A2S(NL80211_ATTR_MPATH_NEXT_HOP)
    A2S(NL80211_ATTR_MPATH_INFO)

    A2S(NL80211_ATTR_BSS_CTS_PROT)
    A2S(NL80211_ATTR_BSS_SHORT_PREAMBLE)
    A2S(NL80211_ATTR_BSS_SHORT_SLOT_TIME)

    A2S(NL80211_ATTR_HT_CAPABILITY)

    A2S(NL80211_ATTR_SUPPORTED_IFTYPES)

    A2S(NL80211_ATTR_REG_ALPHA2)
    A2S(NL80211_ATTR_REG_RULES)

    A2S(NL80211_ATTR_MESH_CONFIG)

    A2S(NL80211_ATTR_BSS_BASIC_RATES)

    A2S(NL80211_ATTR_WIPHY_TXQ_PARAMS)
    A2S(NL80211_ATTR_WIPHY_FREQ)
    A2S(NL80211_ATTR_WIPHY_CHANNEL_TYPE)

    A2S(NL80211_ATTR_KEY_DEFAULT_MGMT)

    A2S(NL80211_ATTR_MGMT_SUBTYPE)
    A2S(NL80211_ATTR_IE)

    A2S(NL80211_ATTR_MAX_NUM_SCAN_SSIDS)

    A2S(NL80211_ATTR_SCAN_FREQUENCIES)
    A2S(NL80211_ATTR_SCAN_SSIDS)
    A2S(NL80211_ATTR_GENERATION) /* replaces old SCAN_GENERATION */
    A2S(NL80211_ATTR_BSS)

    A2S(NL80211_ATTR_REG_INITIATOR)
    A2S(NL80211_ATTR_REG_TYPE)

    A2S(NL80211_ATTR_SUPPORTED_COMMANDS)

    A2S(NL80211_ATTR_FRAME)
    A2S(NL80211_ATTR_SSID)
    A2S(NL80211_ATTR_AUTH_TYPE)
    A2S(NL80211_ATTR_REASON_CODE)

    A2S(NL80211_ATTR_KEY_TYPE)
    A2S(NL80211_ATTR_MAX_SCAN_IE_LEN)
    A2S(NL80211_ATTR_CIPHER_SUITES)

    A2S(NL80211_ATTR_FREQ_BEFORE)
    A2S(NL80211_ATTR_FREQ_AFTER)

    A2S(NL80211_ATTR_FREQ_FIXED)


    A2S(NL80211_ATTR_WIPHY_RETRY_SHORT)
    A2S(NL80211_ATTR_WIPHY_RETRY_LONG)
    A2S(NL80211_ATTR_WIPHY_FRAG_THRESHOLD)
    A2S(NL80211_ATTR_WIPHY_RTS_THRESHOLD)

    A2S(NL80211_ATTR_TIMED_OUT)

    A2S(NL80211_ATTR_USE_MFP)

    A2S(NL80211_ATTR_STA_FLAGS2)

    A2S(NL80211_ATTR_CONTROL_PORT)

    A2S(NL80211_ATTR_TESTDATA)

    A2S(NL80211_ATTR_PRIVACY)

    A2S(NL80211_ATTR_DISCONNECTED_BY_AP)
    A2S(NL80211_ATTR_STATUS_CODE)

    A2S(NL80211_ATTR_CIPHER_SUITES_PAIRWISE)
    A2S(NL80211_ATTR_CIPHER_SUITE_GROUP)
    A2S(NL80211_ATTR_WPA_VERSIONS)
    A2S(NL80211_ATTR_AKM_SUITES)

    A2S(NL80211_ATTR_REQ_IE)
    A2S(NL80211_ATTR_RESP_IE)

    A2S(NL80211_ATTR_PREV_BSSID)
    A2S(NL80211_ATTR_KEY)
    A2S(NL80211_ATTR_KEYS)

    A2S(NL80211_ATTR_PID)

    A2S(NL80211_ATTR_4ADDR)

    A2S(NL80211_ATTR_SURVEY_INFO)

    A2S(NL80211_ATTR_PMKID)
    A2S(NL80211_ATTR_MAX_NUM_PMKIDS)

    A2S(NL80211_ATTR_DURATION)

    A2S(NL80211_ATTR_COOKIE)

    A2S(NL80211_ATTR_WIPHY_COVERAGE_CLASS)

    A2S(NL80211_ATTR_TX_RATES)

    A2S(NL80211_ATTR_FRAME_MATCH)

    A2S(NL80211_ATTR_ACK)

    A2S(NL80211_ATTR_PS_STATE)

    A2S(NL80211_ATTR_CQM)

    A2S(NL80211_ATTR_LOCAL_STATE_CHANGE)

    A2S(NL80211_ATTR_AP_ISOLATE)

    A2S(NL80211_ATTR_WIPHY_TX_POWER_SETTING)
    A2S(NL80211_ATTR_WIPHY_TX_POWER_LEVEL)

    A2S(NL80211_ATTR_TX_FRAME_TYPES)
    A2S(NL80211_ATTR_RX_FRAME_TYPES)
    A2S(NL80211_ATTR_FRAME_TYPE)

    A2S(NL80211_ATTR_CONTROL_PORT_ETHERTYPE)
    A2S(NL80211_ATTR_CONTROL_PORT_NO_ENCRYPT)

    A2S(NL80211_ATTR_SUPPORT_IBSS_RSN)

    A2S(NL80211_ATTR_WIPHY_ANTENNA_TX)
    A2S(NL80211_ATTR_WIPHY_ANTENNA_RX)

    A2S(NL80211_ATTR_MCAST_RATE)

    A2S(NL80211_ATTR_OFFCHANNEL_TX_OK)

    A2S(NL80211_ATTR_BSS_HT_OPMODE)

    A2S(NL80211_ATTR_KEY_DEFAULT_TYPES)

    A2S(NL80211_ATTR_MAX_REMAIN_ON_CHANNEL_DURATION)

    A2S(NL80211_ATTR_MESH_SETUP)

    A2S(NL80211_ATTR_WIPHY_ANTENNA_AVAIL_TX)
    A2S(NL80211_ATTR_WIPHY_ANTENNA_AVAIL_RX)

    A2S(NL80211_ATTR_SUPPORT_MESH_AUTH)
    A2S(NL80211_ATTR_STA_PLINK_STATE)

    A2S(NL80211_ATTR_WOWLAN_TRIGGERS)
    A2S(NL80211_ATTR_WOWLAN_TRIGGERS_SUPPORTED)

    A2S(NL80211_ATTR_SCHED_SCAN_INTERVAL)

    A2S(NL80211_ATTR_INTERFACE_COMBINATIONS)
    A2S(NL80211_ATTR_SOFTWARE_IFTYPES)

    A2S(NL80211_ATTR_REKEY_DATA)

    A2S(NL80211_ATTR_MAX_NUM_SCHED_SCAN_SSIDS)
    A2S(NL80211_ATTR_MAX_SCHED_SCAN_IE_LEN)

    A2S(NL80211_ATTR_SCAN_SUPP_RATES)

    A2S(NL80211_ATTR_HIDDEN_SSID)

    A2S(NL80211_ATTR_IE_PROBE_RESP)
    A2S(NL80211_ATTR_IE_ASSOC_RESP)

    A2S(NL80211_ATTR_STA_WME)
    A2S(NL80211_ATTR_SUPPORT_AP_UAPSD)

    A2S(NL80211_ATTR_ROAM_SUPPORT)

    A2S(NL80211_ATTR_SCHED_SCAN_MATCH)
    A2S(NL80211_ATTR_MAX_MATCH_SETS)

    A2S(NL80211_ATTR_PMKSA_CANDIDATE)

    A2S(NL80211_ATTR_TX_NO_CCK_RATE)

    A2S(NL80211_ATTR_TDLS_ACTION)
    A2S(NL80211_ATTR_TDLS_DIALOG_TOKEN)
    A2S(NL80211_ATTR_TDLS_OPERATION)
    A2S(NL80211_ATTR_TDLS_SUPPORT)
    A2S(NL80211_ATTR_TDLS_EXTERNAL_SETUP)

    A2S(NL80211_ATTR_DEVICE_AP_SME)

    A2S(NL80211_ATTR_DONT_WAIT_FOR_ACK)

    A2S(NL80211_ATTR_FEATURE_FLAGS)

    A2S(NL80211_ATTR_PROBE_RESP_OFFLOAD)

    A2S(NL80211_ATTR_PROBE_RESP)

    A2S(NL80211_ATTR_DFS_REGION)

    A2S(NL80211_ATTR_DISABLE_HT)
    A2S(NL80211_ATTR_HT_CAPABILITY_MASK)

    A2S(NL80211_ATTR_NOACK_MAP)
    A2S(NL80211_ATTR_INACTIVITY_TIMEOUT)

    A2S(NL80211_ATTR_RX_SIGNAL_DBM)

    A2S(NL80211_ATTR_BG_SCAN_PERIOD)

    A2S(NL80211_ATTR_WDEV)

    A2S(NL80211_ATTR_USER_REG_HINT_TYPE)

    A2S(NL80211_ATTR_CONN_FAILED_REASON)

    A2S(NL80211_ATTR_AUTH_DATA)

    A2S(NL80211_ATTR_VHT_CAPABILITY)

    A2S(NL80211_ATTR_SCAN_FLAGS)

    A2S(NL80211_ATTR_CHANNEL_WIDTH)
    A2S(NL80211_ATTR_CENTER_FREQ1)
    A2S(NL80211_ATTR_CENTER_FREQ2)

    A2S(NL80211_ATTR_P2P_CTWINDOW)
    A2S(NL80211_ATTR_P2P_OPPPS)

    A2S(NL80211_ATTR_LOCAL_MESH_POWER_MODE)

    A2S(NL80211_ATTR_ACL_POLICY)

    A2S(NL80211_ATTR_MAC_ADDRS)

    A2S(NL80211_ATTR_MAC_ACL_MAX)

    A2S(NL80211_ATTR_RADAR_EVENT)

    A2S(NL80211_ATTR_EXT_CAPA)
    A2S(NL80211_ATTR_EXT_CAPA_MASK)

    A2S(NL80211_ATTR_STA_CAPABILITY)
    A2S(NL80211_ATTR_STA_EXT_CAPABILITY)
    A2S(NL80211_ATTR_PROTOCOL_FEATURES)
    A2S(NL80211_ATTR_SPLIT_WIPHY_DUMP)

    A2S(NL80211_ATTR_DISABLE_VHT)
    A2S(NL80211_ATTR_VHT_CAPABILITY_MASK)

    A2S(NL80211_ATTR_MDID)
    A2S(NL80211_ATTR_IE_RIC)

    A2S(NL80211_ATTR_CRIT_PROT_ID)
    A2S(NL80211_ATTR_MAX_CRIT_PROT_DURATION)

    A2S(NL80211_ATTR_PEER_AID)

    A2S(NL80211_ATTR_COALESCE_RULE)

    A2S(NL80211_ATTR_CH_SWITCH_COUNT)
    A2S(NL80211_ATTR_CH_SWITCH_BLOCK_TX)
    A2S(NL80211_ATTR_CSA_IES)
    A2S(NL80211_ATTR_CSA_C_OFF_BEACON)
    A2S(NL80211_ATTR_CSA_C_OFF_PRESP)

    A2S(NL80211_ATTR_RXMGMT_FLAGS)

    A2S(NL80211_ATTR_STA_SUPPORTED_CHANNELS)

    A2S(NL80211_ATTR_STA_SUPPORTED_OPER_CLASSES)

    A2S(NL80211_ATTR_HANDLE_DFS)

    A2S(NL80211_ATTR_SUPPORT_5_MHZ)
    A2S(NL80211_ATTR_SUPPORT_10_MHZ)

    A2S(NL80211_ATTR_OPMODE_NOTIF)

    A2S(NL80211_ATTR_VENDOR_ID)
    A2S(NL80211_ATTR_VENDOR_SUBCMD)
    A2S(NL80211_ATTR_VENDOR_DATA)
    A2S(NL80211_ATTR_VENDOR_EVENTS)
    A2S(NL80211_ATTR_QOS_MAP)

    A2S(NL80211_ATTR_MAC_HINT)
    A2S(NL80211_ATTR_WIPHY_FREQ_HINT)

    A2S(NL80211_ATTR_MAX_AP_ASSOC_STA)

    A2S(NL80211_ATTR_TDLS_PEER_CAPABILITY)

    A2S(NL80211_ATTR_SOCKET_OWNER)

    A2S(NL80211_ATTR_CSA_C_OFFSETS_TX)
    A2S(NL80211_ATTR_MAX_CSA_COUNTERS)

    A2S(NL80211_ATTR_TDLS_INITIATOR)

    A2S(NL80211_ATTR_USE_RRM)

    A2S(NL80211_ATTR_WIPHY_DYN_ACK)

    A2S(NL80211_ATTR_TSID)
    A2S(NL80211_ATTR_USER_PRIO)
    A2S(NL80211_ATTR_ADMITTED_TIME)

    A2S(NL80211_ATTR_SMPS_MODE)

    A2S(NL80211_ATTR_OPER_CLASS)

    A2S(NL80211_ATTR_MAC_MASK)

    A2S(NL80211_ATTR_WIPHY_SELF_MANAGED_REG)

    A2S(NL80211_ATTR_EXT_FEATURES)

    A2S(NL80211_ATTR_SURVEY_RADIO_STATS)

    A2S(NL80211_ATTR_NETNS_FD)

    A2S(NL80211_ATTR_SCHED_SCAN_DELAY)
    A2S(NL80211_ATTR_REG_INDOOR)

    A2S(NL80211_ATTR_MAX_NUM_SCHED_SCAN_PLANS)
    A2S(NL80211_ATTR_MAX_SCAN_PLAN_INTERVAL)
    A2S(NL80211_ATTR_MAX_SCAN_PLAN_ITERATIONS)
    A2S(NL80211_ATTR_SCHED_SCAN_PLANS)

    A2S(NL80211_ATTR_PBSS)

    A2S(NL80211_ATTR_BSS_SELECT)

    A2S(NL80211_ATTR_STA_SUPPORT_P2P_PS)

    A2S(NL80211_ATTR_PAD)

    A2S(NL80211_ATTR_IFTYPE_EXT_CAPA)

    A2S(NL80211_ATTR_MU_MIMO_GROUP_DATA)
    A2S(NL80211_ATTR_MU_MIMO_FOLLOW_MAC_ADDR)

    A2S(NL80211_ATTR_SCAN_START_TIME_TSF)
    A2S(NL80211_ATTR_SCAN_START_TIME_TSF_BSSID)
    A2S(NL80211_ATTR_MEASUREMENT_DURATION)
    A2S(NL80211_ATTR_MEASUREMENT_DURATION_MANDATORY)

    A2S(NL80211_ATTR_MESH_PEER_AID)

    A2S(NL80211_ATTR_NAN_MASTER_PREF)
    A2S(NL80211_ATTR_BANDS)
    A2S(NL80211_ATTR_NAN_FUNC)
    A2S(NL80211_ATTR_NAN_MATCH)

    A2S(NL80211_ATTR_FILS_KEK)
    A2S(NL80211_ATTR_FILS_NONCES)

    A2S(NL80211_ATTR_MULTICAST_TO_UNICAST_ENABLED)

    A2S(NL80211_ATTR_BSSID)

    A2S(NL80211_ATTR_SCHED_SCAN_RELATIVE_RSSI)
    A2S(NL80211_ATTR_SCHED_SCAN_RSSI_ADJUST)

    A2S(NL80211_ATTR_TIMEOUT_REASON)

    A2S(NL80211_ATTR_FILS_ERP_USERNAME)
    A2S(NL80211_ATTR_FILS_ERP_REALM)
    A2S(NL80211_ATTR_FILS_ERP_NEXT_SEQ_NUM)
    A2S(NL80211_ATTR_FILS_ERP_RRK)
    A2S(NL80211_ATTR_FILS_CACHE_ID)

    A2S(NL80211_ATTR_PMK)

    A2S(NL80211_ATTR_SCHED_SCAN_MULTI)
    A2S(NL80211_ATTR_SCHED_SCAN_MAX_REQS)

    A2S(NL80211_ATTR_WANT_1X_4WAY_HS)
    A2S(NL80211_ATTR_PMKR0_NAME)
    A2S(NL80211_ATTR_PORT_AUTHORIZED)

    A2S(NL80211_ATTR_EXTERNAL_AUTH_ACTION)
    A2S(NL80211_ATTR_EXTERNAL_AUTH_SUPPORT)

    A2S(NL80211_ATTR_NSS)
    A2S(NL80211_ATTR_ACK_SIGNAL)

    A2S(NL80211_ATTR_CONTROL_PORT_OVER_NL80211)

    A2S(NL80211_ATTR_TXQ_STATS)
    A2S(NL80211_ATTR_TXQ_LIMIT)
    A2S(NL80211_ATTR_TXQ_MEMORY_LIMIT)
    A2S(NL80211_ATTR_TXQ_QUANTUM)

    default:
        return "NL80211_ATTRIB_UNKNOWN";

    }
#undef A2S
}

const char *nl80211_command_to_string(enum nl80211_commands cmd)
{
#define C2S(x) case x: return #x;
    switch (cmd) {
    C2S(NL80211_CMD_UNSPEC)
    C2S(NL80211_CMD_GET_WIPHY)
    C2S(NL80211_CMD_SET_WIPHY)
    C2S(NL80211_CMD_NEW_WIPHY)
    C2S(NL80211_CMD_DEL_WIPHY)
    C2S(NL80211_CMD_GET_INTERFACE)
    C2S(NL80211_CMD_SET_INTERFACE)
    C2S(NL80211_CMD_NEW_INTERFACE)
    C2S(NL80211_CMD_DEL_INTERFACE)
    C2S(NL80211_CMD_GET_KEY)
    C2S(NL80211_CMD_SET_KEY)
    C2S(NL80211_CMD_NEW_KEY)
    C2S(NL80211_CMD_DEL_KEY)
    C2S(NL80211_CMD_GET_BEACON)
    C2S(NL80211_CMD_SET_BEACON)
    C2S(NL80211_CMD_START_AP)
    C2S(NL80211_CMD_STOP_AP)
    C2S(NL80211_CMD_GET_STATION)
    C2S(NL80211_CMD_SET_STATION)
    C2S(NL80211_CMD_NEW_STATION)
    C2S(NL80211_CMD_DEL_STATION)
    C2S(NL80211_CMD_GET_MPATH)
    C2S(NL80211_CMD_SET_MPATH)
    C2S(NL80211_CMD_NEW_MPATH)
    C2S(NL80211_CMD_DEL_MPATH)
    C2S(NL80211_CMD_SET_BSS)
    C2S(NL80211_CMD_SET_REG)
    C2S(NL80211_CMD_REQ_SET_REG)
    C2S(NL80211_CMD_GET_MESH_CONFIG)
    C2S(NL80211_CMD_SET_MESH_CONFIG)
    C2S(NL80211_CMD_SET_MGMT_EXTRA_IE)
    C2S(NL80211_CMD_GET_REG)
    C2S(NL80211_CMD_GET_SCAN)
    C2S(NL80211_CMD_TRIGGER_SCAN)
    C2S(NL80211_CMD_NEW_SCAN_RESULTS)
    C2S(NL80211_CMD_SCAN_ABORTED)
    C2S(NL80211_CMD_REG_CHANGE)
    C2S(NL80211_CMD_AUTHENTICATE)
    C2S(NL80211_CMD_ASSOCIATE)
    C2S(NL80211_CMD_DEAUTHENTICATE)
    C2S(NL80211_CMD_DISASSOCIATE)
    C2S(NL80211_CMD_MICHAEL_MIC_FAILURE)
    C2S(NL80211_CMD_REG_BEACON_HINT)
    C2S(NL80211_CMD_JOIN_IBSS)
    C2S(NL80211_CMD_LEAVE_IBSS)
    C2S(NL80211_CMD_TESTMODE)
    C2S(NL80211_CMD_CONNECT)
    C2S(NL80211_CMD_ROAM)
    C2S(NL80211_CMD_DISCONNECT)
    C2S(NL80211_CMD_SET_WIPHY_NETNS)
    C2S(NL80211_CMD_GET_SURVEY)
    C2S(NL80211_CMD_NEW_SURVEY_RESULTS)
    C2S(NL80211_CMD_SET_PMKSA)
    C2S(NL80211_CMD_DEL_PMKSA)
    C2S(NL80211_CMD_FLUSH_PMKSA)
    C2S(NL80211_CMD_REMAIN_ON_CHANNEL)
    C2S(NL80211_CMD_CANCEL_REMAIN_ON_CHANNEL)
    C2S(NL80211_CMD_SET_TX_BITRATE_MASK)
    C2S(NL80211_CMD_REGISTER_FRAME)
    C2S(NL80211_CMD_FRAME)
    C2S(NL80211_CMD_FRAME_TX_STATUS)
    C2S(NL80211_CMD_SET_POWER_SAVE)
    C2S(NL80211_CMD_GET_POWER_SAVE)
    C2S(NL80211_CMD_SET_CQM)
    C2S(NL80211_CMD_NOTIFY_CQM)
    C2S(NL80211_CMD_SET_CHANNEL)
    C2S(NL80211_CMD_SET_WDS_PEER)
    C2S(NL80211_CMD_FRAME_WAIT_CANCEL)
    C2S(NL80211_CMD_JOIN_MESH)
    C2S(NL80211_CMD_LEAVE_MESH)
    C2S(NL80211_CMD_UNPROT_DEAUTHENTICATE)
    C2S(NL80211_CMD_UNPROT_DISASSOCIATE)
    C2S(NL80211_CMD_NEW_PEER_CANDIDATE)
    C2S(NL80211_CMD_GET_WOWLAN)
    C2S(NL80211_CMD_SET_WOWLAN)
    C2S(NL80211_CMD_START_SCHED_SCAN)
    C2S(NL80211_CMD_STOP_SCHED_SCAN)
    C2S(NL80211_CMD_SCHED_SCAN_RESULTS)
    C2S(NL80211_CMD_SCHED_SCAN_STOPPED)
    C2S(NL80211_CMD_SET_REKEY_OFFLOAD)
    C2S(NL80211_CMD_PMKSA_CANDIDATE)
    C2S(NL80211_CMD_TDLS_OPER)
    C2S(NL80211_CMD_TDLS_MGMT)
    C2S(NL80211_CMD_UNEXPECTED_FRAME)
    C2S(NL80211_CMD_PROBE_CLIENT)
    C2S(NL80211_CMD_REGISTER_BEACONS)
    C2S(NL80211_CMD_UNEXPECTED_4ADDR_FRAME)
    C2S(NL80211_CMD_SET_NOACK_MAP)
    C2S(NL80211_CMD_CH_SWITCH_NOTIFY)
    C2S(NL80211_CMD_START_P2P_DEVICE)
    C2S(NL80211_CMD_STOP_P2P_DEVICE)
    C2S(NL80211_CMD_CONN_FAILED)
    C2S(NL80211_CMD_SET_MCAST_RATE)
    C2S(NL80211_CMD_SET_MAC_ACL)
    C2S(NL80211_CMD_RADAR_DETECT)
    C2S(NL80211_CMD_GET_PROTOCOL_FEATURES)
    C2S(NL80211_CMD_UPDATE_FT_IES)
    C2S(NL80211_CMD_FT_EVENT)
    C2S(NL80211_CMD_CRIT_PROTOCOL_START)
    C2S(NL80211_CMD_CRIT_PROTOCOL_STOP)
    C2S(NL80211_CMD_GET_COALESCE)
    C2S(NL80211_CMD_SET_COALESCE)
    C2S(NL80211_CMD_CHANNEL_SWITCH)
    C2S(NL80211_CMD_VENDOR)
    C2S(NL80211_CMD_SET_QOS_MAP)
    C2S(NL80211_CMD_ADD_TX_TS)
    C2S(NL80211_CMD_DEL_TX_TS)
    C2S(NL80211_CMD_WIPHY_REG_CHANGE)
    C2S(NL80211_CMD_PORT_AUTHORIZED)
    C2S(NL80211_CMD_EXTERNAL_AUTH)
    C2S(NL80211_CMD_STA_OPMODE_CHANGED)
    C2S(NL80211_CMD_CONTROL_PORT_FRAME)
    default:
        return "NL80211_CMD_UNKNOWN";
    }
#undef C2S
}

void print_attributes(char *cmd, struct nlattr *tb[])
{
    unsigned int i;
    wifi_hal_dbg_print("\n%s attributes:\n", cmd);
    for (i = 0; i < NL80211_ATTR_MAX; i++) {
        if (tb[i] != NULL) {
            wifi_hal_dbg_print("%s\t", nl80211_attribute_to_string(nla_type(tb[i])));
        }
    }
    wifi_hal_dbg_print("\n\n");
}

void print_supported_commands(char *cmd, struct nlattr *tb)
{
    unsigned int i;
    struct nlattr *nl_cmd;

    if (tb != NULL) {
        wifi_hal_dbg_print("\n%s commands:\n", cmd);
        nla_for_each_nested(nl_cmd, tb, i) {
            wifi_hal_dbg_print("%s\t", nl80211_command_to_string(nla_get_u32(nl_cmd)));
        }
        wifi_hal_dbg_print("\n\n");
    }
}

char *get_wifi_drv_name(const char *device)
{
    unsigned int i;

    for (i = 0; i < ARRAY_SZ(driver_info); i++) {
            if (strncmp(driver_info[i].device, device, strlen(device)) == 0) {
                    return driver_info[i].driver_name;
            }
    }

    return NULL;
}

bool lsmod_by_name(const char *name)
{
    FILE *fp = NULL;
    char line[4096];

    if ((fp = fopen("/proc/modules", "r")) == NULL) {
        return false;
    }

    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, name) != NULL) {
            fclose(fp);
            return true;
        }
    }

    fclose(fp);

    return false;
}
