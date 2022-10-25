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
#ifndef WIFI_HAL_PRIV_H
#define WIFI_HAL_PRIV_H

#include <utils/includes.h>
#include "utils/common.h"
#include "utils/eloop.h"
#include "common/ieee802_11_defs.h"
#include "common/wpa_ctrl.h"
#include "common/sae.h"
#include "common/dpp.h"
#include "radius/radius.h"
#include "radius/radius_client.h"
#include "p2p/p2p.h"
#include "fst/fst.h"
#include "crypto/crypto.h"
#include "crypto/tls.h"
#include "hostapd.h"
#include "accounting.h"
#include "ieee802_1x.h"
#include "ieee802_11.h"
#include "ieee802_11_auth.h"
#include "wpa_auth.h"
#include "preauth_auth.h"
#include "ap_config.h"
#include "ap_drv_ops.h"
#include "beacon.h"
#include "ap_mlme.h"
#include "vlan_init.h"
#include "p2p_hostapd.h"
#include "gas_serv.h"
#include "wnm_ap.h"
#include "mbo_ap.h"
#include "ndisc_snoop.h"
#include "sta_info.h"
#include "vlan.h"
#include "wps_hostapd.h"
#include "hostapd/ctrl_iface.h"
#include "rsn_supp/wpa.h"
#include "rsn_supp/wpa_i.h"
#include "eapol_supp/eapol_supp_sm.h"
#include "eap_peer/eap_config.h"
#include "eap_peer/eap.h"
#include <stdbool.h>
#include "wifi_hal.h"
#include "wifi_hal_sta.h"
#include "wifi_hal_rdk_framework.h"
#include "collection.h"
#include "driver.h"
#include <linux/nl80211.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <netlink/handlers.h>
#include <netlink/attr.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WIFI_HAL_MAJOR  3
#define WIFI_HAL_MINOR  0
#ifdef HOSTAPD_2_10
    #define HOSTAPD_VERSION 210
#else
    #define HOSTAPD_VERSION 209
#endif
/*
 * Copyright (c) 2003-2013, Jouni Malinen <j@w1.fi>
 * Licensed under the BSD-3 License
*/
#if 0
#define RSN_SELECTOR(a, b, c, d) \
   ((((unsigned int) (a)) << 24) | (((unsigned int) (b)) << 16) | (((unsigned int) (c)) << 8) | \
   (unsigned int) (d))
#endif
#define RSN_CIPHER_SUITE_NONE RSN_SELECTOR(0x00, 0x0f, 0xac, 0)
#define RSN_CIPHER_SUITE_TKIP RSN_SELECTOR(0x00, 0x0f, 0xac, 2)
#if 0
#define RSN_CIPHER_SUITE_WRAP RSN_SELECTOR(0x00, 0x0f, 0xac, 3)
#endif
#define RSN_CIPHER_SUITE_CCMP RSN_SELECTOR(0x00, 0x0f, 0xac, 4)
#define RSN_CIPHER_SUITE_AES_128_CMAC RSN_SELECTOR(0x00, 0x0f, 0xac, 6)
#define RSN_CIPHER_SUITE_NO_GROUP_ADDRESSED RSN_SELECTOR(0x00, 0x0f, 0xac, 7)
#define RSN_CIPHER_SUITE_GCMP RSN_SELECTOR(0x00, 0x0f, 0xac, 8)
#define RSN_CIPHER_SUITE_GCMP_256 RSN_SELECTOR(0x00, 0x0f, 0xac, 9)
#define RSN_CIPHER_SUITE_CCMP_256 RSN_SELECTOR(0x00, 0x0f, 0xac, 10)
#define RSN_CIPHER_SUITE_BIP_GMAC_128 RSN_SELECTOR(0x00, 0x0f, 0xac, 11)
#define RSN_CIPHER_SUITE_BIP_GMAC_256 RSN_SELECTOR(0x00, 0x0f, 0xac, 12)
#define RSN_CIPHER_SUITE_BIP_CMAC_256 RSN_SELECTOR(0x00, 0x0f, 0xac, 13)

#define WIFI_CIPHER_CAPA_ENC_WEP40   0x00000001
#define WIFI_CIPHER_CAPA_ENC_WEP104  0x00000002
#define WIFI_CIPHER_CAPA_ENC_TKIP    0x00000004
#define WIFI_CIPHER_CAPA_ENC_CCMP    0x00000008
#define WIFI_CIPHER_CAPA_ENC_WEP128  0x00000010
#define WIFI_CIPHER_CAPA_ENC_GCMP    0x00000020
#define WIFI_CIPHER_CAPA_ENC_GCMP_256    0x00000040
#define WIFI_CIPHER_CAPA_ENC_CCMP_256    0x00000080
#define WIFI_CIPHER_CAPA_ENC_BIP     0x00000100
#define WIFI_CIPHER_CAPA_ENC_BIP_GMAC_128    0x00000200
#define WIFI_CIPHER_CAPA_ENC_BIP_GMAC_256    0x00000400
#define WIFI_CIPHER_CAPA_ENC_BIP_CMAC_256    0x00000800
#define WIFI_CIPHER_CAPA_ENC_GTK_NOT_USED    0x00001000

#define DEFAULT_WPA_DISABLE_EAPOL_KEY_RETRIES 0
#define RADIUS_CLIENT_MAX_RETRIES 5
#define RADIUS_CLIENT_MAX_WAIT 120
#define ecw2cw(ecw) ((1 << (ecw)) - 1)

#define     MAX_BSSID_IN_ESS    8

#define BUF_SIZE         32
#define NVRAM_NAME_SIZE  32
#define WPS_METHODS_SIZE 512

/* 2GHz radio */
#define MIN_FREQ_MHZ_2G             2412
#define MAX_FREQ_MHZ_2G             2484
#define MIN_CHANNEL_2G              1
#define MAX_CHANNEL_2G              11

/* 5GHz radio */
#define MIN_FREQ_MHZ_5G             5180
#define MAX_FREQ_MHZ_5G             5825
#define MIN_CHANNEL_5G              36
#define MAX_CHANNEL_5G              165

/* 6GHz radio */
#define MIN_FREQ_MHZ_6G             5935
#define MAX_FREQ_MHZ_6G             7115
#define MIN_CHANNEL_6G              1
#define MAX_CHANNEL_6G              229

extern const struct wpa_driver_ops g_wpa_driver_nl80211_ops;

typedef int    (* platform_pre_init_t)();
typedef int    (* platform_post_init_t)(wifi_vap_info_map_t *vap_map);
typedef int    (* platform_keypassphrase_default_t)(char *password, int vap_index);
typedef int    (* platform_radius_key_default_t)(char *radius_key);
typedef int    (* platform_ssid_default_t)(char *ssid, int vap_index);
typedef int    (* platform_wps_pin_default_t)(char *pin);
typedef int    (* platform_country_code_default_t)(char *code);
typedef int    (* platform_set_radio_params_t)(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam);
typedef int    (* platform_set_radio_pre_init_t)(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam);
typedef int    (* platform_create_vap_t)(wifi_radio_index_t index, wifi_vap_info_map_t *map);
typedef int    (* platform_wps_event_t)(wifi_wps_event_t data);
typedef struct wifi_enum_to_str_map
{
    int enum_val;
    const char *str_val;
} wifi_enum_to_str_map_t;

typedef struct {
    void    *arg;
    int     *err;
} wifi_finish_data_t;

typedef struct {
    char		*device_name;
    char		*manufacturer;
    char		*model_name;
    char		*model_number;
    char		*model_description;
    char		*model_url;
    char		*serial_number;
    char		*friendly_name;
    char		*manufacturer_url;
} wifi_device_info_t;

typedef struct {
    char			*device;
    char			*driver_name;
    wifi_device_info_t		device_info;
    platform_pre_init_t		platform_pre_init_fn;
    platform_post_init_t	platform_post_init_fn;
    platform_set_radio_params_t	platform_set_radio_fn;
    platform_set_radio_pre_init_t platform_set_radio_pre_init_fn;
    platform_create_vap_t	platform_create_vap_fn;
    platform_ssid_default_t           platform_ssid_default_fn;
    platform_keypassphrase_default_t  platform_keypassphrase_default_fn;
    platform_radius_key_default_t  platform_radius_key_default_fn;
    platform_wps_pin_default_t        platform_wps_pin_default_fn;
    platform_country_code_default_t platform_country_code_default_fn;
    platform_wps_event_t              platform_wps_event_fn;
} wifi_driver_info_t;

typedef struct {
    unsigned int    op_class;
    unsigned int    global_op_class;
    unsigned int    num;
    unsigned int    ch_list[16];
} wifi_radio_op_class_t;

struct wifiCountryEnumStrMap {
    wifi_countrycode_type_t countryCode;
    char countryStr[4];
};

struct wifiEnvironmentEnumStrMap {
    wifi_operating_env_t operatingEnvironment;
    char environment[2];
};

typedef struct {
    wifi_countrycode_type_t    cc;
    wifi_radio_op_class_t   op_class[6];
} wifi_country_radio_op_class_t;

typedef struct {
    struct wpa_driver_capa capa;

    unsigned int disabled_11b_rates:1;
    unsigned int pending_remain_on_chan:1;
    unsigned int in_interface_list:1;
    unsigned int device_ap_sme:1;
    unsigned int poll_command_supported:1;
    unsigned int data_tx_status:1;
    unsigned int scan_for_auth:1;
    unsigned int retry_auth:1;
    unsigned int use_monitor:1;
    unsigned int ignore_next_local_disconnect:1;
    unsigned int ignore_next_local_deauth:1;
    unsigned int hostapd:1;
    unsigned int start_mode_ap:1;
    unsigned int start_iface_up:1;
    unsigned int test_use_roc_tx:1;
    unsigned int ignore_deauth_event:1;
    unsigned int vendor_cmd_test_avail:1;
    unsigned int roaming_vendor_cmd_avail:1;
    unsigned int dfs_vendor_cmd_avail:1;
    unsigned int have_low_prio_scan:1;
    unsigned int force_connect_cmd:1;
    unsigned int addr_changed:1;
    unsigned int get_features_vendor_cmd_avail:1;
    unsigned int set_rekey_offload:1;
    unsigned int p2p_go_ctwindow_supported:1;
    unsigned int setband_vendor_cmd_avail:1;
    unsigned int get_pref_freq_list:1;
    unsigned int set_prob_oper_freq:1;
    unsigned int scan_vendor_cmd_avail:1;
    unsigned int connect_reassoc:1;
    unsigned int set_wifi_conf_vendor_cmd_avail:1;
    unsigned int fetch_bss_trans_status:1;
    unsigned int roam_vendor_cmd_avail:1;
    unsigned int get_supported_akm_suites_avail:1;
} wifi_driver_data_t;

typedef struct {
    int     sta_sock_fd;

    // supplicant specific data
    struct wpa_sm     *wpa_sm;
    struct eapol_ctx  wpa_eapol_ctx;
    struct eap_peer_config wpa_eapol_config;
    struct eap_method_type wpa_eapol_method;
    unsigned char   assoc_req[512];
    unsigned int    assoc_req_len;
    unsigned char   assoc_rsp[512];
    unsigned int    assoc_rsp_len;
    unsigned char   eapol_msg[512];

    hash_map_t  *scan_info_map;
    wifi_bss_info_t backhaul;
    bool    connected;

    enum wpa_states state;
    bool pending_rx_eapol;
    unsigned char rx_eapol_buff[2048];
    mac_address_t src_addr;
    int buff_len;
} wifi_sta_priv_t;

typedef struct {
    int     br_sock_fd;

    // hostapd specific interface data
    struct hostapd_data     hapd;
    struct hostapd_iface    iface;
    struct hostapd_bss_config   conf;
    bool    hapd_initialized;
    bool    iface_initialized;
    bool    conf_initialized;
    struct hostapd_radius_servers radius;
    struct hostapd_radius_server    auth_serv, acct_serv;
    char   auth_shared_secret[64], acct_shared_secret[64];;
    char   nas_identifier[64];
    // array elements reference
    struct hostapd_data     *hapds[1];
    int eloop_signal_sock[2];
} wifi_ap_priv_t;

typedef struct {
    char name[32];
    char bridge[32];
    unsigned int index;
    unsigned int phy_index;
    mac_address_t   mac;
    unsigned int type;
    unsigned int interface_status;
    bool    primary;
    wifi_vap_info_t     vap_info;
    bool    vap_initialized;
    bool    bss_started;
   
    bool    vap_configured; // important flag, flag = true means that hostap is configured for this and 
                            // interface is ready to receive 802.11 data frames
    struct nl_handle *nl_event;
    int nl_event_fd;
    struct nl_cb *nl_cb;

    union {
        wifi_ap_priv_t  ap;
        wifi_sta_priv_t sta;
    } u;

    char   wpa_passphrase[64];
    char   device_name[64], manufacturer[64], model_name[64], model_number[64];
    char   serial_number[64], friendly_name[64], manufacturer_url[64];
    char   model_description[64], model_url[64];
    int    vlan;
    char   ctrl_interface[32];
    char   wps_config_methods[64];
    char   pin[64];
    int beacon_set;
    int mgmt_frames_registered;

} wifi_interface_info_t;

#define MAX_RATES   16
typedef struct {
    char name[32];
    unsigned int index;
    unsigned int rdk_radio_index;
    unsigned long dev_id;
    wifi_radio_capabilities_t   capab;
    wifi_radio_operationParam_t oper_param;
    hash_map_t  *interface_map;
    queue_t     *supported_cmds;
    
    // hostapd related data for radio config
    struct hostapd_config   iconf;
    wifi_driver_data_t  driver_data;
    struct hostapd_hw_modes hw_modes[NUM_NL80211_BANDS];  // This can be one of enum nl80211_band  
    struct hostapd_channel_data channel_data[NUM_NL80211_BANDS][MAX_CHANNELS];
    int     rates[NUM_NL80211_BANDS][MAX_RATES];
    int     basic_rates[NUM_NL80211_BANDS][MAX_RATES]; // supported rates per band in 100 kbps units
    struct hostapd_rate_data    rate_data[NUM_NL80211_BANDS][MAX_RATES];
    struct wpa_driver_ops   driver_ops;
    struct hapd_interfaces  interfaces;
    struct hostapd_iface *iface[MAX_NUM_VAP_PER_RADIO];
    struct hostapd_bss_config *bss[MAX_NUM_VAP_PER_RADIO];
    bool configured;
    unsigned int  prev_channel;
    unsigned int  prev_channelWidth;
} wifi_radio_info_t;

typedef struct {
    pthread_t nl_tid;
    pthread_t hapd_eloop_tid;
    fd_set   drv_rfds;
    int nl_event_fd;
    int link_fd;
    struct nl_cb *nl_cb;
    int nl80211_id;
    struct nl_handle *nl;
    struct nl_handle *nl_event;
    unsigned int port_bitmap[32];
    unsigned int num_radios;
    wifi_radio_info_t radio_info[MAX_NUM_RADIOS];
    wifi_device_callbacks_t device_callbacks;
} wifi_hal_priv_t;

wifi_hal_priv_t g_wifi_hal;

INT wifi_hal_init();
INT wifi_hal_pre_init();
INT wifi_hal_post_init(wifi_vap_info_map_t *vap_map);
INT wifi_hal_ssid_init(char *ssid, int vap_index);
INT wifi_hal_keypassphrase_init(char *password, int vap_index);
INT wifi_hal_wps_pin_init(char *pin);
INT wifi_hal_hostApGetErouter0Mac(char *out);
INT wifi_hal_getHalCapability(wifi_hal_capability_t *hal);
INT wifi_hal_connect(INT ap_index, wifi_bss_info_t *bss);
INT wifi_hal_setRadioOperatingParameters(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam);
INT wifi_hal_createVAP(wifi_radio_index_t index, wifi_vap_info_map_t *map);
INT wifi_hal_kickAssociatedDevice(INT ap_index, mac_address_t mac);
INT wifi_hal_startScan(wifi_radio_index_t index, wifi_neighborScanMode_t scan_mode, INT dwell_time, UINT num, UINT *chan_list);
INT wifi_hal_disconnect(INT ap_index);
INT wifi_hal_getRadioVapInfoMap(wifi_radio_index_t index, wifi_vap_info_map_t *map);
INT wifi_hal_setApWpsButtonPush(INT apIndex);
INT wifi_hal_sendDataFrame(int vap_id, unsigned char *dmac, unsigned char *data_buff, int data_len, BOOL insert_llc, int protocal, int priority);

wifi_radio_info_t *get_radio_by_index(wifi_radio_index_t index);
wifi_interface_info_t *get_interface_by_vap_index(unsigned int vap_index);
BOOL get_ie_by_eid(unsigned int eid, unsigned char *buff, unsigned int buff_len, unsigned char **ie_out, unsigned short *ie_out_len);
INT get_coutry_str_from_code(wifi_countrycode_type_t code, char *country);
INT get_coutry_str_from_oper_params(wifi_radio_operationParam_t *operParams, char *country);
char *to_mac_str    (mac_address_t mac, mac_addr_str_t key);
const char *wifi_freq_bands_to_string(wifi_freq_bands_t band);
const char *wpa_alg_to_string(enum wpa_alg alg);
int nl80211_update_wiphy(wifi_radio_info_t *radio);
wifi_interface_info_t* get_private_vap_interface(wifi_radio_info_t *radio);
wifi_interface_info_t* get_primary_interface(wifi_radio_info_t *radio);
wifi_interface_info_t* get_private_vap_interface(wifi_radio_info_t *radio);
int nl80211_init_primary_interfaces();
int nl80211_init_radio_info();
int getIpStringFromAdrress(char * ipString,  ip_addr_t * ip);

int init_nl80211();
void wifi_hal_nl80211_wps_pbc(unsigned int ap_index);
int     update_channel_flags();
int     handle_public_action_frame(INT ap_index, mac_address_t sta_mac, wifi_publicActionFrameHdr_t *ppublic_hdr, UINT len);
int     nl80211_create_interface(wifi_radio_info_t *radio, wifi_vap_info_t *vap, wifi_interface_info_t **interface);
int     nl80211_enable_ap(wifi_interface_info_t *interface, bool enable);
int     nl80211_kick_device(wifi_interface_info_t *interface, mac_address_t mac);
int     nl80211_create_bridge(const char *if_name, const char *br_name);
int     nl80211_remove_from_bridge(const char *if_name);
int     nl80211_update_interface(wifi_interface_info_t *interface);
int     nl80211_interface_enable(const char *ifname, bool enable);
int     nl80211_connect_sta(wifi_interface_info_t *interface);
int nl80211_start_scan(wifi_interface_info_t *interface, unsigned int num_freq, unsigned int  *freq_list, unsigned int num_ssid, ssid_t *ssid_list);
int     nl80211_get_scan_results(wifi_interface_info_t *interface);
int     nl80211_switch_channel(wifi_radio_info_t *radio);
int     update_hostap_interfaces(wifi_radio_info_t *radio);
int     update_hostap_interface_params(wifi_interface_info_t *interface);
int     update_hostap_config_params(wifi_radio_info_t *radio);
int     nl80211_get_channel_bw_conn(wifi_interface_info_t *interface);
void    update_wpa_sm_params(wifi_interface_info_t *interface);
void    update_eapol_sm_params(wifi_interface_info_t *interface);
void    *nl_recv_func(void *arg);
void    start_bss(wifi_interface_info_t *interface);
int     process_global_nl80211_event(struct nl_msg *msg, void *arg);
int     no_seq_check(struct nl_msg *msg, void *arg);
void    *eloop_run_thread(void *data);
int     wifi_send_eapol(void *priv, const u8 *addr, const u8 *data,
                    size_t data_len, int encrypt,
                    const u8 *own_addr, u32 flags);
void   *wifi_drv_init(struct hostapd_data *hapd, struct wpa_init_params *params);
int     wifi_set_privacy(void *priv, int enabled);
int     wifi_set_ssid(void *priv, const u8 *buf, int len);
int     wifi_drv_set_operstate(void *priv, int state);
int     wifi_flush(void *priv);
int     wifi_sta_deauth(void *priv, const u8 *own_addr, const u8 *addr, int reason_code);
int     wifi_set_key(const char *ifname, void *priv, enum wpa_alg alg,
                    const u8 *addr, int key_idx, int set_tx, const u8 *seq,
                    size_t seq_len, const u8 *key, size_t key_len);
int     wifi_set_authmode(void *priv, int auth_algs);
int     wifi_set_ieee8021x(void *priv, struct wpa_bss_params *params);
int     wifi_set_opt_ie(void *priv, const u8 *ie, size_t ie_len);
int     wifi_set_ap(void *priv, struct wpa_driver_ap_params *params);
int     wifi_sta_set_flags(void *priv, const u8 *addr,
                unsigned int total_flags, unsigned int flags_or,
                unsigned int flags_and);
int     wifi_sta_disassoc(void *priv, const u8 *own_addr, const u8 *addr, u16 reason_code);
int     wifi_sta_assoc(void *priv, const u8 *own_addr, const u8 *addr,
                int reassoc, u16 status_code, const u8 *ie, size_t len);
int     wifi_set_ap_wps_ie(void *priv, const struct wpabuf *beacon,
                      const struct wpabuf *proberesp,
                      const struct wpabuf *assocresp);
int     wifi_sta_get_seqnum(const char *ifname, void *priv, const u8 *addr, int idx, u8 *seq);
int     wifi_commit(void *priv);
wifi_radio_info_t *get_radio_by_phy_index(wifi_radio_index_t index);
wifi_radio_info_t *get_radio_by_rdk_index(wifi_radio_index_t index);
int set_interface_properties(unsigned int phy_index, wifi_interface_info_t *interface);
int get_op_class_from_radio_params(wifi_radio_operationParam_t *param);
wifi_interface_info_t* get_primary_interface(wifi_radio_info_t *radio);
int nl80211_disconnect_sta(wifi_interface_info_t *interface);
int wifi_hal_purgeScanResult(unsigned int vap_index, unsigned char *sta_mac);
void get_wifi_interface_info_map(wifi_interface_name_idex_map_t *interface_map);
void get_radio_interface_info_map(radio_interface_mapping_t *radio_interface_map);
int is_backhaul_interface(wifi_interface_info_t *interface);
int get_interface_name_from_vap_index(unsigned int vap_index, char *interface_name);
int get_ap_vlan_id(char *interface_name);
int get_vap_mode_str_from_int_mode(unsigned char vap_mode, char *vap_mode_str);
int get_security_mode_str_from_int(wifi_security_modes_t security_mode, char *security_mode_str);
int get_security_encryption_mode_str_from_int(wifi_encryption_method_t encryption_mode, char *encryption_mode_str);
int get_security_mode_support_radius(int mode);
void wps_enum_to_string(unsigned int methods, char *str, int len);
int get_radio_variant_str_from_int(unsigned char variant, char *variant_str);
int get_rdk_radio_index(unsigned int phy_index);
int get_interface_name_from_radio_index(uint8_t radio_index, char *interface_name);

BOOL is_wifi_hal_vap_private(UINT ap_index);
BOOL is_wifi_hal_vap_xhs(UINT ap_index);
BOOL is_wifi_hal_vap_hotspot(UINT ap_index);
BOOL is_wifi_hal_vap_hotspot_open(UINT ap_index);
BOOL is_wifi_hal_vap_lnf(UINT ap_index);
BOOL is_wifi_hal_vap_lnf_psk(UINT ap_index);
BOOL is_wifi_hal_vap_mesh(UINT ap_index);
BOOL is_wifi_hal_vap_mesh_backhaul(UINT ap_index);
BOOL is_wifi_hal_vap_hotspot_secure(UINT ap_index);
BOOL is_wifi_hal_vap_lnf_radius(UINT ap_index);
BOOL is_wifi_hal_vap_mesh_sta(UINT ap_index);
BOOL is_wifi_hal_vap_hotspot_from_interfacename(char *interface_name);

int nvram_get_current_password(char *l_password, int vap_index);
int nvram_get_current_ssid(char *l_ssid, int vap_index);
int nl80211_set_regulatory_domain(wifi_countrycode_type_t country_code);

#ifdef __cplusplus
}
#endif

typedef enum {
    WIFI_HAL_LOG_LVL_DEBUG,
    WIFI_HAL_LOG_LVL_INFO,
    WIFI_HAL_LOG_LVL_ERROR
}wifi_hal_log_level_t;

void wifi_hal_print(wifi_hal_log_level_t level, char *format, ...);

#define wifi_hal_dbg_print(format, ...)  wifi_hal_print(WIFI_HAL_LOG_LVL_DEBUG, format, ##__VA_ARGS__)
#define wifi_hal_info_print(format, ...)  wifi_hal_print(WIFI_HAL_LOG_LVL_INFO, format, ##__VA_ARGS__)
#define wifi_hal_error_print(format, ...)  wifi_hal_print(WIFI_HAL_LOG_LVL_ERROR, format, ##__VA_ARGS__)

bool lsmod_by_name(const char *name);
wifi_device_callbacks_t *get_hal_device_callbacks();
char *get_wifi_drv_name();
wifi_device_info_t get_device_info_details();
typedef char * PCHAR;
extern int platform_pre_init();
extern int platform_post_init(wifi_vap_info_map_t *vap_map);
extern int platform_get_keypassphrase_default(char *password, int vap_index);
extern int platform_get_radius_key_default(char *radius_key);
extern int platform_get_ssid_default(char *ssid, int vap_index);
extern int platform_get_wps_pin_default(char *pin);
extern int platform_wps_event(wifi_wps_event_t data);
extern int platform_get_country_code_default(char *code);
extern int platform_set_radio(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam);
extern int platform_create_vap(wifi_radio_index_t index, wifi_vap_info_map_t *map);
extern int platform_set_radio_pre_init(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam);
platform_pre_init_t     	get_platform_pre_init_fn();
platform_post_init_t    	get_platform_post_init_fn();
platform_keypassphrase_default_t     get_platform_keypassphrase_default_fn();
platform_ssid_default_t              get_platform_ssid_default_fn();
platform_wps_pin_default_t           get_platform_wps_pin_default_fn();
platform_wps_event_t                 get_platform_wps_event_fn();
platform_country_code_default_t get_platform_country_code_default_fn();
platform_set_radio_params_t 	get_platform_set_radio_fn();
platform_set_radio_pre_init_t get_platform_set_radio_pre_init_fn();
platform_create_vap_t 		get_platform_create_vap_fn();
platform_radius_key_default_t       get_platform_radius_key_default_fn();

INT wifi_hal_wps_event(wifi_wps_event_t data);
#endif // WIFI_HAL_PRIV_H
